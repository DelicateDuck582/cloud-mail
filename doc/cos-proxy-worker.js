// =====================================================================
// COS 前置代理 Worker —— 短期签名（防伪造）+ Cache API 按文件缓存
// ---------------------------------------------------------------------
// 1. 对 /attachments/ 路径强制校验"后端签发"的短期签名（?expires=&sign=）。
//    伪造脚本没有后端私钥（ATT_SIGN_SECRET），永远算不出合法签名 -> 403。
// 2. 验签通过后用 Workers Cache API 按 path 缓存（每个请求都先验签，
//    命中缓存不会绕过签名校验）。附件 key 是内容哈希，文件不变则哈希不变，
//    同一文件只需回源 COS 一次，之后所有合法签名请求直接命中缓存。
//
// 需要配置的环境变量：
//   ATT_SIGN_SECRET        必填。与 CloudMail(mail-worker) 的 ATT_SIGN_SECRET 保持一致
//   ATT_SIGN_MAX_TTL       可选。允许的最大签名有效期（秒），默认 3600
//   S3_ENDPOINT / REGION / AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
//                           原有配置，用于回源 COS 的 S3 签名
// =====================================================================
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);

      // 1. 根路径拦截：访问根域名时自动跳转到邮件登录页
      const REDIRECT_TARGET = 'https://mail.duckgame-play.top';
      if (url.pathname === '/' || url.pathname === '') {
        return Response.redirect(REDIRECT_TARGET, 302);
      }

      // 浏览器自动请求的 favicon：直接 204，避免落入白名单 403 刷日志
      if (url.pathname === '/favicon.ico') {
        return new Response(null, { status: 204 });
      }

      // =====================================================
      // 1.2 【文件浏览器】/browse —— 个人只读网盘
      //     所有请求都经本 Worker（cos-exchange），手机不直连 COS
      //     独立密码门控（BROWSE_PASS），与附件签名体系互不影响
      // =====================================================
      if (url.pathname === '/browse' || url.pathname.startsWith('/browse/')) {
        return await handleBrowse(request, env, ctx);
      }

      // 仅允许 GET 和 HEAD 请求
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return new Response('Method Not Allowed', { status: 405 });
      }

      // =====================================================
      // 1.5 【路径白名单】只代理两类路径，其余一律 403
      //     /attachments/ —— 附件/内嵌图（上方已强制验签）
      //     /static/      —— 登录背景等公开资源（保留 Referer/Sec-Fetch 校验）
      //     收紧后 Worker 不会变成「任意路径的 COS 代理」，缩小盗刷面
      // =====================================================
      if (!url.pathname.startsWith('/attachments/') && !url.pathname.startsWith('/static/')) {
        return new Response('Forbidden', { status: 403 });
      }

      // =====================================================
      // 2. 【新增】短期签名校验（防伪造核心）
      //    attachments/ 下的文件只有携带后端签发的有效签名才能访问。
      //    伪造 Referer + Sec-Fetch 全套头的脚本，拿不到 ATT_SIGN_SECRET，
      //    签不出来 -> 直接 403。
      // =====================================================
      const isAttachment = url.pathname.startsWith('/attachments/');
      let signature = { ok: true, remaining: 3600 };
      if (isAttachment) {
        signature = await verifySignature(url, env);
        if (!signature.ok) {
          return new Response(signature.reason || 'Forbidden', {
            status: 403,
            headers: { 'Content-Type': 'text/plain; charset=utf-8' },
          });
        }
      }

      // =====================================================
      // 3. 访问控制（双层校验，保留原逻辑作为第二层防线）
      //    第一层：Referer 精确域名匹配 —— 防浏览器直开/盗链/转发
      //    第二层：Sec-Fetch 浏览器特性头 —— 防 curl 伪造 Referer
      // =====================================================
      const referer = request.headers.get('Referer') || '';
      let refererHost = '';
      try { refererHost = new URL(referer).hostname; } catch (e) {}

      const secFetchSite = request.headers.get('Sec-Fetch-Site') || '';
      const secFetchDest = request.headers.get('Sec-Fetch-Dest') || '';

      // ① Referer 必须是邮件域
      const refererOk = refererHost === 'mail.duckgame-play.top';
      // ② Sec-Fetch-Site 必须是 same-site/same-origin
      const siteOk = secFetchSite === 'same-site' || secFetchSite === 'same-origin';
      // ③ Sec-Fetch-Dest：image / 旧浏览器无此头；附件下载/预览场景放行 document 等
      const destOk =
        secFetchDest === 'image' || secFetchDest === '' ||
        ['document', 'empty', 'frame', 'iframe', 'audio', 'video', 'embed', 'object'].includes(secFetchDest);

      // 已通过 HMAC 签名校验的附件请求：签名本身就是授权凭证，
      // 放宽 Referer/Sec-Fetch 检查（兼容邮件客户端、新标签页直开等无 Referer 场景；
      // 签名有效期受 ATT_SIGN_MAX_TTL 限制，最长 1 小时）
      const isSignedOk = isAttachment && signature.ok;
      if (!isSignedOk && (!refererOk || !siteOk || !destOk)) {
        return new Response('Forbidden', {
          status: 403,
          headers: { 'Content-Type': 'text/plain; charset=utf-8' },
        });
      }

      // =====================================================
      // 4.5 【Cache API 缓存查找】按 path（忽略签名参数）缓存
      //      每个请求都在此之前完成验签，无签名/伪造签名请求已被 403 拦截，
      //      因此命中缓存不会绕过签名校验。
      //      同一文件（内容哈希不变）只需回源一次，之后所有合法签名请求直接命中。
      // =====================================================
      const cacheKey = new Request(url.origin + url.pathname);
      const cached = await caches.default.match(cacheKey);
      if (cached) {
        return cached;
      }
      // 4. 获取并标准化 Endpoint 地址（必须配置，不再内置默认域名）
      let rawEndpoint = (env.S3_ENDPOINT || '').trim();
      if (!rawEndpoint) {
        return new Response('Worker 配置错误：缺失环境变量 S3_ENDPOINT。', { status: 500 });
      }
      if (!rawEndpoint.startsWith('http://') && !rawEndpoint.startsWith('https://')) {
        rawEndpoint = 'https://' + rawEndpoint;
      }
      rawEndpoint = rawEndpoint.replace(/\/+$/, '');

      const region = (env.REGION || '').trim();
      if (!region) {
        return new Response('Worker 配置错误：缺失环境变量 REGION。', { status: 500 });
      }
      const accessKeyId = env.AWS_ACCESS_KEY_ID ? env.AWS_ACCESS_KEY_ID.trim() : '';
      const secretAccessKey = env.AWS_SECRET_ACCESS_KEY ? env.AWS_SECRET_ACCESS_KEY.trim() : '';

      if (!accessKeyId || !secretAccessKey) {
        return new Response('Worker 配置错误：缺失环境变量 AWS_ACCESS_KEY_ID 或 AWS_SECRET_ACCESS_KEY。', { status: 500 });
      }

      // 5. 构造回源 Target URL
      //    移除 HMAC 验签参数（expires/sign）：它们只供本 Worker 验签，透传给 COS 会
      //    导致 COS 的 S3 V4 签名 canonical query 不一致 → SignatureDoesNotMatch
      const cleanSearch = new URLSearchParams();
      for (const [k, v] of url.searchParams.entries()) {
        if (k !== 'expires' && k !== 'sign') {
          cleanSearch.append(k, v);
        }
      }
      const cleanQs = cleanSearch.toString();
      const targetUrl = new URL(url.pathname + (cleanQs ? '?' + cleanQs : ''), rawEndpoint);

      // 6. 计算标准 S3 V4 签名
      const signedHeaders = await getS3v4Headers({
        method: request.method,
        url: targetUrl,
        region: region,
        accessKeyId: accessKeyId,
        secretAccessKey: secretAccessKey,
      });

      // 移除 host 头，防止 Cloudflare Worker 抛出 Forbidden Header 异常
      const headersForFetch = { ...signedHeaders };
      delete headersForFetch['host'];
      delete headersForFetch['Host'];

      // 发起带私有凭证的回源请求
      const response = await fetch(targetUrl.toString(), {
        method: request.method,
        headers: headersForFetch,
      });

      // 设置跨域 Header（只放行邮件域）并去除敏感头
      const newHeaders = new Headers(response.headers);
      newHeaders.set('Access-Control-Allow-Origin', 'https://mail.duckgame-play.top');
      newHeaders.delete('x-cos-request-id');

      // =====================================================
      // 7. 回源成功后写入 Cache API（按 path；内容哈希不变则无需重复回源）
      //    缓存的响应不带 s-maxage，避免 Cloudflare HTTP 缓存命中时绕过 Worker 验签
      // =====================================================
      if (response.status === 200 && request.method === 'GET') {
        // 附件 key 为内容哈希，文件不变则缓存内容永远有效；
        // TTL 设为 7 天，同文件最多每 7 天回源一次（文件被删除时最迟 7 天失效）
        // 只缓存 GET：HEAD 首次请求如果把空 body 写入缓存，会污染同路径的
        // GET 命中（Cache API 对 GET/HEAD 按同一 key 匹配）→ 附件下载/预览返回空内容
        newHeaders.set('Cache-Control', 'public, max-age=604800');
        const cacheResp = new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: newHeaders,
        });
        ctx.waitUntil(caches.default.put(cacheKey, cacheResp.clone()));
        return cacheResp;
      }

      // 非 200（如回源 404）：不缓存
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders,
      });
    } catch (err) {
      console.error('cos-exchange proxy error:', err);
      return new Response('Internal Server Error', { status: 500 });
    }
  }
};
// =====================================================================
// 签名校验：expires 必须在有效期内，sign 必须与后端用同一密钥算出的
// HMAC-SHA256 一致。
//   sign = hex( HMAC-SHA256( secret, `${pathname}:${expires}` ) )
// =====================================================================
async function verifySignature(url, env) {
  const secret = (env.ATT_SIGN_SECRET || '').trim();
  if (!secret) {
    return { ok: false, reason: 'Worker 未配置 ATT_SIGN_SECRET', remaining: 0 };
  }

  const expires = parseInt(url.searchParams.get('expires') || '', 10);
  const sign = (url.searchParams.get('sign') || '').toLowerCase();
  const now = Math.floor(Date.now() / 1000);

  if (!Number.isFinite(expires) || !sign) {
    return { ok: false, reason: 'Forbidden', remaining: 0 };
  }

  // 已过期
  if (now > expires) {
    return { ok: false, reason: 'Forbidden', remaining: 0 };
  }

  // 防"长期有效签名"：后端误配了超长 TTL 或签名被长期复用也拒绝
  const maxTtl = Math.max(60, Math.min(Number(env.ATT_SIGN_MAX_TTL || 3600), 86400));
  if (expires - now > maxTtl) {
    return { ok: false, reason: 'Forbidden', remaining: 0 };
  }

  // URL 解码后再签名：后端 sign-utils 用原始文件名（含空格/Unicode）签名，
  // 浏览器请求时 pathname 是百分号编码形式，必须解码后才一致
  let pathname = url.pathname;
  try {
    pathname = decodeURIComponent(url.pathname);
  } catch (e) {
    return { ok: false, reason: 'Forbidden', remaining: 0 };
  }

  const expected = await hmacSha256Hex(secret, `${pathname}:${expires}`);

  if (!timingSafeEqual(expected, sign)) {
    return { ok: false, reason: 'Forbidden', remaining: 0 };
  }

  return { ok: true, remaining: expires - now };
}

// HMAC-SHA256 -> 小写 hex（与后端 sign-utils.js 保持一致）
async function hmacSha256Hex(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// 常量时间比较，防止计时侧信道
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
// =====================================================================
// S3 V4 签名核心计算逻辑（原有，未改动）
// =====================================================================
async function getS3v4Headers({ method, url, region, accessKeyId, secretAccessKey }) {
  const service = 's3';
  const host = url.host;
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);

  async function hmacSha256(key, data) {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      typeof key === 'string' ? new TextEncoder().encode(key) : key,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    return await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(data));
  }

  async function sha256Hex(data) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  const payloadHash = 'UNSIGNED-PAYLOAD';
  const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
  const signedHeadersStr = 'host;x-amz-content-sha256;x-amz-date';

  const canonicalRequest = [
    method,
    url.pathname,
    url.search.slice(1),
    canonicalHeaders,
    signedHeadersStr,
    payloadHash
  ].join('\n');

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest)
  ].join('\n');

  const kDate = await hmacSha256('AWS4' + secretAccessKey, dateStamp);
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, service);
  const kSigning = await hmacSha256(kService, 'aws4_request');
  const signatureBuf = await hmacSha256(kSigning, stringToSign);
  const signature = Array.from(new Uint8Array(signatureBuf)).map(b => b.toString(16).padStart(2, '0')).join('');

  return {
    'host': host,
    'x-amz-date': amzDate,
    'x-amz-content-sha256': payloadHash,
    'Authorization': `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeadersStr}, Signature=${signature}`
  };
}

// 导出供测试使用（Cloudflare 只用 default export，不受影响）
export { verifySignature, hmacSha256Hex, timingSafeEqual };

// =====================================================================
// 【文件浏览器】/browse —— 个人只读网盘（请求全部经本 Worker，手机不直连 COS）
// ---------------------------------------------------------------------
// 需要：
//   env.BROWSE_PASS                访问密码（必设；未配置时 /browse 一律拒绝）
//   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / S3_ENDPOINT / REGION
//                                  复用上面的只读子账号（策略需含 GetObject + GetBucket）
// 说明：/browse 是独立密码门控的个人浏览入口，不参与附件签名体系
// =====================================================================
async function handleBrowse(request, env, ctx) {
  const url = new URL(request.url);

  // 国家/地区白名单（可选）：BROWSE_ALLOW_COUNTRY = "CN,HK"，只允许这些地区的 IP 访问 /browse
  const allowC = (env.BROWSE_ALLOW_COUNTRY || '').trim();
  if (allowC) {
    const c = (request.headers.get('CF-IPCountry') || '').toUpperCase();
    if (!allowC.toUpperCase().split(',').map(s => s.trim()).includes(c)) {
      return new Response('Forbidden', { status: 403 });
    }
  }

  // 登录（POST）
  if (request.method === 'POST' && url.pathname === '/browse/login') {
    return await browseLogin(request, env);
  }
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  // 密码门控：未配置 BROWSE_PASS 时直接拒绝，防止误配导致整桶裸奔
  if (!env.BROWSE_PASS || !browseAuthed(request, env.BROWSE_PASS)) {
    return new Response(browseLoginHtml(env), {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff' },
    });
  }

  // 首页
  if (url.pathname === '/browse' || url.pathname === '/browse/') {
    return new Response(browseIndexHtml(), {
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff' },
    });
  }

  // 列目录
  if (url.pathname === '/browse/api/list') {
    if (rateLimited('list:' + clientIP(request), 40, 60000)) {
      return new Response('Too Many Requests', { status: 429, headers: { 'Retry-After': '60' } });
    }
    try {
      const prefix = url.searchParams.get('prefix') || '';
      const token = url.searchParams.get('token') || '';
      const data = await browseList(env, prefix, token);
      return new Response(JSON.stringify(data), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff' },
      });
    } catch (e) {
      console.error('browse list error:', e);
      const msg = String((e && e.message) || e);
      return new Response(msg.startsWith('{') ? msg : JSON.stringify({ error: msg.slice(0, 500) }), {
        status: 500,
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
      });
    }
  }

  // 下载/预览（经本 Worker 回源，不直连 COS）
  if (url.pathname === '/browse/api/file') {
    if (rateLimited('file:' + clientIP(request), 120, 60000)) {
      return new Response('Too Many Requests', { status: 429, headers: { 'Retry-After': '60' } });
    }
    const key = url.searchParams.get('key') || '';
    if (!key || key.startsWith('/') || key.includes('../')) {
      return new Response('bad key', { status: 400 });
    }
    try {
      return await browseFetchFile(env, key, ctx);
    } catch (e) {
      console.error('browse file error:', e);
      return new Response('fetch failed', { status: 500 });
    }
  }

  return new Response('Not Found', { status: 404 });
}

function browseAuthed(request, pass) {
  const cookies = (request.headers.get('Cookie') || '').split(';');
  for (const c of cookies) {
    const [k, v] = c.trim().split('=');
    if (k === 'browse_pwd' && v === browseFingerprint(pass)) {
      return true;
    }
  }
  return false;
}

async function browseLogin(request, env) {
  const ip = clientIP(request);
  if (loginBlocked(ip)) {
    return new Response('Too Many Login Attempts', { status: 429, headers: { 'Retry-After': '600' } });
  }
  const form = await request.formData();
  // Turnstile 人机验证（可选，配置 TURNSTILE_SECRET 后生效）
  if (env.TURNSTILE_SECRET) {
    const token = form.get('cf-turnstile-response') || '';
    if (!token) {
      return new Response('&#x9A8C;&#x8BC1;&#x7801;&#x672A;&#x52A0;&#x8F7D;&#xFF0C;&#x8BF7;&#x91CD;&#x65B0;&#x52A0;&#x8F7D;&#x9875;&#x9762;&#x540E;&#x5B8C;&#x6210;&#x4EBA;&#x673A;&#x9A8C;&#x8BC1;', {
        status: 400,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }
    const ok = await verifyTurnstile(env.TURNSTILE_SECRET, token, ip);
    if (!ok) {
      console.error('turnstile verify failed ip=', ip);
      return new Response('&#x9A8C;&#x8BC1;&#x7801;&#x9A8C;&#x8BC1;&#x5931;&#x8D25;&#xFF0C;&#x8BF7;&#x91CD;&#x8BD5;', {
        status: 400,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }
  }
  const p = form.get('p') || '';
  if (p === env.BROWSE_PASS) {
    loginOk(ip);
    return new Response('', {
      status: 302,
      headers: {
        Location: '/browse',
        'Set-Cookie': `browse_pwd=${browseFingerprint(env.BROWSE_PASS)}; Path=/; Max-Age=604800; SameSite=Lax; HttpOnly; Secure`,
      },
    });
  }
  // 登录失败：计数（同 IP 5 次/10 分钟锁定）+ 强制延迟 1 秒
  loginFailRecord(ip);
  await new Promise(r => setTimeout(r, 1000));
  return new Response('&#x5BC6;&#x7801;&#x9519;&#x8BEF;', {
    status: 401,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

// Turnstile 人机验证（免费、无需绑卡）：用 secret 校验前端提交的 token
async function verifyTurnstile(secret, token, ip) {
  try {
    // remoteip 可选，且必须是合法 IP 才传，否则 siteverify 可能直接拒绝
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$/.test(ip || '');
    let body = `secret=${encodeURIComponent(secret)}&response=${encodeURIComponent(token)}`;
    if (isIp) body += `&remoteip=${encodeURIComponent(ip)}`;
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body,
    });
    const j = await r.json();
    if (!j || !j.success) console.error('turnstile siteverify:', JSON.stringify(j));
    return !!(j && j.success);
  } catch (e) {
    return false;
  }
}

// cookie 校验用轻量指纹（非安全加密场景；正式场景请再加 Cloudflare Access）
function browseFingerprint(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16);
}

// ---- per-IP 速率限制（内存实现；配合 CF Access 更稳）----
const rateMap = new Map();
function rateLimited(key, max, windowMs) {
  if (rateMap.size > 5000) rateMap.clear();
  const now = Date.now();
  const rec = rateMap.get(key);
  if (!rec || now - rec.t > windowMs) {
    rateMap.set(key, { c: 1, t: now });
    return false;
  }
  rec.c++;
  return rec.c > max;
}
const loginFailMap = new Map();
function loginBlocked(ip) {
  const rec = loginFailMap.get(ip);
  return !!(rec && Date.now() - rec.t < 600000 && rec.c >= 5);
}
function loginFailRecord(ip) {
  const rec = loginFailMap.get(ip);
  const now = Date.now();
  if (!rec || now - rec.t > 600000) loginFailMap.set(ip, { c: 1, t: now });
  else rec.c++;
}
function loginOk(ip) { loginFailMap.delete(ip); }
function clientIP(request) {
  return request.headers.get('CF-Connecting-IP') || request.headers.get('x-forwarded-for') || 'unknown';
}

// ---- S3 SigV4 工具（浏览专用，与上方 getS3v4Headers 同算法）----
function enc(s) {
  return encodeURIComponent(s).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function canonQuery(params) {
  return Object.keys(params)
    .sort()
    .map(k => `${enc(k)}=${enc(params[k])}`)
    .join('&');
}

async function hmacHex(key, data) {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    typeof key === 'string' ? new TextEncoder().encode(key) : key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(data));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(data) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function signingKey(sk, dateStamp, region) {
  async function h(key, data) {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      typeof key === 'string' ? new TextEncoder().encode(key) : key,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    return await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(data));
  }
  const kDate = await h('AWS4' + sk, dateStamp);
  const kRegion = await h(kDate, region);
  const kService = await h(kRegion, 's3');
  return await h(kService, 'aws4_request');
}

// 列目录：GET ?list-type=2&delimiter=/&prefix=...&continuation-token=...
async function browseList(env, prefix, token) {
  // 与附件主流程一致：密钥/地域/endpoint 必须 trim（粘贴进 CF 的环境变量常带尾随空格/换行）
  const host = new URL((env.S3_ENDPOINT || '').trim()).host;
  const region = (env.REGION || '').trim();
  const ak = (env.AWS_ACCESS_KEY_ID || '').trim();
  const sk = (env.AWS_SECRET_ACCESS_KEY || '').trim();
  const params = { 'list-type': '2', 'encoding-type': 'url', delimiter: '/' };
  if (prefix) params.prefix = prefix;
  if (token) params['continuation-token'] = token;

  const qs = canonQuery(params);
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  // 与 AWS SDK 一致：GET 无 body，payload hash 用空串的真实 SHA256（e3b0c442…），
  // 而不是 UNSIGNED-PAYLOAD。COS 对 ListObjectsV2 可能不接受 UNSIGNED-PAYLOAD。
  const payloadHash = await sha256Hex('');

  const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
  const signedHeadersStr = 'host;x-amz-content-sha256;x-amz-date';
  const canonicalRequest = ['GET', '/', qs, canonicalHeaders, signedHeadersStr, payloadHash].join('\n');
  const scope = `${dateStamp}/${region}/s3/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, await sha256Hex(canonicalRequest)].join('\n');
  const key = await signingKey(sk, dateStamp, region);
  const signature = await hmacHex(key, stringToSign);
  const auth = `AWS4-HMAC-SHA256 Credential=${ak}/${scope}, SignedHeaders=${signedHeadersStr}, Signature=${signature}`;

  const res = await fetch(`https://${host}/?${qs}`, {
    headers: {
      'x-amz-date': amzDate,
      'x-amz-content-sha256': payloadHash,
      Authorization: auth,
    },
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) {
    const body = await res.text();
    const cos = body.match(/<StringToSign>([\s\S]*?)<\/StringToSign>/);
    // 把两边 StringToSign 都返回，方便直接对照（第4行=canonical request 哈希）
    throw new Error(JSON.stringify({
      error: `list failed ${res.status} (SignatureDoesNotMatch)` + (cos ? '' : ': ' + body.slice(0, 300)),
      ourSTS: stringToSign,
      cosSTS: cos ? cos[1] : '',
      sentUrl: `https://${host}/?${qs}`,
    }));
  }
  const xml = await res.text();
  const parsed = parseListXml(xml);
  if (parsed.folders.length === 0 && parsed.files.length === 0) {
    parsed.raw = xml.slice(0, 800); // 空结果时带回原始 XML，便于确认 COS 返回格式
  }
  return parsed;
}

function parseListXml(xml) {
  const folders = [];
  // 容忍 CommonPrefixes 内部有换行/缩进（COS 实际返回格式带空白）
  const reFolder = /<CommonPrefixes>[\s\S]*?<Prefix>([^<]*)<\/Prefix>[\s\S]*?<\/CommonPrefixes>/g;
  let m;
  while ((m = reFolder.exec(xml))) {
    let p = m[1];
    try { p = decodeURIComponent(p); } catch (e) {}
    folders.push(p);
  }
  const files = [];
  const reFile = /<Contents>([\s\S]*?)<\/Contents>/g;
  while ((m = reFile.exec(xml))) {
    const block = m[1];
    const keyM = block.match(/<Key>([^<]*)<\/Key>/);
    const sizeM = block.match(/<Size>(\d+)<\/Size>/);
    const timeM = block.match(/<LastModified>([^<]*)<\/LastModified>/);
    if (!keyM) continue;
    let k = keyM[1];
    try { k = decodeURIComponent(k); } catch (e) {}
    if (k.endsWith('/')) continue; // 过滤 0 字节「文件夹标记」对象（控制台建文件夹会生成 xxx/）
    files.push({ key: k, size: sizeM ? Number(sizeM[1]) : 0, mtime: timeM ? timeM[1] : '' });
  }
  const truncated = /<IsTruncated>true<\/IsTruncated>/.test(xml);
  const tm = xml.match(/<NextContinuationToken>([^<]*)<\/NextContinuationToken>/);
  return { folders, files, truncated, token: tm ? tm[1] : '' };
}

// 下载：经本 Worker 回源 COS（S3 签名 GET），不直连 COS 默认域名
async function browseFetchFile(env, key, ctx) {
  const rawEndpoint = (env.S3_ENDPOINT || '').trim().replace(/\/+$/, '');
  const region = (env.REGION || '').trim();
  const ak = (env.AWS_ACCESS_KEY_ID || '').trim();
  const sk = (env.AWS_SECRET_ACCESS_KEY || '').trim();
  const encodedPath = '/' + key.split('/').map(enc).join('/');
  const targetUrl = new URL(encodedPath, rawEndpoint);

  // Cache API 按 key 缓存（缩略图/预览会反复请求同一文件，7 天内只回源一次）
  const cacheKey = new Request('https://' + new URL(rawEndpoint).host + '/_browse/' + encodedPath);
  const cached = await caches.default.match(cacheKey);
  if (cached) return cached;

  const signedHeaders = await getS3v4Headers({
    method: 'GET',
    url: targetUrl,
    region: region,
    accessKeyId: ak,
    secretAccessKey: sk,
  });
  const headersForFetch = { ...signedHeaders };
  delete headersForFetch['host'];
  delete headersForFetch['Host'];

  const res = await fetch(targetUrl.toString(), { method: 'GET', headers: headersForFetch, signal: AbortSignal.timeout(10000) });
  let final = res;
  // COS 偶发限流/抖动：429 或 5xx 时重试一次（600ms 后退避）
  if (res.status === 429 || res.status >= 500) {
    await new Promise(r => setTimeout(r, 600));
    final = await fetch(targetUrl.toString(), { method: 'GET', headers: headersForFetch, signal: AbortSignal.timeout(10000) });
  }
  const newHeaders = new Headers(final.headers);
  newHeaders.delete('x-cos-request-id');
  newHeaders.delete('x-cos-hash-crc64ecma');
  newHeaders.set('X-Content-Type-Options', 'nosniff');
  // 非 200 时标记上游状态：X-Upstream-Status 存在 = 429 来自 COS；不存在 = 429 来自 CF（worker 前被拒）
  if (!final.ok) newHeaders.set('X-Upstream-Status', String(final.status));
  if (final.ok) {
    newHeaders.set('Cache-Control', 'public, max-age=604800');
    const cacheResp = new Response(final.body, { status: final.status, statusText: final.statusText, headers: newHeaders });
    ctx.waitUntil(caches.default.put(cacheKey, cacheResp.clone()));
    return cacheResp;
  }
  return new Response(final.body, { status: final.status, statusText: final.statusText, headers: newHeaders });
}

// ---- 页面（全部 ASCII：中文/emoji 用 HTML 实体，免疫粘贴编码问题）----
function browseLoginHtml(env) {
  const sitekey = (env && env.TURNSTILE_SITEKEY) || '';
  const tsScript = sitekey ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' : '';
  const tsWidget = sitekey ? '<div class="cf-turnstile" data-sitekey="' + sitekey + '" data-callback="onTs" style="margin-bottom:14px"></div>' : '';
  const tsJs = sitekey ? '<script>function onTs(){var b=document.getElementById("loginBtn");if(b){b.disabled=false;}}</script>' : '';
  return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>&#x767B;&#x5F55; - COS &#x6587;&#x4EF6;&#x6D4F;&#x89C8;</title>
${tsScript}
${tsJs}
<style>
body{font-family:system-ui,-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;background:#f5f6f8;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#fff;border-radius:12px;padding:32px;width:min(90vw,340px);box-shadow:0 4px 24px rgba(0,0,0,.08)}
h1{font-size:18px;margin:0 0 20px;text-align:center;color:#1a1a2e}
input{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #ddd;border-radius:8px;margin-bottom:14px;font-size:15px}
button{width:100%;padding:11px;border:0;border-radius:8px;background:#3b82f6;color:#fff;font-size:15px;cursor:pointer}
button:disabled{opacity:.5;cursor:not-allowed}
</style></head><body>
<div class="card"><h1>&#x1F510; COS &#x6587;&#x4EF6;&#x6D4F;&#x89C8;</h1>
<form method="post" action="/browse/login"><input type="password" name="p" placeholder="&#x8BBF;&#x95EE;&#x5BC6;&#x7801;" required autofocus>${tsWidget}<button type="submit" id="loginBtn"${sitekey ? ' disabled' : ''}>&#x767B; &#x5F55;</button></form>
</div></body></html>`;
}
function browseIndexHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>COS &#x6587;&#x4EF6;&#x6D4F;&#x89C8;</title>
<style>
:root{--bg:#f3f4f6;--card:#ffffff;--text:#1f2430;--muted:#9aa3b2;--line:#e5e7eb;--accent:#3b82f6;--shadow:0 1px 4px rgba(0,0,0,.06)}
body.dark{--bg:#0f1115;--card:#191c23;--text:#e6e9ef;--muted:#8a93a5;--line:#262b34;--accent:#60a5fa;--shadow:0 1px 4px rgba(0,0,0,.4)}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;background:var(--bg);color:var(--text);margin:0;transition:background .2s,color .2s}
header{position:sticky;top:0;z-index:20;background:var(--card);border-bottom:1px solid var(--line);padding:10px 14px;display:flex;align-items:center;gap:10px}
header h1{font-size:16px;margin:0;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.iconbtn{border:1px solid var(--line);background:var(--card);color:var(--text);border-radius:8px;padding:6px 10px;font-size:13px;cursor:pointer}
.toolbar{position:sticky;top:49px;z-index:15;background:var(--bg);padding:8px 14px;display:flex;flex-wrap:wrap;gap:8px;align-items:center;border-bottom:1px solid var(--line)}
.search{flex:1 1 140px;min-width:110px;padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--text);font-size:14px}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{border:1px solid var(--line);background:var(--card);color:var(--text);border-radius:999px;padding:5px 11px;font-size:12px;cursor:pointer}
.chip.on{background:var(--accent);border-color:var(--accent);color:#fff}
select{padding:6px 8px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--text);font-size:12px}
#crumbs{padding:8px 14px;font-size:13px;background:var(--card);border-bottom:1px solid var(--line);overflow-x:auto;white-space:nowrap}
#crumbs .crumb{color:var(--accent);cursor:pointer;margin-right:6px}
#grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;padding:4px 0 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden;cursor:pointer;box-shadow:var(--shadow);position:relative}
.card:hover{border-color:var(--accent)}
.cimg{width:100%;aspect-ratio:1;object-fit:cover;background:var(--bg);display:block}
.cicon{width:100%;aspect-ratio:1;display:flex;align-items:center;justify-content:center;font-size:46px;background:var(--bg)}
.cbody{padding:8px 10px}
.cname{font-size:13px;word-break:break-all;line-height:1.35;max-height:2.7em;overflow:hidden}
.cmeta{font-size:11px;color:var(--muted);margin-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dl{position:absolute;top:8px;right:8px;width:30px;height:30px;border-radius:8px;border:0;background:rgba(0,0,0,.45);color:#fff;font-size:15px;cursor:pointer;z-index:5}
#loadmore{display:block;width:min(380px,88%);margin:14px auto;padding:10px;border:1px solid var(--line);background:var(--card);border-radius:10px;color:var(--accent);font-size:14px;cursor:pointer}
#status{text-align:center;color:var(--muted);font-size:13px;padding:30px}
#lightbox{position:fixed;inset:0;background:rgba(0,0,0,.93);z-index:100;display:none}
#lightbox.show{display:block}
#lightbox img{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);max-width:94vw;max-height:84vh;object-fit:contain;border-radius:4px}
.lbbtn{position:fixed;z-index:101;border:0;background:rgba(255,255,255,.16);color:#fff;font-size:22px;width:44px;height:44px;border-radius:50%;cursor:pointer}
.lb-close{top:14px;right:14px}
.lb-prev{left:12px;top:50%;transform:translateY(-50%)}
.lb-next{right:12px;top:50%;transform:translateY(-50%)}
#lbcap{position:fixed;bottom:16px;left:0;right:0;text-align:center;color:#ccc;font-size:13px;z-index:101;padding:0 70px;word-break:break-all}
#modal{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:90;display:none;align-items:center;justify-content:center;padding:16px}
#modal.show{display:flex}
#modal .box{background:var(--card);color:var(--text);border-radius:12px;width:min(94vw,860px);max-height:92vh;display:flex;flex-direction:column;overflow:hidden}
#modal .head{display:flex;align-items:center;padding:10px 14px;border-bottom:1px solid var(--line);gap:10px}
#modal .t{flex:1;font-size:14px;word-break:break-all}
#modal .body{flex:1;overflow:auto;min-height:180px;background:var(--card)}
#modal iframe,#modal video,#modal audio{width:100%;border:0;display:block;background:#000}
#modal pre{margin:0;padding:14px;font-size:13px;white-space:pre-wrap;word-break:break-all;font-family:ui-monospace,Consolas,monospace;background:var(--bg);color:var(--text)}
.layout{display:flex;max-width:1180px;margin:0 auto}
.main{flex:1;min-width:0;padding:0 6px}
#side{width:258px;flex-shrink:0;padding:12px;display:none;align-self:flex-start;position:sticky;top:108px}
#side.show{display:block}
#side .side-thumb{width:100%;aspect-ratio:1;object-fit:cover;border-radius:12px;background:var(--bg)}
#side .side-ic{width:100%;aspect-ratio:1;display:flex;align-items:center;justify-content:center;font-size:64px;background:var(--bg);border-radius:12px}
#side .sname{font-size:14px;font-weight:600;margin:10px 0 6px;word-break:break-all}
#side .smeta{font-size:12px;color:var(--muted);line-height:1.9;word-break:break-all}
#side .sbtns{display:flex;gap:6px;margin-top:10px;flex-wrap:wrap}
#side .sbtns .btn{flex:1;text-align:center;min-width:64px}
#viewbar{display:flex;gap:6px;align-items:center;padding:6px 0}
#tableWrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}
#table{width:100%;border-collapse:collapse;font-size:13px}
#table th,#table td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#table thead th{background:var(--card);color:var(--muted);font-size:12px;font-weight:700;cursor:pointer;user-select:none;border-bottom:2px solid var(--line)}
#table thead th:hover{color:var(--accent)}
#table tr{cursor:pointer}
#table tr:hover{background:var(--bg)}
#table tr.sel{background:var(--accent);color:#fff}
#table tr.sel .tmeta{color:#fff}
#table tbody tr:last-child td{border-bottom:0}
#table .tname{max-width:46vw;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#table .tthumb{width:28px;height:28px;object-fit:cover;border-radius:6px;vertical-align:middle;margin-right:8px;background:var(--bg)}
@media (max-width:900px){#side{position:fixed;right:0;top:0;bottom:0;width:280px;z-index:80;background:var(--card);box-shadow:-8px 0 24px rgba(0,0,0,.25);overflow:auto}}
footer{position:fixed;bottom:0;left:0;right:0;text-align:center;font-size:11px;color:var(--muted);padding:6px;background:var(--bg)}
</style></head><body>
<header><h1>&#x1F4C1; COS &#x6587;&#x4EF6;&#x6D4F;&#x89C8;</h1><button class="iconbtn" id="modeBtn" title="&#x6DF1;&#x8272;&#x6A21;&#x5F0F;">&#x1F319;</button></header>
<div class="toolbar">
  <input class="search" id="search" placeholder="&#x641C;&#x7D22;&#x6587;&#x4EF6;&#x540D;..." autocomplete="off">
  <div class="chips" id="chips">
    <span class="chip on" data-f="all">&#x5168;&#x90E8;</span>
    <span class="chip" data-f="img">&#x56FE;&#x7247;</span>
    <span class="chip" data-f="vid">&#x89C6;&#x9891;</span>
    <span class="chip" data-f="doc">&#x6587;&#x6863;</span>
    <span class="chip" data-f="arc">&#x538B;&#x7F29;&#x5305;</span>
    <span class="chip" data-f="oth">&#x5176;&#x4ED6;</span>
  </div>
  <select id="sort">
    <option value="name-asc">&#x540D;&#x79F0; &#x2191;</option>
    <option value="name-desc">&#x540D;&#x79F0; &#x2193;</option>
    <option value="size-desc" selected>&#x5927;&#x5C0F; &#x2193;</option>
    <option value="size-asc">&#x5927;&#x5C0F; &#x2191;</option>
    <option value="time-desc">&#x4FEE;&#x6539;&#x65F6;&#x95F4; &#x2193;</option>
    <option value="time-asc">&#x4FEE;&#x6539;&#x65F6;&#x95F4; &#x2191;</option>
  </select>
  <button class="iconbtn" id="upBtn" title="&#x8FD4;&#x56DE;&#x4E0A;&#x7EA7;">&#x2B06;&#xFE0F;</button>
</div>
<div class="layout">
  <div class="main">
    <div id="crumbs"></div>
    <div id="viewbar"><button class="iconbtn" id="viewBtn">&#x8868;&#x683C;</button></div>
    <div id="grid"><div id="status">&#x52A0;&#x8F7D;&#x4E2D;&#x2026;</div></div>
    <div id="tableWrap" style="display:none"><table id="table"><thead><tr><th data-s="name">&#x540D;&#x79F0;</th><th data-s="size">&#x5927;&#x5C0F;</th><th data-s="time">&#x4FEE;&#x6539;&#x65F6;&#x95F4;</th><th>&#x7C7B;&#x578B;</th></tr></thead><tbody id="tbody"></tbody></table></div>
  </div>
  <aside id="side"></aside>
</div>
<footer>&#x53EA;&#x8BFB;&#x6D4F;&#x89C8; &#xB7; cos-exchange</footer>
<div id="lightbox"><button class="lbbtn lb-close">&#x2715;</button><button class="lbbtn lb-prev">&#x2039;</button><img id="lbImg" alt=""><button class="lbbtn lb-next">&#x203A;</button><div id="lbcap"></div></div>
<div id="modal"><div class="box"><div class="head"><span class="t" id="modalTitle"></span><button class="iconbtn" id="modalClose">&#x5173;&#x95ED;</button></div><div class="body" id="modalBody"></div></div></div>
<script>
let prefix = '';
let token = '';
let truncated = false;
let filter = 'all';
let keyword = '';
let sortVal = 'size-desc';
let allData = null;
let imgs = [];
let imgIdx = 0;
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/'/g,'&#39;').replace(/"/g,'&quot;');
const escAttr = s => String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;');
const IMG = ['png','jpg','jpeg','gif','webp','bmp','svg'];
const VID = ['mp4','mkv','mov','avi','webm','m4v'];
const AUD = ['mp3','wav','flac','ogg','m4a'];
const DOC = ['pdf','doc','docx','xls','xlsx','ppt','pptx','txt','md','csv','json','html','htm'];
const ARC = ['zip','rar','7z','tar','gz','bz2','xz'];
const icons = {jpg:'&#x1F5BC;&#xFE0F;',jpeg:'&#x1F5BC;&#xFE0F;',png:'&#x1F5BC;&#xFE0F;',gif:'&#x1F5BC;&#xFE0F;',webp:'&#x1F5BC;&#xFE0F;',bmp:'&#x1F5BC;&#xFE0F;',svg:'&#x1F5BC;&#xFE0F;',pdf:'&#x1F4D5;',zip:'&#x1F5DC;&#xFE0F;',rar:'&#x1F5DC;&#xFE0F;','7z':'&#x1F5DC;&#xFE0F;',tar:'&#x1F5DC;&#xFE0F;',gz:'&#x1F5DC;&#xFE0F;',mp3:'&#x1F3B5;',wav:'&#x1F3B5;',flac:'&#x1F3B5;',ogg:'&#x1F3B5;',mp4:'&#x1F3AC;',mkv:'&#x1F3AC;',mov:'&#x1F3AC;',avi:'&#x1F3AC;',webm:'&#x1F3AC;',doc:'&#x1F4C4;',docx:'&#x1F4C4;',txt:'&#x1F4C3;',md:'&#x1F4C3;',csv:'&#x1F4C3;',xls:'&#x1F4CA;',xlsx:'&#x1F4CA;',ppt:'&#x1F4FD;&#xFE0F;',pptx:'&#x1F4FD;&#xFE0F;',html:'&#x1F310;',htm:'&#x1F310;',exe:'&#x2699;&#xFE0F;',apk:'&#x1F4F1;'};
const ext = n => (n.split('.').pop() || '').toLowerCase();
const iconOf = n => icons[ext(n)] || '&#x1F4E6;';
const fmt = s => s < 1024 ? s+' B' : s < 1048576 ? (s/1024).toFixed(1)+' KB' : (s/1048576).toFixed(1)+' MB';
const fmtT = t => { if(!t) return ''; const d = new Date(t); if(isNaN(d)) return ''; const p = n => String(n).padStart(2,'0'); return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes()); };
const urlOf = k => '/browse/api/file?key=' + encodeURIComponent(k);
const typeOf = n => { const e = ext(n); if(IMG.includes(e)) return 'img'; if(VID.includes(e)||AUD.includes(e)) return 'vid'; if(DOC.includes(e)) return 'doc'; if(ARC.includes(e)) return 'arc'; return 'oth'; };
async function load(reset) {
  if (reset) { token = ''; truncated = false; }
  const q = new URLSearchParams({prefix});
  if (token) q.set('token', token);
  $('grid').innerHTML = '<div id="status">&#x52A0;&#x8F7D;&#x4E2D;&#x2026;</div>';
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 15000);
    const res = await fetch('/browse/api/list?' + q, { signal: ctrl.signal });
    clearTimeout(timer);
    if (res.status === 429) {
      $('grid').innerHTML = '<div id="status">&#x8BF7;&#x6C42;&#x8FC7;&#x4E8E;&#x9891;&#x7E41;(429)&#xFF0C;&#x7A0D;&#x540E;&#x81EA;&#x52A8;&#x91CD;&#x8BD5;&#x2026;</div>';
      setTimeout(() => load(reset), 4000);
      return;
    }
    if (!res.ok) {
      $('grid').innerHTML = '<div id="status">&#x52A0;&#x8F7D;&#x5931;&#x8D25;(HTTP ' + res.status + ')</div>';
      return;
    }
    let data;
    try { data = await res.json(); } catch (e) {
      $('grid').innerHTML = '<div id="status">&#x52A0;&#x8F7D;&#x5931;&#x8D25;(&#x4E0D;&#x662F;&#x6709;&#x6548;&#x54CD;&#x5E94;) HTTP ' + res.status + '</div>';
      return;
    }
    if (data.error) { $('grid').innerHTML = '<div id="status">&#x52A0;&#x8F7D;&#x5931;&#x8D25;: ' + esc(data.error) + '</div>'; return; }
    allData = data;
    truncated = data.truncated;
    token = data.token || '';
    render();
  } catch (e) {
    $('grid').innerHTML = '<div id="status">&#x52A0;&#x8F7D;&#x5931;&#x8D25;: ' + esc(String((e && e.message) || e)) + '</div>';
  }
}

function visibleList() {
  let list = [];
  for (const f of (allData.files || [])) {
    const name = f.key.split('/').pop();
    list.push({ key: f.key, name, size: f.size || 0, mtime: f.mtime || '', type: typeOf(name) });
  }
  if (filter !== 'all') list = list.filter(o => o.type === filter);
  if (keyword) { const kw = keyword.toLowerCase(); list = list.filter(o => o.name.toLowerCase().includes(kw)); }
  const [field, dir] = sortVal.split('-');
  const mul = dir === 'asc' ? 1 : -1;
  list.sort((a, b) => {
    if (field === 'size') return (a.size - b.size) * mul;
    if (field === 'time') return (a.mtime < b.mtime ? -1 : a.mtime > b.mtime ? 1 : 0) * mul;
    return a.name.localeCompare(b.name) * mul;
  });
  return list;
}

function render() {
  const folders = allData ? (allData.folders || []) : [];
  const files = visibleList();
  imgs = files.filter(o => o.type === 'img');
  const box = $('grid');
  const crumb = $('crumbs');
  let html = '';
  for (const f of folders) {
    const name = f.slice(0, -1).split('/').pop();
    html += '<div class="card" data-act="open" data-key="' + escAttr(f) + '"><div class="cicon">&#x1F4C1;</div><div class="cbody"><div class="cname">' + esc(name) + '</div><div class="cmeta">&#x6587;&#x4EF6;&#x5939;</div></div></div>';
  }
  for (const o of files) {
    const thumb = o.type === 'img' ? '<img class="cimg" loading="lazy" data-src="' + urlOf(o.key) + '" decoding="async">' : '<div class="cicon">' + iconOf(o.name) + '</div>';
    const meta = fmt(o.size) + (o.mtime ? ' &#xB7; ' + esc(fmtT(o.mtime)) : '');
    html += '<div class="card" data-act="sel" data-key="' + escAttr(o.key) + '"><button class="dl" data-dl="' + escAttr(o.key) + '">&#x2913;</button>' + thumb + '<div class="cbody"><div class="cname">' + esc(o.name) + '</div><div class="cmeta">' + meta + '</div></div></div>';
  }
  if (folders.length === 0 && files.length === 0 && !(allData && allData.raw)) {
    html = '<div id="status">&#xFF08;&#x7A7A;&#x76EE;&#x5F55;&#xFF09;</div>';
  }
  if (truncated) html += '<button id="loadmore">&#x52A0;&#x8F7D;&#x66F4;&#x591A;</button>';
  box.innerHTML = html;
  lazyBind();

  const parts = prefix.split('/').filter(Boolean);
  let cr = '<span class="crumb" data-cr="">&#x6839;&#x76EE;&#x5F55;</span>';
  let acc = '';
  parts.forEach((p) => { acc += p + '/'; cr += ' / <span class="crumb" data-cr="' + escAttr(acc) + '">' + esc(p) + '</span>'; });
  crumb.innerHTML = cr;

  box.onclick = (e) => {
    const dl = e.target.closest('[data-dl]');
    if (dl) { e.stopPropagation(); window.location.href = urlOf(dl.getAttribute('data-dl')); return; }
    const card = e.target.closest('.card');
    if (!card) return;
    const act = card.dataset.act;
    const key = card.dataset.key || '';
    if (act === 'open') open(key);
    else if (act === 'sel') selectRow(key);
  };
  const lm = $('loadmore');
  if (lm) lm.onclick = () => load(false);
  crumb.onclick = (e) => { const c = e.target.closest('.crumb'); if (c) go(c.dataset.cr || ''); };

  $('grid').style.display = view === 'grid' ? '' : 'none';
  $('tableWrap').style.display = view === 'table' ? '' : 'none';
  if (view === 'table') renderTable();
}
function clearSel() {
  selKey = '';
  $('side').classList.remove('show');
  $('side').innerHTML = '';
  document.querySelectorAll('#table tr.sel').forEach(r => r.classList.remove('sel'));
}
function go(p) { clearSel(); prefix = p; load(true); window.scrollTo(0, 0); }
function up() { clearSel(); const parts = prefix.split('/').filter(Boolean); parts.pop(); prefix = parts.length ? parts.join('/') + '/' : ''; load(true); window.scrollTo(0, 0); }
function open(p) { clearSel(); prefix = p; load(true); window.scrollTo(0, 0); }

function showLightbox(key) {
  if (imgs.length === 0) return;
  const idx = imgs.findIndex(o => o.key === key);
  imgIdx = idx >= 0 ? idx : 0;
  const img = $('lbImg');
  const cap = $('lbcap');
  const show = () => {
    const o = imgs[imgIdx];
    img.src = urlOf(o.key);
    cap.textContent = (imgIdx + 1) + '/' + imgs.length + '  ' + o.name;
  };
  $('lightbox').classList.add('show');
  show();
  $('lightbox').onclick = (e) => {
    if (e.target.closest('.lb-close')) closeLb();
    else if (e.target.closest('.lb-prev')) { imgIdx = (imgIdx - 1 + imgs.length) % imgs.length; show(); }
    else if (e.target.closest('.lb-next')) { imgIdx = (imgIdx + 1) % imgs.length; show(); }
  };
}
function closeLb() { $('lightbox').classList.remove('show'); $('lbImg').src = ''; }

function preview(key) {
  const name = key.split('/').pop();
  const e = ext(name);
  const box = $('modalBody');
  $('modalTitle').textContent = name;
  if (VID.includes(e)) {
    box.innerHTML = '<video controls autoplay src="' + urlOf(key) + '"></video>';
  } else if (AUD.includes(e)) {
    box.innerHTML = '<audio controls src="' + urlOf(key) + '"></audio>';
  } else if (e === 'pdf') {
    box.innerHTML = '<iframe src="' + urlOf(key) + '#toolbar=0"></iframe>';
  } else if (['txt','md','csv','json','log'].includes(e)) {
    box.innerHTML = '<div id="status">&#x52A0;&#x8F7D;&#x4E2D;&#x2026;</div>';
    $('modal').classList.add('show');
    fetch(urlOf(key)).then(r => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.text(); }).then(t => { box.innerHTML = '<pre>' + esc(t.slice(0, 200000)) + '</pre>'; }).catch(() => { box.innerHTML = '<pre>&#x52A0;&#x8F7D;&#x5931;&#x8D25;</pre>'; });
    return;
  } else {
    window.location.href = urlOf(key);
    return;
  }
  $('modal').classList.add('show');
}
function closeModal() { $('modal').classList.remove('show'); $('modalBody').innerHTML = ''; }

$('upBtn').onclick = up;
$('modeBtn').onclick = () => {
  document.body.classList.toggle('dark');
  try { localStorage.setItem('browseDark', document.body.classList.contains('dark') ? '1' : '0'); } catch (e) {}
  $('modeBtn').innerHTML = document.body.classList.contains('dark') ? '&#x2600;&#xFE0F;' : '&#x1F319;';
};
$('search').addEventListener('input', (e) => { keyword = e.target.value; render(); });
$('sort').addEventListener('change', (e) => { sortVal = e.target.value; render(); });
$('chips').addEventListener('click', (e) => {
  const c = e.target.closest('.chip');
  if (!c) return;
  filter = c.dataset.f;
  document.querySelectorAll('.chip').forEach(x => x.classList.toggle('on', x === c));
  render();
});
$('modalClose').onclick = closeModal;
$('modal').onclick = (e) => { if (e.target === $('modal')) closeModal(); };
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') { closeLb(); closeModal(); }
});
try { if (localStorage.getItem('browseDark') === '1') { document.body.classList.add('dark'); $('modeBtn').innerHTML = '&#x2600;&#xFE0F;'; } } catch (e) {}

let view = 'grid';
let selKey = '';
let io = null;
const TYPE_LABEL = { img:'&#x56FE;&#x7247;', vid:'&#x89C6;&#x9891;', doc:'&#x6587;&#x6863;', arc:'&#x538B;&#x7F29;&#x5305;', oth:'&#x5176;&#x4ED6;' };
const typeLabel = o => TYPE_LABEL[o.type] || '';

const MAX_CONCURRENT = 4;
let thumbQueue = [];
let thumbActive = 0;
function thumbPump() {
  while (thumbActive < MAX_CONCURRENT && thumbQueue.length) {
    const img = thumbQueue.shift();
    if (!img || img.dataset.src === undefined) continue;
    thumbActive++;
    img.onload = () => { thumbActive--; thumbPump(); };
    img.onerror = () => { thumbActive--; thumbPump(); };
    img.src = img.dataset.src;
    img.removeAttribute('data-src');
  }
}
if ('IntersectionObserver' in window) {
  io = new IntersectionObserver((entries) => {
    for (const en of entries) {
      if (en.isIntersecting) {
        const img = en.target;
        if (img.dataset.src) { thumbQueue.push(img); thumbPump(); }
        io.unobserve(img);
      }
    }
  }, { rootMargin: '400px' });
}
function lazyBind(root) {
  const imgs = (root || document).querySelectorAll('img.cimg[data-src], img.tthumb[data-src]');
  imgs.forEach(img => { if (io) io.observe(img); else { thumbQueue.push(img); thumbPump(); } });
}

function renderTable() {
  const folders = allData ? (allData.folders || []) : [];
  const files = visibleList();
  const tb = $('tbody');
  let html = '';
  for (const f of folders) {
    const name = f.slice(0, -1).split('/').pop();
    html += '<tr data-key="' + escAttr(f) + '" data-is="folder"><td class="tname">&#x1F4C1; ' + esc(name) + '</td><td>&#x2014;</td><td>&#x2014;</td><td>&#x6587;&#x4EF6;&#x5939;</td></tr>';
  }
  for (const o of files) {
    const thumb = o.type === 'img' ? '<img class="tthumb" loading="lazy" data-src="' + urlOf(o.key) + '" decoding="async">' : '';
    html += '<tr data-key="' + escAttr(o.key) + '" data-is="file"><td class="tname">' + thumb + iconOf(o.name) + ' ' + esc(o.name) + '</td><td>' + fmt(o.size) + '</td><td>' + esc(fmtT(o.mtime)) + '</td><td>' + typeLabel(o) + '</td></tr>';
  }
  tb.innerHTML = html || '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:30px">&#xFF08;&#x7A7A;&#x76EE;&#x5F55;&#xFF09;</td></tr>';
  lazyBind(tb);
  tb.onclick = (e) => {
    const tr = e.target.closest('tr');
    if (!tr) return;
    const key = tr.dataset.key || '';
    if (tr.dataset.is === 'folder') { open(key); return; }
    selectRow(key);
  };
  if (selKey) document.querySelectorAll('#table tr').forEach(r => r.classList.toggle('sel', r.dataset.key === selKey));
}

function selectRow(key) {
  selKey = key;
  document.querySelectorAll('#table tr').forEach(r => r.classList.toggle('sel', r.dataset.key === key));
  const item = (allData.files || []).map(f => {
    const n = f.key.split('/').pop();
    return { key: f.key, name: n, size: f.size || 0, mtime: f.mtime || '', type: typeOf(n) };
  }).find(x => x.key === key);
  if (!item) return;
  const thumb = item.type === 'img' ? '<img class="side-thumb" src="' + urlOf(item.key) + '">' : '<div class="side-ic">' + iconOf(item.name) + '</div>';
  $('side').innerHTML = thumb +
    '<div class="sname">' + esc(item.name) + '</div>' +
    '<div class="smeta">&#x5927;&#x5C0F;: ' + fmt(item.size) + '<br>&#x4FEE;&#x6539;&#x65F6;&#x95F4;: ' + esc(fmtT(item.mtime)) + '<br>&#x7C7B;&#x578B;: ' + typeLabel(item) + '<br>&#x8DEF;&#x5F84;: ' + esc(item.key) + '</div>' +
    '<div class="sbtns"><button class="btn" data-a="prev">&#x9884;&#x89C8;</button><button class="btn" data-a="dl">&#x4E0B;&#x8F7D;</button></div>';
  $('side').classList.add('show');
  $('side').onclick = (e) => {
    const b = e.target.closest('.btn');
    if (!b) return;
    if (b.dataset.a === 'dl') window.location.href = urlOf(item.key);
    else if (item.type === 'img') showLightbox(item.key);
    else preview(item.key);
  };
}

$('viewBtn').onclick = () => {
  view = view === 'grid' ? 'table' : 'grid';
  $('viewBtn').innerHTML = view === 'grid' ? '&#x8868;&#x683C;' : '&#x5361;&#x7247;';
  $('grid').style.display = view === 'grid' ? '' : 'none';
  $('tableWrap').style.display = view === 'table' ? '' : 'none';
  if (view === 'table') renderTable();
};
document.querySelectorAll('#table th[data-s]').forEach(th => {
  th.onclick = () => {
    const field = th.dataset.s;
    sortVal = (sortVal === field + '-asc') ? field + '-desc' : field + '-asc';
    $('sort').value = sortVal;
    render();
  };
});

load(true);
</script></body></html>`;
}

