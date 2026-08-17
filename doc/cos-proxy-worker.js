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

// =====================================================================
// 【文件浏览器】/browse —— Alist 风格个人只读网盘页面（登录页 + 主界面）
// ---------------------------------------------------------------------
// 说明：
//   - 本文件只含两个 HTML 页面函数（登录页 browseLoginHtml / 主界面
//     browseIndexHtml），由 _build-browse.mjs 合并进 cos-proxy-worker.js。
//     原附件签名代理、浏览后端、限流、人机验证等逻辑全部保持不变。
//   - 两个模板里的中文/emoji 在构建时会被转换成：
//       <script> 内  -> \uXXXX 转义
//       <script> 外  -> HTML 实体 &#xXXXX;
//     保证 served 页面永远是纯 ASCII，避免粘贴/编辑时编码损坏。
//   - 手写模板时不要引入反引号 ` 与 ${（除页面内声明的插值外），
//     也不要在内联 JS 里写反斜杠正则（如 \d）。
// =====================================================================

function browseLoginHtml(env) {
  const sitekey = (env && env.TURNSTILE_SITEKEY) || '';
  const tsScript = sitekey ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' : '';
  const tsWidget = sitekey ? '<div class="cf-turnstile" data-sitekey="' + sitekey + '" data-callback="onTs"></div>' : '';
  const tsJs = sitekey ? '<script>function onTs(){var b=document.getElementById("loginBtn");if(b){b.disabled=false;}}</script>' : '';
  return `<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#2f6bff">
<title>&#x767B;&#x5F55; &#xB7; COS &#x7F51;&#x76D8;</title>
<style>
:root{--accent:#2f6bff;--text:#1f2329;--muted:#9aa0a8}
@media (prefers-color-scheme:dark){:root{--accent:#4c80ff;--text:#e8eaed;--muted:#6b7280}body{background:linear-gradient(160deg,#0d1016,#151a26)}.card{background:#171b23;box-shadow:0 14px 44px rgba(0,0,0,.5)}input{border-color:#252a35;background:#1d222b;color:#e8eaed}.hint{color:#626a78}}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;background:linear-gradient(160deg,#eef3fb,#f7f8fb);color:var(--text);display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.card{width:min(92vw,360px);background:#fff;border-radius:20px;padding:36px 30px 26px;box-shadow:0 14px 44px rgba(31,35,41,.1);text-align:center}
.logo{font-size:44px;line-height:1;margin-bottom:12px}
h1{font-size:21px;margin:0 0 6px;font-weight:700}
.sub{font-size:13px;color:var(--muted);margin:0 0 24px}
input[type=password]{width:100%;height:44px;border:1px solid #e2e5ea;border-radius:12px;padding:0 15px;font-size:15px;outline:none;background:#fafbfc;margin-bottom:14px;color:var(--text)}
input[type=password]:focus{border-color:var(--accent);background:#fff}
.cf-turnstile{margin-bottom:14px;display:flex;justify-content:center}
button{width:100%;height:44px;border:0;border-radius:12px;background:var(--accent);color:#fff;font-size:15px;font-weight:600;cursor:pointer;transition:filter .15s,opacity .15s}
button:hover{filter:brightness(1.08)}
button:disabled{opacity:.5;cursor:not-allowed}
.err{min-height:20px;margin:10px 0 0;font-size:13px;color:#e5484d;line-height:20px}
.hint{margin-top:22px;font-size:11px;color:#b9bec6}
</style></head><body>
<div class="card">
  <div class="logo">&#x2601;&#xFE0F;</div>
  <h1>COS &#x7F51;&#x76D8;</h1>
  <p class="sub">&#x8F93;&#x5165;&#x8BBF;&#x95EE;&#x5BC6;&#x7801;&#x4EE5;&#x7EE7;&#x7EED;</p>
  <form method="post" action="/browse/login" id="loginForm">
    <input type="password" name="p" placeholder="&#x8BBF;&#x95EE;&#x5BC6;&#x7801;" required autofocus>
    ${tsWidget}
    <button type="submit" id="loginBtn"${sitekey ? ' disabled' : ''}>&#x767B;&#x5F55;</button>
  </form>
  <div class="err" id="loginErr"></div>
  <div class="hint">&#x53EA;&#x8BFB;&#x6D4F;&#x89C8; &middot; cos-exchange</div>
</div>
${tsScript}
${tsJs}
<script>
var btn=document.getElementById('loginBtn');
var form=document.getElementById('loginForm');
var err=document.getElementById('loginErr');
var original=btn.textContent;
function onTs(){ if(btn){ btn.disabled=false; } }
form.addEventListener('submit',function(ev){
  ev.preventDefault();
  if(btn.disabled){ return; }
  btn.disabled=true;
  btn.textContent='\\u767B\\u5F55\\u4E2D\\u2026';
  var fd=new FormData(form);
  fetch(form.action,{method:'POST',body:fd,credentials:'same-origin'})
  .then(function(r){
    if(r.redirected||(r.ok&&r.url.indexOf('/browse')>=0)){ window.location.href='/browse'; return null; }
    return r.text().then(function(t){ return {status:r.status,text:t}; });
  })
  .then(function(o){
    if(!o){ return; }
    if(o.status===429){ err.innerHTML='\\u8BF7\\u6C42\\u8FC7\\u4E8E\\u9891\\u7E41\\uFF0C\\u8BF7\\u7A0D\\u540E\\u518D\\u8BD5'; }
    else if(o.text){ err.innerHTML=o.text; }
    else { err.innerHTML='\\u767B\\u5F55\\u5931\\u8D25\\uFF0C\\u8BF7\\u91CD\\u8BD5'; }
    btn.disabled=false;
    btn.textContent=original;
  })
  .catch(function(){
    err.innerHTML='\\u7F51\\u7EDC\\u9519\\u8BEF\\uFF0C\\u8BF7\\u91CD\\u8BD5';
    btn.disabled=false;
    btn.textContent=original;
  });
});
</script>
</body></html>`;
}


function browseIndexHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#2f6bff">
<title>COS &#x7F51;&#x76D8;</title>
<style>
:root{--bg:#f5f6f8;--card:#ffffff;--text:#1f2329;--sub:#646a73;--muted:#9aa0a8;--line:#e6e8ec;--line2:#eef0f3;--accent:#2f6bff;--accent-weak:#e9efff;--hover:#f0f2f5;--danger:#e5484d;--shadow:0 1px 3px rgba(31,35,41,.08);--radius:12px}
body.dark{--bg:#0d1016;--card:#171b23;--text:#e8eaed;--sub:#9aa2ae;--muted:#626a78;--line:#252a35;--line2:#1d222b;--accent:#4c80ff;--accent-weak:#1b2a4e;--hover:#1f242e;--danger:#f0574f;--shadow:0 1px 3px rgba(0,0,0,.45)}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{font-family:system-ui,-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased;transition:background .2s,color .2s}
button{font-family:inherit;color:var(--text);cursor:pointer}
.topbar{position:sticky;top:0;z-index:60;display:flex;align-items:center;gap:8px;height:52px;padding:0 12px;background:var(--card);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:8px;font-size:16px;font-weight:700;white-space:nowrap;cursor:pointer;user-select:none}
.brand .logo{font-size:19px;line-height:1}
.searchwrap{flex:1;max-width:430px;margin:0 4px 0 8px;position:relative}
.searchwrap input{width:100%;height:34px;border:1px solid var(--line);border-radius:17px;background:var(--bg);color:var(--text);padding:0 13px 0 32px;font-size:14px;outline:none;transition:border .15s,background .15s}
.searchwrap input:focus{border-color:var(--accent);background:var(--card)}
.searchwrap .sic{position:absolute;left:11px;top:50%;transform:translateY(-50%);font-size:12px;color:var(--muted);pointer-events:none}
.headbtns{display:flex;align-items:center;gap:2px;margin-left:auto}
.iconbtn{width:34px;height:34px;border:0;border-radius:9px;background:transparent;color:var(--sub);font-size:16px;display:inline-flex;align-items:center;justify-content:center;transition:background .15s,color .15s}
.iconbtn:hover{background:var(--hover);color:var(--text)}
.iconbtn:active{transform:scale(.94)}
.layout{display:flex;max-width:1280px;margin:0 auto;min-height:calc(100vh - 52px)}
.sidebar{width:216px;flex-shrink:0;padding:16px 10px 12px;border-right:1px solid var(--line);display:flex;flex-direction:column}
.sb-brand{display:none}
.sb-nav{display:flex;flex-direction:column;gap:2px}
.sb-item{display:flex;align-items:center;gap:11px;padding:9px 12px;border-radius:10px;font-size:14px;color:var(--sub);cursor:pointer;user-select:none;transition:background .15s,color .15s}
.sb-item .ic{font-size:16px;width:20px;text-align:center;flex-shrink:0}
.sb-item:hover{background:var(--hover);color:var(--text)}
.sb-item.on{background:var(--accent-weak);color:var(--accent);font-weight:600}
.sb-foot{margin-top:auto;padding:12px 8px 2px;font-size:11px;color:var(--muted)}
.main{flex:1;min-width:0;padding:0 16px 34px}
.crumbs{display:flex;align-items:center;gap:2px;padding:13px 0 6px;font-size:14px;overflow-x:auto;white-space:nowrap;scrollbar-width:none}
.crumbs::-webkit-scrollbar{display:none}
.crumb{color:var(--sub);cursor:pointer;padding:3px 5px;border-radius:6px}
.crumb:hover{color:var(--accent);background:var(--hover)}
.chips{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.chip{height:28px;padding:0 11px;border:1px solid var(--line);border-radius:999px;background:var(--card);color:var(--sub);font-size:12px;display:inline-flex;align-items:center;cursor:pointer;transition:all .15s;user-select:none}
.chip:hover{color:var(--text);border-color:var(--accent)}
.chip.on{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px}
.item{position:relative;background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:12px 10px 10px;cursor:pointer;transition:box-shadow .15s,border-color .15s,transform .1s;user-select:none}
.item:hover{border-color:var(--accent);box-shadow:var(--shadow)}
.item:active{transform:scale(.98)}
.it-ic{height:76px;display:flex;align-items:center;justify-content:center;font-size:44px;line-height:1;background:var(--line2);border-radius:10px;margin-bottom:9px;overflow:hidden}
.it-ic .it-img{width:100%;height:100%;object-fit:cover;display:block}
.it-name{font-size:13px;line-height:1.35;word-break:break-all;max-height:2.7em;overflow:hidden}
.it-meta{font-size:11px;color:var(--muted);margin-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.it-more{position:absolute;top:6px;right:6px;width:26px;height:26px;border:0;border-radius:7px;background:rgba(0,0,0,.5);color:#fff;font-size:14px;line-height:1;cursor:pointer;opacity:0;transition:opacity .15s;z-index:3}
.item:hover .it-more,.item:focus-within .it-more{opacity:1}
@media (hover:none){.it-more{opacity:.9}}
.tblwrap{overflow-x:auto;border:1px solid var(--line);border-radius:var(--radius);background:var(--card)}
table.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th,.tbl td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
.tbl th{color:var(--muted);font-size:12px;font-weight:600;cursor:pointer;user-select:none;background:var(--card)}
.tbl th:hover{color:var(--accent)}
.tbl tbody tr{cursor:pointer}
.tbl tbody tr:hover{background:var(--hover)}
.tbl tbody tr:last-child td{border-bottom:0}
.tbl .c-name{display:flex;align-items:center;gap:8px;max-width:44vw;overflow:hidden}
.tbl .c-name .ic{font-size:18px;flex-shrink:0}
.tbl .c-name .nm{overflow:hidden;text-overflow:ellipsis}
.tbl .td-size{color:var(--sub)}
.tbl .td-time{color:var(--muted)}
.tbl .td-more{color:var(--muted);text-align:right;font-size:15px}
.status{padding:44px 0;text-align:center;color:var(--muted);font-size:14px}
.status .s-ic{font-size:38px;display:block;margin-bottom:10px;opacity:.85}
#loadmore{display:block;width:min(360px,86%);margin:16px auto;padding:10px;border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--accent);font-size:14px;cursor:pointer}
#loadmore:hover{border-color:var(--accent)}
#lightbox{position:fixed;inset:0;background:rgba(0,0,0,.94);z-index:120;display:none;flex-direction:column}
#lightbox.show{display:flex}
.lb-top{position:absolute;top:0;left:0;right:0;display:flex;align-items:center;padding:10px 12px;color:#fff;z-index:2}
.lb-cap{flex:1;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding:0 10px}
.lb-btn{width:40px;height:40px;border:0;border-radius:50%;background:rgba(255,255,255,.14);color:#fff;font-size:18px;cursor:pointer;flex-shrink:0;display:inline-flex;align-items:center;justify-content:center}
.lb-btn:hover{background:rgba(255,255,255,.28)}
#lbImg{flex:1;min-height:0;object-fit:contain;max-width:100%;max-height:100%;margin:auto}
.lb-nav{position:absolute;top:50%;transform:translateY(-50%);z-index:2}
.lb-prev{left:12px}
.lb-next{right:12px}

#sheet{position:fixed;left:0;right:0;bottom:0;z-index:110;background:var(--card);border-radius:16px 16px 0 0;box-shadow:0 -8px 30px rgba(0,0,0,.22);max-height:90vh;display:flex;flex-direction:column;transform:translateY(104%);transition:transform .28s ease;visibility:hidden}
#sheet.show{transform:none;visibility:visible}
.sh-grab{width:36px;height:4px;border-radius:2px;background:var(--line);margin:8px auto 2px}
.sh-head{display:flex;align-items:center;gap:10px;padding:8px 16px 10px;border-bottom:1px solid var(--line)}
.sh-title{flex:1;font-size:15px;font-weight:600;word-break:break-all;line-height:1.4;max-height:2.8em;overflow:hidden}
.sh-body{flex:1;overflow:auto;padding:14px 16px 6px;min-height:120px}
.sh-meta{font-size:12px;color:var(--sub);line-height:2;word-break:break-all}
.sh-meta b{color:var(--muted);font-weight:500;display:inline-block;min-width:64px}
.sh-actions{display:flex;gap:8px;padding:12px 16px calc(14px + env(safe-area-inset-bottom))}
.btn{flex:1;height:38px;border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--text);font-size:13px;display:inline-flex;align-items:center;justify-content:center;gap:5px;transition:background .15s}
.btn:hover{background:var(--hover)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.primary:hover{filter:brightness(1.06)}
.preview{background:#000;border-radius:10px;overflow:hidden;margin:0 0 12px;min-height:60px}
.preview img{display:block;max-width:100%;max-height:56vh;object-fit:contain;margin:0 auto}
.preview video,.preview audio{width:100%;max-height:56vh;border:0;display:block}
.preview iframe{width:100%;height:56vh;border:0;background:#fff;display:block}
.preview pre{margin:0;padding:12px;font-size:12.5px;white-space:pre-wrap;word-break:break-all;font-family:ui-monospace,Consolas,'Courier New',monospace;background:var(--bg);color:var(--text);max-height:48vh;overflow:auto}
.preview .ph{color:#c5c9d0;text-align:center;padding:30px 12px;font-size:13px}
.preview .ph .big{font-size:42px;display:block;margin-bottom:10px}
#toast{position:fixed;left:50%;bottom:26px;transform:translateX(-50%) translateY(20px);background:rgba(20,22,26,.92);color:#fff;padding:9px 16px;border-radius:10px;font-size:13px;opacity:0;pointer-events:none;transition:all .25s;z-index:200;max-width:86vw;text-align:center}
#toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.scrim{position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:75;opacity:0;pointer-events:none;transition:opacity .25s}
.scrim.show{opacity:1;pointer-events:auto}
@media (max-width:860px){
  .sidebar{position:fixed;left:0;top:0;bottom:0;width:250px;z-index:85;background:var(--card);border-right:0;box-shadow:8px 0 30px rgba(0,0,0,.25);transform:translateX(-104%);transition:transform .28s ease;padding-top:16px}
  .sidebar.open{transform:none}
  .sb-brand{display:flex;align-items:center;gap:8px;font-size:15px;font-weight:700;padding:0 12px 14px;border-bottom:1px solid var(--line);margin-bottom:10px}
  .sb-foot{display:none}
  .brand .bname{display:none}
  .grid{grid-template-columns:repeat(auto-fill,minmax(98px,1fr));gap:9px}
  .item{padding:8px 6px}
  .it-ic{height:58px;font-size:34px;margin-bottom:7px}
  .it-name{font-size:12px}
  .it-meta{font-size:10px}
  .searchwrap{max-width:none}
  .main{padding:0 8px 24px}
  .crumbs{padding:10px 2px 4px;font-size:13px}
  .toolbar{padding:8px 2px 10px}
}
@media (min-width:861px){
  #menuBtn{display:none}
  #sheet{left:50%;right:auto;bottom:auto;top:50%;transform:translate(-50%,-50%) scale(.96);width:min(560px,94vw);max-height:88vh;border-radius:16px;visibility:hidden}
  #sheet.show{transform:translate(-50%,-50%) scale(1)}
  .sh-grab{display:none}
}
</style></head><body>

<header class="topbar">
  <button class="iconbtn" id="menuBtn" title="&#x83DC;&#x5355;">&#x2630;</button>
  <div class="brand" id="brand"><span class="logo">&#x2601;&#xFE0F;</span><span class="bname">COS &#x7F51;&#x76D8;</span></div>
  <div class="searchwrap"><span class="sic">&#x1F50D;</span><input id="search" placeholder="&#x641C;&#x7D22;..." autocomplete="off"></div>
  <div class="headbtns">
    <button class="iconbtn" id="refreshBtn" title="&#x5237;&#x65B0;">&#x27F3;</button>
    <button class="iconbtn" id="viewBtn" title="&#x5207;&#x6362;&#x89C6;&#x56FE;">&#x5217;&#x8868;</button>
    <button class="iconbtn" id="themeBtn" title="&#x4E3B;&#x9898;">&#x1F319;</button>
    <button class="iconbtn" id="logoutBtn" title="&#x9000;&#x51FA;">&#x23FB;</button>
  </div>
</header>
<div class="layout">
  <div class="scrim" id="scrim"></div>
  <aside class="sidebar" id="sidebar">
    <div class="sb-brand"><span class="logo">&#x2601;&#xFE0F;</span> COS &#x7F51;&#x76D8;</div>
    <nav class="sb-nav">
      <a class="sb-item on" data-nav="home" href="javascript:void(0)"><span class="ic">&#x1F3E0;</span><span>&#x9996;&#x9875;</span></a>
      <a class="sb-item" data-nav="recent" href="javascript:void(0)"><span class="ic">&#x23F3;</span><span>&#x6700;&#x8FD1;</span></a>
      <a class="sb-item" data-nav="fav" href="javascript:void(0)"><span class="ic">&#x2B50;</span><span>&#x6536;&#x85CF;</span></a>
    </nav>
    <div class="sb-foot">&#x53EA;&#x8BFB;&#x6D4F;&#x89C8; &middot; cos-exchange</div>
  </aside>
  <main class="main">
    <nav class="crumbs" id="crumbs"></nav>
    <div class="toolbar">
      <div class="tleft">
        <button class="iconbtn" id="upBtn" title="&#x4E0A;&#x4E00;&#x7EA7;">&#x2191;</button>
        <select id="sort" title="&#x6392;&#x5E8F;">
          <option value="name-asc">&#x540D;&#x79F0; &#x2191;</option>
          <option value="name-desc">&#x540D;&#x79F0; &#x2193;</option>
          <option value="size-desc" selected>&#x5927;&#x5C0F; &#x2193;</option>
          <option value="size-asc">&#x5927;&#x5C0F; &#x2191;</option>
          <option value="time-desc">&#x4FEE;&#x6539;&#x65F6;&#x95F4; &#x2193;</option>
          <option value="time-asc">&#x4FEE;&#x6539;&#x65F6;&#x95F4; &#x2191;</option>
        </select>
      </div>
      <div class="chips" id="chips">
        <span class="chip on" data-f="all">&#x5168;&#x90E8;</span>
        <span class="chip" data-f="img">&#x56FE;&#x7247;</span>
        <span class="chip" data-f="vid">&#x89C6;&#x9891;</span>
        <span class="chip" data-f="aud">&#x97F3;&#x9891;</span>
        <span class="chip" data-f="doc">&#x6587;&#x6863;</span>
        <span class="chip" data-f="arc">&#x538B;&#x7F29;</span>
        <span class="chip" data-f="oth">&#x5176;&#x4ED6;</span>
      </div>
    </div>
    <div id="filelist"></div>
  </main>
</div>
<div id="lightbox">
  <div class="lb-top"><span class="lb-cap" id="lbCap"></span><button class="lb-btn" id="lbClose">&#x2715;</button></div>
  <button class="lb-btn lb-nav lb-prev" id="lbPrev">&#x2039;</button>
  <img id="lbImg" alt="">
  <button class="lb-btn lb-nav lb-next" id="lbNext">&#x203A;</button>
</div>
<div id="sheet">
  <div class="sh-grab"></div>
  <div class="sh-head"><span class="sh-title" id="shTitle"></span><button class="iconbtn" id="shClose">&#x2715;</button></div>
  <div class="sh-body">
    <div class="preview" id="shPreview"></div>
    <div class="sh-meta" id="shMeta"></div>
  </div>
  <div class="sh-actions">
    <button class="btn" id="shFavBtn">&#x2606; &#x6536;&#x85CF;</button>
    <button class="btn" id="shCopyBtn">&#x1F517; &#x590D;&#x5236;&#x94FE;&#x63A5;</button>
    <button class="btn primary" id="shDlBtn">&#x2B07; &#x4E0B;&#x8F7D;</button>
  </div>
</div>
<div id="toast"></div>
<script>

var $=function(id){return document.getElementById(id);};
var esc=function(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/'/g,'&#39;').replace(/"/g,'&quot;');};
var IMG=['png','jpg','jpeg','gif','webp','bmp','svg','ico','heic','avif','jfif'];
var VID=['mp4','mkv','mov','avi','webm','m4v','wmv','flv','ts','3gp','rmvb'];
var AUD=['mp3','wav','flac','ogg','m4a','aac','opus','ape','amr'];
var DOC=['pdf','doc','docx','xls','xlsx','ppt','pptx','txt','md','csv','json','html','htm','xml','log','ini','yaml','yml'];
var ARC=['zip','rar','7z','tar','gz','bz2','xz','7zip','tgz'];
var TXT=['txt','md','csv','json','log','xml','html','htm','ini','yaml','yml','js','css','ts','sh','bat','conf','cfg','py'];
var icons={
  'jpg':'&#x1F5BC;&#xFE0F;','jpeg':'&#x1F5BC;&#xFE0F;','png':'&#x1F5BC;&#xFE0F;','gif':'&#x1F5BC;&#xFE0F;','webp':'&#x1F5BC;&#xFE0F;','bmp':'&#x1F5BC;&#xFE0F;','svg':'&#x1F5BC;&#xFE0F;','ico':'&#x1F5BC;&#xFE0F;',
  'mp4':'&#x1F3AC;','mkv':'&#x1F3AC;','mov':'&#x1F3AC;','avi':'&#x1F3AC;','webm':'&#x1F3AC;','m4v':'&#x1F3AC;',
  'mp3':'&#x1F3B5;','wav':'&#x1F3B5;','flac':'&#x1F3B5;','ogg':'&#x1F3B5;','m4a':'&#x1F3B5;',
  'pdf':'&#x1F4D5;','doc':'&#x1F4C4;','docx':'&#x1F4C4;','txt':'&#x1F4C3;','md':'&#x1F4C3;','csv':'&#x1F4CA;','xls':'&#x1F4CA;','xlsx':'&#x1F4CA;',
  'ppt':'&#x1F4FD;&#xFE0F;','pptx':'&#x1F4FD;&#xFE0F;','zip':'&#x1F5DC;&#xFE0F;','rar':'&#x1F5DC;&#xFE0F;','7z':'&#x1F5DC;&#xFE0F;','tar':'&#x1F5DC;&#xFE0F;','gz':'&#x1F5DC;&#xFE0F;','tgz':'&#x1F5DC;&#xFE0F;',
  'exe':'&#x2699;&#xFE0F;','apk':'&#x1F4F1;','html':'&#x1F310;','htm':'&#x1F310;','folder':'&#x1F4C1;'
};
var ext=function(n){return (n.split('.').pop()||'').toLowerCase();};
var iconOf=function(n){return icons[ext(n)]||'&#x1F4E6;';};
var fmt=function(s){s=s||0;if(s<1024){return s+' B';}if(s<1048576){return (s/1024).toFixed(1)+' KB';}if(s<1073741824){return (s/1048576).toFixed(1)+' MB';}return (s/1073741824).toFixed(2)+' GB';};
var fmtT=function(t){if(!t){return '';}var d=new Date(t);if(isNaN(d.getTime())){return '';}var p=function(n){return String(n).padStart(2,'0');};return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes());};
var urlOf=function(k){return '/browse/api/file?key='+encodeURIComponent(k);};
var typeOf=function(n){var e=ext(n);if(IMG.indexOf(e)>=0){return 'img';}if(VID.indexOf(e)>=0){return 'vid';}if(AUD.indexOf(e)>=0){return 'aud';}if(DOC.indexOf(e)>=0){return 'doc';}if(ARC.indexOf(e)>=0){return 'arc';}return 'oth';};
var typeLabel={'img':'\\u56FE\\u7247','vid':'\\u89C6\\u9891','aud':'\\u97F3\\u9891','doc':'\\u6587\\u6863','arc':'\\u538B\\u7F29','oth':'\\u5176\\u4ED6'};
var prefix='';
var token='';
var truncated=false;
var filter='all';
var keyword='';
var sortVal='size-desc';
var view='grid';
var page='home';
var allData=null;
var folders=[];
var files=[];
var activeItems=[];
var imgs=[];
var imgIdx=0;
var curItem=null;
var favs=loadArray('browse_fav');
var recents=loadArray('browse_recent');
function loadArray(k){try{var v=JSON.parse(localStorage.getItem(k)||'[]');return v instanceof Array?v:[];}catch(e){return [];}}
function applyFilter(list){
  if(filter!=='all'){list=list.filter(function(o){return o.type===filter;});}
  if(keyword){var kw=keyword.toLowerCase();list=list.filter(function(o){return o.name.toLowerCase().indexOf(kw)>=0;});}
  return list;
}
function sortList(list){
  var p=sortVal.split('-'),field=p[0],dir=p[1],mul=dir==='asc'?1:-1;
  list.sort(function(a,b){
    if(field==='size'){return (a.size-b.size)*mul;}
    if(field==='time'){return (a.mtime<b.mtime?-1:(a.mtime>b.mtime?1:0))*mul;}
    return a.name.localeCompare(b.name)*mul;
  });
  return list;
}
function norm(f){
  var n=f.key.split('/').pop();
  return {key:f.key,name:n,size:f.size||0,mtime:f.mtime||'',type:typeOf(n)};
}
function findItem(key){
  for(var i=0;i<activeItems.length;i++){if(activeItems[i].key===key){return activeItems[i];}}
  return null;
}

function load(reset){
  if(page!=='home'){renderLocal();return;}
  if(reset){token='';truncated=false;}
  var box=$('filelist');
  var q=new URLSearchParams({prefix:prefix});
  if(token){q.set('token',token);}
  box.className='';
  box.innerHTML='<div class="status"><span class="s-ic">&#x23F3;</span>\\u52A0\\u8F7D\\u4E2D...</div>';
  var ctrl=new AbortController();
  var timer=setTimeout(function(){ctrl.abort();},15000);
  fetch('/browse/api/list?'+q.toString(),{signal:ctrl.signal})
  .then(function(res){
    if(res.status===429){
      box.innerHTML='<div class="status"><span class="s-ic">&#x23F3;</span>\\u8BF7\\u6C42\\u8FC7\\u4E8E\\u9891\\u7E41(429)\\uFF0C\\u7A0D\\u540E\\u81EA\\u52A8\\u91CD\\u8BD5...</div>';
      setTimeout(function(){load(reset);},4000);
      return null;
    }
    if(!res.ok){throw new Error('HTTP '+res.status);}
    return res.json();
  })
  .then(function(data){
    if(data===null){return;}
    if(data.error){
      box.innerHTML='<div class="status"><span class="s-ic">&#x26A0;</span>\\u52A0\\u8F7D\\u5931\\u8D25: '+esc(data.error)+'</div>';
      return;
    }
    allData=data;
    truncated=!!data.truncated;
    token=data.token||'';
    var nf=data.folders||[];
    var nfiles=data.files||[];
    if(reset){
      folders=nf;
      files=nfiles;
    }else{
      var seenF={},m=[];
      var both=folders.concat(nf);
      for(var i=0;i<both.length;i++){if(!seenF[both[i]]){seenF[both[i]]=1;m.push(both[i]);}}
      folders=m;
      var seenK={},fm=[];
      var fb=files.concat(nfiles);
      for(var j=0;j<fb.length;j++){var k=fb[j].key;if(!seenK[k]){seenK[k]=1;fm.push(fb[j]);}}
      files=fm;
    }
    render();
  })
  .catch(function(e){
    if(ctrl.signal.aborted){
      box.innerHTML='<div class="status"><span class="s-ic">&#x26A0;</span>\\u52A0\\u8F7D\\u8D85\\u65F6\\uFF0C\\u8BF7\\u91CD\\u8BD5</div>';
    }else{
      box.innerHTML='<div class="status"><span class="s-ic">&#x26A0;</span>\\u52A0\\u8F7D\\u5931\\u8D25: '+esc(String((e&&e.message)||e))+'</div>';
    }
  })
  .then(function(){clearTimeout(timer);});
}
function render(){
  if(page==='home'){renderHome();}else{renderLocal();}
}
function renderHome(){
  var list=sortList(applyFilter(files.map(norm)));
  activeItems=list;
  imgs=list.filter(function(o){return o.type==='img';});
  var box=$('filelist');
  var html='';
  if(view==='grid'){
    box.className='grid';
    html=gridHtml(folders,list);
    if(!html&&!(allData&&allData.raw)){html='<div class="status"><span class="s-ic">&#x1F4C1;</span>\\uFF08\\u7A7A\\u76EE\\u5F55\\uFF09</div>';}
  }else{
    box.className='';
    html='<div class="tblwrap">'+tableHtml(folders,list)+'</div>';
    if(!list.length&&!folders.length){html='<div class="status"><span class="s-ic">&#x1F4C1;</span>\\uFF08\\u7A7A\\u76EE\\u5F55\\uFF09</div>';}
  }
  if(truncated){html+='<button id="loadmore">\\u52A0\\u8F7D\\u66F4\\u591A</button>';}
  box.innerHTML=html;
  lazyBind(box);
  bindBox(box);
  renderCrumbs();
}
function renderLocal(){
  var src=(page==='recent')?recents:favs;
  var list=sortList(applyFilter(src.slice()));
  activeItems=list;
  imgs=list.filter(function(o){return o.type==='img';});
  var box=$('filelist');
  var label=(page==='recent')?'\\u6682\\u65E0\\u6700\\u8FD1\\u6D4F\\u89C8\\u8BB0\\u5F55':'\\u6682\\u65E0\\u6536\\u85CF\\u6587\\u4EF6';
  var ic=(page==='recent')?'&#x23F3;':'&#x2B50;';
  if(!list.length){
    box.className='';
    box.innerHTML='<div class="status"><span class="s-ic">'+ic+'</span>'+label+'</div>';
  }else if(view==='grid'){
    box.className='grid';
    box.innerHTML=gridHtml([],list);
  }else{
    box.className='';
    box.innerHTML='<div class="tblwrap">'+tableHtml([],list)+'</div>';
  }
  lazyBind(box);
  bindBox(box);
  renderCrumbs();
}
function gridHtml(folders,list){
  var h='';
  for(var i=0;i<folders.length;i++){
    var f=folders[i];
    var nm=f.slice(0,-1).split('/').pop();
    h+='<div class="item" data-act="open" data-key="'+esc(f)+'">'
      +'<div class="it-ic"><span>'+icons.folder+'</span></div>'
      +'<div class="it-name">'+esc(nm)+'</div>'
      +'<div class="it-meta">\\u6587\\u4EF6\\u5939</div></div>';
  }
  for(var j=0;j<list.length;j++){
    var o=list[j];
    var ic=(o.type==='img')
      ?'<img class="it-img" loading="lazy" data-src="'+urlOf(o.key)+'" decoding="async" alt="">'
      :'<span>'+iconOf(o.name)+'</span>';
    h+='<div class="item" data-act="file" data-key="'+esc(o.key)+'">'
      +'<button class="it-more" data-more="'+esc(o.key)+'" title="\\u66F4\\u591A">&#x22EF;</button>'
      +'<div class="it-ic">'+ic+'</div>'
      +'<div class="it-name">'+esc(o.name)+'</div>'
      +'<div class="it-meta">'+fmt(o.size)+' &#xB7; '+esc(fmtT(o.mtime))+'</div></div>';
  }
  return h;
}
function tableHtml(folders,list){
  var h='<table class="tbl"><thead><tr>'
    +'<th data-s="name">\\u540D\\u79F0</th><th data-s="size">\\u5927\\u5C0F</th><th data-s="time">\\u4FEE\\u6539\\u65F6\\u95F4</th><th>\\u7C7B\\u578B</th><th></th>'
    +'</tr></thead><tbody>';
  for(var i=0;i<folders.length;i++){
    var f=folders[i],nm=f.slice(0,-1).split('/').pop();
    h+='<tr class="trow" data-act="open" data-key="'+esc(f)+'">'
      +'<td class="c-name"><span class="ic">'+icons.folder+'</span><span class="nm">'+esc(nm)+'</span></td>'
      +'<td class="td-size">&#x2014;</td><td class="td-time">&#x2014;</td><td>\\u6587\\u4EF6\\u5939</td><td class="td-more">&#x22EF;</td></tr>';
  }
  for(var j=0;j<list.length;j++){
    var o=list[j];
    h+='<tr class="trow" data-act="file" data-key="'+esc(o.key)+'">'
      +'<td class="c-name"><span class="ic">'+iconOf(o.name)+'</span><span class="nm">'+esc(o.name)+'</span></td>'
      +'<td class="td-size">'+fmt(o.size)+'</td><td class="td-time">'+esc(fmtT(o.mtime))+'</td>'
      +'<td>'+typeLabel[o.type]+'</td><td class="td-more">&#x22EF;</td></tr>';
  }
  h+='</tbody></table>';
  return h;
}

function bindBox(box){
  box.onclick=function(e){
    var th=e.target.closest('th[data-s]');
    if(th){sortKey(th.getAttribute('data-s'));return;}
    var m=e.target.closest('[data-more]');
    if(m){e.stopPropagation();var mk=m.getAttribute('data-more');var mo=findItem(mk);if(mo){openDetail(mo);}return;}
    var it=e.target.closest('.item,.trow');
    if(!it){return;}
    var key=it.getAttribute('data-key')||'';
    if(it.getAttribute('data-act')==='open'){open(key);return;}
    var o=findItem(key);
    if(!o){return;}
    if(o.type==='img'){showLightbox(key);}else{openDetail(o);}
  };
  var lm=document.getElementById('loadmore');
  if(lm){lm.onclick=function(){load(false);};}
}
function sortKey(field){
  if(sortVal===field+'-asc'){sortVal=field+'-desc';}
  else if(sortVal===field+'-desc'){sortVal=field+'-asc';}
  else{sortVal=field+'-desc';}
  $('sort').value=sortVal;
  render();
}
function go(p){
  page='home';
  prefix=p;
  closeSidebar();
  load(true);
  window.scrollTo(0,0);
}
function up(){
  if(page!=='home'){return;}
  var parts=prefix.split('/').filter(Boolean);
  parts.pop();
  prefix=parts.length?parts.join('/')+'/':'';
  load(true);
  window.scrollTo(0,0);
}
function open(p){go(p);}
function renderCrumbs(){
  var c=$('crumbs');
  var html='';
  if(page!=='home'){
    html='<span class="crumb last">'+(page==='recent'?'\\u6700\\u8FD1':'\\u6536\\u85CF')+'</span>';
    c.innerHTML=html;
    c.onclick=null;
    return;
  }
  var parts=prefix.split('/').filter(Boolean);
  html='<span class="crumb" data-cr="">\\u9996\\u9875</span>';
  var acc='';
  for(var i=0;i<parts.length;i++){
    acc+=parts[i]+'/';
    var cls=(i===parts.length-1)?'crumb last':'crumb';
    html+='<span class="csep">/</span><span class="'+cls+'" data-cr="'+esc(acc)+'">'+esc(parts[i])+'</span>';
  }
  c.innerHTML=html;
  c.onclick=function(e){
    var cr=e.target.closest('.crumb');
    if(!cr||cr.classList.contains('last')){return;}
    go(cr.getAttribute('data-cr')||'');
  };
}
function showLightbox(key){
  if(!imgs.length){return;}
  var idx=-1;
  for(var i=0;i<imgs.length;i++){if(imgs[i].key===key){idx=i;break;}}
  imgIdx=idx>=0?idx:0;
  $('lightbox').classList.add('show');
  lbShow();
  recordRecent(imgs[imgIdx]);
}
function lbShow(){
  var o=imgs[imgIdx];
  if(!o){return;}
  $('lbImg').src=urlOf(o.key);
  $('lbCap').textContent=(imgIdx+1)+'/'+imgs.length+'  '+o.name;
}
function closeLb(){$('lightbox').classList.remove('show');$('lbImg').src='';}
function openDetail(o){
  curItem=o;
  recordRecent(o);
  $('shTitle').textContent=o.name;
  $('shMeta').innerHTML='<b>\\u5927\\u5C0F</b>'+fmt(o.size)+'<br><b>\\u4FEE\\u6539\\u65F6\\u95F4</b>'+esc(fmtT(o.mtime))+'<br><b>\\u7C7B\\u578B</b>'+typeLabel[o.type]+'<br><b>\\u8DEF\\u5F84</b>'+esc(o.key);
  var pv=$('shPreview');
  var e=ext(o.name),t=o.type;
  if(t==='vid'){
    pv.innerHTML='<video controls autoplay src="'+urlOf(o.key)+'"></video>';
  }else if(t==='aud'){
    pv.innerHTML='<audio controls src="'+urlOf(o.key)+'"></audio>';
  }else if(e==='pdf'){
    pv.innerHTML='<iframe src="'+urlOf(o.key)+'"></iframe>';
  }else if(TXT.indexOf(e)>=0){
    pv.innerHTML='<div class="ph"><span class="big">&#x1F4C3;</span>\\u52A0\\u8F7D\\u4E2D...</div>';
    fetchText(o.key,pv);
  }else if(t==='img'){
    pv.innerHTML='<img src="'+urlOf(o.key)+'" alt="">';
  }else{
    pv.innerHTML='<div class="ph"><span class="big">'+iconOf(o.name)+'</span>\\u8BE5\\u7C7B\\u578B\\u6682\\u4E0D\\u652F\\u6301\\u5728\\u7EBF\\u9884\\u89C8\\uFF0C\\u53EF\\u4E0B\\u8F7D\\u67E5\\u770B</div>';
  }
  var fav=isFav(o.key);
  $('shFavBtn').innerHTML=fav?'&#x2B50; \\u5DF2\\u6536\\u85CF':'&#x2606; \\u6536\\u85CF';
  $('shFavBtn').classList.toggle('primary',fav);
  $('sheet').classList.add('show');
}
function fetchText(key,pv){
  fetch(urlOf(key)).then(function(r){
    if(!r.ok){throw new Error('HTTP '+r.status);}
    return r.text();
  }).then(function(t){
    pv.innerHTML='<pre>'+esc(t.slice(0,200000))+'</pre>';
  }).catch(function(){
    pv.innerHTML='<div class="ph"><span class="big">&#x26A0;</span>\\u6587\\u672C\\u52A0\\u8F7D\\u5931\\u8D25</div>';
  });
}
function saveFav(){try{localStorage.setItem('browse_fav',JSON.stringify(favs));}catch(e){}}
function isFav(key){for(var i=0;i<favs.length;i++){if(favs[i].key===key){return true;}}return false;}
function addFav(o){favs=favs.filter(function(x){return x.key!==o.key;});favs.unshift(o);saveFav();}
function removeFav(key){favs=favs.filter(function(x){return x.key!==key;});saveFav();}
function recordRecent(o){
  recents=recents.filter(function(x){return x.key!==o.key;});
  recents.unshift(o);
  if(recents.length>60){recents=recents.slice(0,60);}
  try{localStorage.setItem('browse_recent',JSON.stringify(recents));}catch(e){}
}

var toastTimer=null;
function toast(msg){
  var t=$('toast');
  t.textContent=msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer=setTimeout(function(){t.classList.remove('show');},1800);
}
var io=null;
if('IntersectionObserver' in window){
  io=new IntersectionObserver(function(entries){
    for(var i=0;i<entries.length;i++){
      var en=entries[i];
      if(en.isIntersecting){
        var im=en.target;
        if(im.dataset.src){im.src=im.dataset.src;im.removeAttribute('data-src');}
        io.unobserve(im);
      }
    }
  },{rootMargin:'500px'});
}
function lazyBind(root){
  var imgs=(root||document).querySelectorAll('img[data-src]');
  for(var i=0;i<imgs.length;i++){
    if(io){io.observe(imgs[i]);}else{imgs[i].src=imgs[i].dataset.src;imgs[i].removeAttribute('data-src');}
  }
}
var side=$('sidebar');
var scrim=$('scrim');
function closeSidebar(){side.classList.remove('open');scrim.classList.remove('show');}
$('menuBtn').onclick=function(){side.classList.toggle('open');scrim.classList.toggle('show');};
scrim.onclick=closeSidebar;
var navs=document.querySelectorAll('.sb-item');
for(var ni=0;ni<navs.length;ni++){
  navs[ni].addEventListener('click',function(){
    var n=this.getAttribute('data-nav');
    page=n;
    for(var k=0;k<navs.length;k++){navs[k].classList.toggle('on',navs[k]===this);}
    closeSidebar();
    if(n==='home'){load(true);}else{renderLocal();}
    window.scrollTo(0,0);
  });
}
$('brand').onclick=function(){
  page='home';
  for(var k=0;k<navs.length;k++){navs[k].classList.toggle('on',navs[k].getAttribute('data-nav')==='home');}
  load(true);
};
$('refreshBtn').onclick=function(){load(true);};
$('viewBtn').onclick=function(){
  view=view==='grid'?'table':'grid';
  try{localStorage.setItem('browseView',view);}catch(e){}
  $('viewBtn').innerHTML=view==='grid'?'&#x5217;&#x8868;':'&#x5361;&#x7247;';
  render();
};
$('themeBtn').onclick=function(){
  document.body.classList.toggle('dark');
  try{localStorage.setItem('browseDark',document.body.classList.contains('dark')?'1':'0');}catch(e){}
  $('themeBtn').innerHTML=document.body.classList.contains('dark')?'&#x2600;&#xFE0F;':'&#x1F319;';
};
$('logoutBtn').onclick=function(){
  document.cookie='browse_pwd=;Path=/;Max-Age=0;';
  window.location.href='/browse';
};
$('upBtn').onclick=function(){if(page==='home'){up();}};
$('search').addEventListener('input',function(e){keyword=e.target.value;render();});
$('sort').addEventListener('change',function(){sortVal=this.value;render();});
$('chips').addEventListener('click',function(e){
  var c=e.target.closest('.chip');
  if(!c){return;}
  filter=c.getAttribute('data-f');
  var cs=document.querySelectorAll('.chip');
  for(var i=0;i<cs.length;i++){cs[i].classList.toggle('on',cs[i]===c);}
  render();
});
$('shClose').onclick=function(){$('sheet').classList.remove('show');};
$('sheet').onclick=function(e){if(e.target===$('sheet')){$('sheet').classList.remove('show');}};
$('shDlBtn').onclick=function(){if(curItem){recordRecent(curItem);window.location.href=urlOf(curItem.key);}};
$('shFavBtn').onclick=function(){
  if(!curItem){return;}
  if(isFav(curItem.key)){
    removeFav(curItem.key);
    $('shFavBtn').innerHTML='&#x2606; \\u6536\\u85CF';
    $('shFavBtn').classList.remove('primary');
    toast('\\u5DF2\\u53D6\\u6D88\\u6536\\u85CF');
  }else{
    addFav(curItem);
    $('shFavBtn').innerHTML='&#x2B50; \\u5DF2\\u6536\\u85CF';
    $('shFavBtn').classList.add('primary');
    toast('\\u5DF2\\u52A0\\u5165\\u6536\\u85CF');
  }
};
$('shCopyBtn').onclick=function(){
  if(!curItem){return;}
  var url=location.origin+urlOf(curItem.key);
  var done=function(){toast('\\u94FE\\u63A5\\u5DF2\\u590D\\u5236');};
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(url).then(done,function(){fallbackCopy(url);done();});
  }else{fallbackCopy(url);done();}
};
function fallbackCopy(t){
  var ta=document.createElement('textarea');
  ta.value=t;
  ta.style.position='fixed';
  ta.style.opacity='0';
  document.body.appendChild(ta);
  ta.select();
  try{document.execCommand('copy');}catch(e){}
  document.body.removeChild(ta);
}
$('lbPrev').onclick=function(){imgIdx=(imgIdx-1+imgs.length)%imgs.length;lbShow();};
$('lbNext').onclick=function(){imgIdx=(imgIdx+1)%imgs.length;lbShow();};
$('lbClose').onclick=closeLb;
$('lightbox').onclick=function(e){if(e.target===$('lightbox')){closeLb();}};
var tx=0,ty=0;
$('lightbox').addEventListener('touchstart',function(e){tx=e.touches[0].clientX;ty=e.touches[0].clientY;});
$('lightbox').addEventListener('touchend',function(e){
  var dx=e.changedTouches[0].clientX-tx;
  var dy=e.changedTouches[0].clientY-ty;
  if(Math.abs(dx)>50&&Math.abs(dx)>Math.abs(dy)){
    if(dx<0){imgIdx=(imgIdx+1)%imgs.length;}else{imgIdx=(imgIdx-1+imgs.length)%imgs.length;}
    lbShow();
  }
});
document.addEventListener('keydown',function(e){
  if(e.key==='Escape'){closeLb();$('sheet').classList.remove('show');}
  else if(e.key==='ArrowLeft'&&$('lightbox').classList.contains('show')){imgIdx=(imgIdx-1+imgs.length)%imgs.length;lbShow();}
  else if(e.key==='ArrowRight'&&$('lightbox').classList.contains('show')){imgIdx=(imgIdx+1)%imgs.length;lbShow();}
});
try{
  if(localStorage.getItem('browseDark')==='1'){document.body.classList.add('dark');$('themeBtn').innerHTML='&#x2600;&#xFE0F;';}
  view=localStorage.getItem('browseView')||'grid';
}catch(e){}
if(view==='table'){$('viewBtn').innerHTML='&#x5361;&#x7247;';}
load(true);
</script>
</body></html>`;
}
