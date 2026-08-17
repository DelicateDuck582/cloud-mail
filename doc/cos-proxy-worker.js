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
        // 防自杀式重定向：若本代码被误部署到跳转目标域名（如 mail.duckgame-play.top），
        // 302 到自身会无限循环（ERR_TOO_MANY_REDIRECTS）。命中即 200 兜底，不跳转。
        try {
          if (url.hostname === new URL(REDIRECT_TARGET).hostname) {
            return new Response('OK', { status: 200 });
          }
        } catch (e) {}
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
  // 注意：ATT_SIGN_MAX_TTL 若被配成非数字（如粘贴错值），Number() 得 NaN，
  // NaN 参与比较恒为 false → TTL 限制会整体失效（超长签名被放行）。必须兜底回默认值。
  let maxTtl = Number(env.ATT_SIGN_MAX_TTL || 3600);
  if (!Number.isFinite(maxTtl) || maxTtl <= 0) maxTtl = 3600;
  maxTtl = Math.max(60, Math.min(maxTtl, 86400));
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
  // 退出登录：browse_pwd 是 HttpOnly cookie，前端 JS 的 document.cookie 无法删除它，
  // 必须由服务端 Set-Cookie 清除（服务端可以删 HttpOnly）。放在密码门控之前，
  // 保证已登录用户一定能退出；未登录访问也无害（只是删一个不存在的 cookie）。
  if (url.pathname === '/browse/logout') {
    return new Response('', {
      status: 302,
      headers: {
        Location: '/browse',
        'Set-Cookie': 'browse_pwd=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly; Secure',
      },
    });
  }
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  // 密码门控：未配置 BROWSE_PASS 时直接拒绝，防止误配导致整桶裸奔
  if (!env.BROWSE_PASS || !(await browseAuthed(request, env.BROWSE_PASS))) {
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
      // prefix/token 限制长度：防超长参数滥用（COS 对超长 prefix 会 400，限流兜底）
      const prefix = (url.searchParams.get('prefix') || '').slice(0, 1024);
      const token = (url.searchParams.get('token') || '').slice(0, 2048);
      // per_page：每页条数（前端 30/60/100），限制 1~200，非法值回退 100
      let perPage = parseInt(url.searchParams.get('per_page') || '', 10);
      if (!Number.isFinite(perPage) || perPage < 1) perPage = 100;
      if (perPage > 200) perPage = 200;
      const data = await browseList(env, prefix, token, perPage);
      return new Response(JSON.stringify(data), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff' },
      });
    } catch (e) {
      // 只把 error 字段回给前端：browseList 的 throw 里带 ourSTS/cosSTS/sentUrl 等排错字段，
      // 原样返回会泄露 COS 桶域名与签名中间值；调试细节只在服务端日志
      console.error('browse list error:', e);
      const msg = String((e && e.message) || e);
      let errMsg = msg;
      try {
        const parsed = JSON.parse(msg);
        if (parsed && parsed.error) errMsg = parsed.error;
      } catch (e2) {}
      return new Response(JSON.stringify({ error: errMsg.slice(0, 500) }), {
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
    // 路径穿越拦截：绝对路径(/开头) / 反斜杠 / ../
    // （对象存储无目录上溯，但拦截这些字符可避免奇怪的 key 与回源 URL 歧义）
    if (!key || key.startsWith('/') || key.includes('\\') || key.includes('../')) {
      return new Response('bad key', { status: 400 });
    }
    try {
      // 透传 Range 头：视频/音频播放器靠 Range 流式分段下载 + seek，
      // 没有它浏览器只能全量下载完才能播，表现为"等待很久才开始"
      const range = request.headers.get('Range') || '';
      return await browseFetchFile(env, key, ctx, request.method, range);
    } catch (e) {
      console.error('browse file error:', e);
      return new Response('fetch failed', { status: 500 });
    }
  }

  return new Response('Not Found', { status: 404 });
}

async function browseAuthed(request, pass) {
  const fingerprint = await browseFingerprint(pass);
  const cookies = (request.headers.get('Cookie') || '').split(';');
  for (const c of cookies) {
    const [k, v] = c.trim().split('=');
    if (k === 'browse_pwd' && v === fingerprint) {
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
    const fp = await browseFingerprint(env.BROWSE_PASS);
    return new Response('', {
      status: 302,
      headers: {
        Location: '/browse',
        'Set-Cookie': `browse_pwd=${fp}; Path=/; Max-Age=604800; SameSite=Lax; HttpOnly; Secure`,
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

// cookie 校验用 HMAC-SHA256 指纹。
// 原 FNV-1a 32 位可碰撞、可用字典反推密码；HMAC-SHA256 输出 256 位，不可碰撞、
// 单向不可逆（对强密码无法反推）。密钥为独立常量（非 BROWSE_PASS 本身），
// 同一密码只产生唯一指纹，无法通过 cookie 值关联/推导其它信息。
// BROWSE_PASS 在 Worker 实例生命周期内不变，缓存指纹避免每次请求重复 importKey。
let fpCachePass = '';
let fpCacheVal = '';
async function browseFingerprint(pass) {
  if (fpCachePass === pass && fpCacheVal) return fpCacheVal;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode('cos-browse-cookie-fp-v2'),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(pass));
  fpCachePass = pass;
  fpCacheVal = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  return fpCacheVal;
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
// 定期清理过期的失败记录，防止攻击者用海量不同 IP 把 Map 撑爆
function loginFailGC(now) {
  if (loginFailMap.size < 10000) return;
  for (const [k, v] of loginFailMap) {
    if (now - v.t > 600000) loginFailMap.delete(k);
  }
  if (loginFailMap.size > 20000) loginFailMap.clear();
}
function loginBlocked(ip) {
  const now = Date.now();
  loginFailGC(now);
  const rec = loginFailMap.get(ip);
  return !!(rec && now - rec.t < 600000 && rec.c >= 5);
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

// 列目录：GET ?list-type=2&delimiter=/&prefix=...&continuation-token=...&max-keys=...
async function browseList(env, prefix, token, perPage) {
  // 与附件主流程一致：密钥/地域/endpoint 必须 trim（粘贴进 CF 的环境变量常带尾随空格/换行）
  const host = new URL((env.S3_ENDPOINT || '').trim()).host;
  const region = (env.REGION || '').trim();
  const ak = (env.AWS_ACCESS_KEY_ID || '').trim();
  const sk = (env.AWS_SECRET_ACCESS_KEY || '').trim();
  // max-keys 由前端每页条数（per_page）决定：默认 100，支持 30/60/100 分页器，
  // 避免一次拉回上千条导致页面渲染卡顿、响应过大
  if (!Number.isFinite(perPage) || perPage < 1) perPage = 100;
  if (perPage > 200) perPage = 200;
  const params = { 'list-type': '2', 'encoding-type': 'url', delimiter: '/', 'max-keys': String(perPage) };
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
async function browseFetchFile(env, key, ctx, method, range) {
  method = method || 'GET';
  range = range || '';
  const rawEndpoint = (env.S3_ENDPOINT || '').trim().replace(/\/+$/, '');
  const region = (env.REGION || '').trim();
  const ak = (env.AWS_ACCESS_KEY_ID || '').trim();
  const sk = (env.AWS_SECRET_ACCESS_KEY || '').trim();
  const encodedPath = '/' + key.split('/').map(enc).join('/');
  const targetUrl = new URL(encodedPath, rawEndpoint);

  // Cache API 按 key 缓存（缩略图/预览会反复请求同一文件，7 天内只回源一次）。
  // Range 请求（视频/音频流式播放、拖动 seek）跳过缓存：Cache API 不支持 206/Range，
  // 且大视频不适合 Worker Cache。直接回源透传 Range，浏览器按段下载，首帧更快。
  const isRange = range !== '';
  const cacheKey = new Request('https://' + new URL(rawEndpoint).host + '/_browse/' + encodedPath);
  if (!isRange) {
    const cached = await caches.default.match(cacheKey);
    if (cached) return cached;
  }

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
  if (range) headersForFetch['Range'] = range;

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
  // 只对 GET 写缓存：HEAD 无 body、Range 的 206 分段都不写入（否则污染同 key 的
  // 完整 GET 缓存；视频等大文件也不适合 Worker Cache，交给 COS 回源）
  if (final.ok && method === 'GET' && !isRange) {
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


// =====================================================================
// 【文件浏览器】/browse —— Alist 风格个人只读网盘页面（登录页 + 主界面）
// ---------------------------------------------------------------------
// 参照 Alist 前端（AlistGo/alist-web，SolidJS + HopeUI）的设计语言重制：
//   - 主色 #1890ff（getMainColor 默认值），页面背景 #f7f8fa，hover 底色
//     rgba(132,133,141,0.18)，内容容器 min(99%, 980px)，字体栈与 Alist 一致；
//   - 文件列表放在白色圆角卡片内（Obj 卡片风格，rounded 12px + 阴影）；
//   - 网格卡片悬停 scale(1.05) + hover 底色，图标为主色单色 SVG；
//   - 列表三列（名称 / 大小 / 修改时间），移动端隐藏修改时间列；
//   - 文件大小格式同 Alist getFileSize（1.02K / 1.00M / 2.00G），
//     时间格式 YYYY-MM-DD HH:MM:SS。
// 实现方式：本文件由 _parts/ 分块拼接（_build-pages.mjs），再由
// _build-browse.mjs 合并进 cos-proxy-worker.js（原附件代理/签名/浏览后端
// 逻辑保持逐字节不变）。中文/emoji 由构建器转成 <script> 内 \uXXXX、
// 其余 HTML 实体，保证 served 页面纯 ASCII。手写模板时不要引入反引号
// 与 ${}（页面内声明的插值除外），也不要在内联 JS 里写反斜杠正则。
// =====================================================================

// =====================================================================
// 【文件浏览器】/browse —— Alist 风格个人只读网盘页面（登录页 + 主界面）
// ---------------------------------------------------------------------
// 参照 Alist 前端（AlistGo/alist-web，SolidJS + HopeUI）的设计语言重制：
//   - 主色 #1890ff（getMainColor 默认值），页面背景 #f7f8fa，hover 底色
//     rgba(132,133,141,0.18)，内容容器 min(99%, 980px)，字体栈与 Alist 一致；
//   - 文件列表放在白色圆角卡片内（Obj 卡片风格，rounded 12px + 阴影）；
//   - 网格卡片悬停 scale(1.05) + hover 底色，图标为主色单色 SVG；
//   - 列表三列（名称 / 大小 / 修改时间），移动端隐藏修改时间列；
//   - 文件大小格式同 Alist getFileSize（1.02K / 1.00M / 2.00G），
//     时间格式 YYYY-MM-DD HH:MM:SS。
// 实现方式：本文件由 _parts/ 分块拼接（_build-pages.mjs），再由
// _build-browse.mjs 合并进 cos-proxy-worker.js（原附件代理/签名/浏览后端
// 逻辑保持逐字节不变）。中文/emoji 由构建器转成 <script> 内 \uXXXX、
// 其余 HTML 实体，保证 served 页面纯 ASCII。手写模板时不要引入反引号
// 与 ${}（页面内声明的插值除外），也不要在内联 JS 里写反斜杠正则。
// =====================================================================

// =====================================================================
// 【文件浏览器】/browse —— Alist 风格个人只读网盘页面（登录页 + 主界面）
// ---------------------------------------------------------------------
// 参照 Alist 前端（AlistGo/alist-web，SolidJS + HopeUI）的设计语言重制：
//   - 主色 #1890ff（getMainColor 默认值），页面背景 #f7f8fa，hover 底色
//     rgba(132,133,141,0.18)，内容容器 min(99%, 980px)，字体栈与 Alist 一致；
//   - 文件列表放在白色圆角卡片内（Obj 卡片风格，rounded 12px + 阴影）；
//   - 网格卡片悬停 scale(1.05) + hover 底色，图标为主色单色 SVG；
//   - 列表三列（名称 / 大小 / 修改时间），移动端隐藏修改时间列；
//   - 文件大小格式同 Alist getFileSize（1.02K / 1.00M / 2.00G），
//     时间格式 YYYY-MM-DD HH:MM:SS。
// 实现方式：本文件由 _parts/ 分块拼接（_build-pages.mjs），再由
// _build-browse.mjs 合并进 cos-proxy-worker.js（原附件代理/签名/浏览后端
// 逻辑保持逐字节不变）。中文/emoji 由构建器转成 <script> 内 \uXXXX、
// 其余 HTML 实体，保证 served 页面纯 ASCII。手写模板时不要引入反引号
// 与 ${}（页面内声明的插值除外），也不要在内联 JS 里写反斜杠正则。
// =====================================================================

// =====================================================================
// 【文件浏览器】/browse —— Alist 风格个人只读网盘页面（登录页 + 主界面）
// ---------------------------------------------------------------------
// 参照 Alist 前端（AlistGo/alist-web，SolidJS + HopeUI）的设计语言重制：
//   - 主色 #1890ff（getMainColor 默认值），页面背景 #f7f8fa，hover 底色
//     rgba(132,133,141,0.18)，内容容器 min(99%, 980px)，字体栈与 Alist 一致；
//   - 文件列表放在白色圆角卡片内（Obj 卡片风格，rounded 12px + 阴影）；
//   - 网格卡片悬停 scale(1.05) + hover 底色，图标为主色单色 SVG；
//   - 列表三列（名称 / 大小 / 修改时间），移动端隐藏修改时间列；
//   - 文件大小格式同 Alist getFileSize（1.02K / 1.00M / 2.00G），
//     时间格式 YYYY-MM-DD HH:MM:SS。
// 实现方式：本文件由 _parts/ 分块拼接（_build-pages.mjs），再由
// _build-browse.mjs 合并进 cos-proxy-worker.js（原附件代理/签名/浏览后端
// 逻辑保持逐字节不变）。中文/emoji 由构建器转成 <script> 内 \uXXXX、
// 其余 HTML 实体，保证 served 页面纯 ASCII。手写模板时不要引入反引号
// 与 ${}（页面内声明的插值除外），也不要在内联 JS 里写反斜杠正则。
// =====================================================================

// =====================================================================
// 【文件浏览器】/browse —— Alist 风格个人只读网盘页面（登录页 + 主界面）
// ---------------------------------------------------------------------
// 参照 Alist 前端（AlistGo/alist-web，SolidJS + HopeUI）的设计语言重制：
//   - 主色 #1890ff（getMainColor 默认值），页面背景 #f7f8fa，hover 底色
//     rgba(132,133,141,0.18)，内容容器 min(99%, 980px)，字体栈与 Alist 一致；
//   - 文件列表放在白色圆角卡片内（Obj 卡片风格，rounded 12px + 阴影）；
//   - 网格卡片悬停 scale(1.05) + hover 底色，图标为主色单色 SVG；
//   - 列表三列（名称 / 大小 / 修改时间），移动端隐藏修改时间列；
//   - 文件大小格式同 Alist getFileSize（1.02K / 1.00M / 2.00G），
//     时间格式 YYYY-MM-DD HH:MM:SS。
// 实现方式：本文件由 _parts/ 分块拼接（_build-pages.mjs），再由
// _build-browse.mjs 合并进 cos-proxy-worker.js（原附件代理/签名/浏览后端
// 逻辑保持逐字节不变）。中文/emoji 由构建器转成 <script> 内 \uXXXX、
// 其余 HTML 实体，保证 served 页面纯 ASCII。手写模板时不要引入反引号
// 与 ${}（页面内声明的插值除外），也不要在内联 JS 里写反斜杠正则。
// =====================================================================

// =====================================================================
// 【文件浏览器】/browse —— Alist 风格个人只读网盘页面（登录页 + 主界面）
// ---------------------------------------------------------------------
// 参照 Alist 前端（AlistGo/alist-web，SolidJS + HopeUI）的设计语言重制：
//   - 主色 #1890ff（getMainColor 默认值），页面背景 #f7f8fa，hover 底色
//     rgba(132,133,141,0.18)，内容容器 min(99%, 980px)，字体栈与 Alist 一致；
//   - 文件列表放在白色圆角卡片内（Obj 卡片风格，rounded 12px + 阴影）；
//   - 网格卡片悬停 scale(1.05) + hover 底色，图标为主色单色 SVG；
//   - 列表三列（名称 / 大小 / 修改时间），移动端隐藏修改时间列；
//   - 文件大小格式同 Alist getFileSize（1.02K / 1.00M / 2.00G），
//     时间格式 YYYY-MM-DD HH:MM:SS。
// 实现方式：本文件由 _parts/ 分块拼接（_build-pages.mjs），再由
// _build-browse.mjs 合并进 cos-proxy-worker.js（原附件代理/签名/浏览后端
// 逻辑保持逐字节不变）。中文/emoji 由构建器转成 <script> 内 \uXXXX、
// 其余 HTML 实体，保证 served 页面纯 ASCII。手写模板时不要引入反引号
// 与 ${}（页面内声明的插值除外），也不要在内联 JS 里写反斜杠正则。
// =====================================================================

// =====================================================================
// 【文件浏览器】/browse —— Alist 风格个人只读网盘页面（登录页 + 主界面）
// ---------------------------------------------------------------------
// 参照 Alist 前端（AlistGo/alist-web，SolidJS + HopeUI）的设计语言重制：
//   - 主色 #1890ff（getMainColor 默认值），页面背景 #f7f8fa，hover 底色
//     rgba(132,133,141,0.18)，内容容器 min(99%, 980px)，字体栈与 Alist 一致；
//   - 文件列表放在白色圆角卡片内（Obj 卡片风格，rounded 12px + 阴影）；
//   - 网格卡片悬停 scale(1.05) + hover 底色，图标为主色单色 SVG；
//   - 列表三列（名称 / 大小 / 修改时间），移动端隐藏修改时间列；
//   - 文件大小格式同 Alist getFileSize（1.02K / 1.00M / 2.00G），
//     时间格式 YYYY-MM-DD HH:MM:SS。
// 实现方式：本文件由 _parts/ 分块拼接（_build-pages.mjs），再由
// _build-browse.mjs 合并进 cos-proxy-worker.js（原附件代理/签名/浏览后端
// 逻辑保持逐字节不变）。中文/emoji 由构建器转成 <script> 内 \uXXXX、
// 其余 HTML 实体，保证 served 页面纯 ASCII。手写模板时不要引入反引号
// 与 ${}（页面内声明的插值除外），也不要在内联 JS 里写反斜杠正则。
// =====================================================================

// =====================================================================
// 【文件浏览器】/browse —— Alist 风格个人只读网盘页面（登录页 + 主界面）
// ---------------------------------------------------------------------
// 参照 Alist 前端（AlistGo/alist-web，SolidJS + HopeUI）的设计语言重制：
//   - 主色 #1890ff（getMainColor 默认值），页面背景 #f7f8fa，hover 底色
//     rgba(132,133,141,0.18)，内容容器 min(99%, 980px)，字体栈与 Alist 一致；
//   - 文件列表放在白色圆角卡片内（Obj 卡片风格，rounded 12px + 阴影）；
//   - 网格卡片悬停 scale(1.05) + hover 底色，图标为主色单色 SVG；
//   - 列表三列（名称 / 大小 / 修改时间），移动端隐藏修改时间列；
//   - 文件大小格式同 Alist getFileSize（1.02K / 1.00M / 2.00G），
//     时间格式 YYYY-MM-DD HH:MM:SS。
// 实现方式：本文件由 _parts/ 分块拼接（_build-pages.mjs），再由
// _build-browse.mjs 合并进 cos-proxy-worker.js（原附件代理/签名/浏览后端
// 逻辑保持逐字节不变）。中文/emoji 由构建器转成 <script> 内 \uXXXX、
// 其余 HTML 实体，保证 served 页面纯 ASCII。手写模板时不要引入反引号
// 与 ${}（页面内声明的插值除外），也不要在内联 JS 里写反斜杠正则。
// =====================================================================

// =====================================================================
// 【文件浏览器】/browse —— Alist 风格个人只读网盘页面（登录页 + 主界面）
// ---------------------------------------------------------------------
// 参照 Alist 前端（AlistGo/alist-web，SolidJS + HopeUI）的设计语言重制：
//   - 主色 #1890ff（getMainColor 默认值），页面背景 #f7f8fa，hover 底色
//     rgba(132,133,141,0.18)，内容容器 min(99%, 980px)，字体栈与 Alist 一致；
//   - 文件列表放在白色圆角卡片内（Obj 卡片风格，rounded 12px + 阴影）；
//   - 网格卡片悬停 scale(1.05) + hover 底色，图标为主色单色 SVG；
//   - 列表三列（名称 / 大小 / 修改时间），移动端隐藏修改时间列；
//   - 文件大小格式同 Alist getFileSize（1.02K / 1.00M / 2.00G），
//     时间格式 YYYY-MM-DD HH:MM:SS。
// 实现方式：本文件由 _parts/ 分块拼接（_build-pages.mjs），再由
// _build-browse.mjs 合并进 cos-proxy-worker.js（原附件代理/签名/浏览后端
// 逻辑保持逐字节不变）。中文/emoji 由构建器转成 <script> 内 \uXXXX、
// 其余 HTML 实体，保证 served 页面纯 ASCII。手写模板时不要引入反引号
// 与 ${}（页面内声明的插值除外），也不要在内联 JS 里写反斜杠正则。
// =====================================================================

// =====================================================================
// 【文件浏览器】/browse —— Alist 风格个人只读网盘页面（登录页 + 主界面）
// ---------------------------------------------------------------------
// 参照 Alist 前端（AlistGo/alist-web，SolidJS + HopeUI）的设计语言重制：
//   - 主色 #1890ff（getMainColor 默认值），页面背景 #f7f8fa，hover 底色
//     rgba(132,133,141,0.18)，内容容器 min(99%, 980px)，字体栈与 Alist 一致；
//   - 文件列表放在白色圆角卡片内（Obj 卡片风格，rounded 12px + 阴影）；
//   - 网格卡片悬停 scale(1.05) + hover 底色，图标为主色单色 SVG；
//   - 列表三列（名称 / 大小 / 修改时间），移动端隐藏修改时间列；
//   - 文件大小格式同 Alist getFileSize（1.02K / 1.00M / 2.00G），
//     时间格式 YYYY-MM-DD HH:MM:SS。
// 实现方式：本文件由 _parts/ 分块拼接（_build-pages.mjs），再由
// _build-browse.mjs 合并进 cos-proxy-worker.js（原附件代理/签名/浏览后端
// 逻辑保持逐字节不变）。中文/emoji 由构建器转成 <script> 内 \uXXXX、
// 其余 HTML 实体，保证 served 页面纯 ASCII。手写模板时不要引入反引号
// 与 ${}（页面内声明的插值除外），也不要在内联 JS 里写反斜杠正则。
// =====================================================================

// =====================================================================
// 【文件浏览器】/browse —— Alist 风格个人只读网盘页面（登录页 + 主界面）
// ---------------------------------------------------------------------
// 参照 Alist 前端（AlistGo/alist-web，SolidJS + HopeUI）的设计语言重制：
//   - 主色 #1890ff（getMainColor 默认值），页面背景 #f7f8fa，hover 底色
//     rgba(132,133,141,0.18)，内容容器 min(99%, 980px)，字体栈与 Alist 一致；
//   - 文件列表放在白色圆角卡片内（Obj 卡片风格，rounded 12px + 阴影）；
//   - 网格卡片悬停 scale(1.05) + hover 底色，图标为主色单色 SVG；
//   - 列表三列（名称 / 大小 / 修改时间），移动端隐藏修改时间列；
//   - 文件大小格式同 Alist getFileSize（1.02K / 1.00M / 2.00G），
//     时间格式 YYYY-MM-DD HH:MM:SS。
// 实现方式：本文件由 _parts/ 分块拼接（_build-pages.mjs），再由
// _build-browse.mjs 合并进 cos-proxy-worker.js（原附件代理/签名/浏览后端
// 逻辑保持逐字节不变）。中文/emoji 由构建器转成 <script> 内 \uXXXX、
// 其余 HTML 实体，保证 served 页面纯 ASCII。手写模板时不要引入反引号
// 与 ${}（页面内声明的插值除外），也不要在内联 JS 里写反斜杠正则。
// =====================================================================
function browseLoginHtml(env) {
  const sitekey = (env && env.TURNSTILE_SITEKEY) || '';
  const tsScript = sitekey ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' : '';
  const tsWidget = sitekey ? '<div class="cf-turnstile" data-sitekey="' + sitekey + '" data-callback="onTs"></div>' : '';
  const tsJs = sitekey ? '<script>function onTs(){var b=document.getElementById("loginBtn");if(b){b.disabled=false;}}</script>' : '';
  return `<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#3573FF">
<title>&#x767B;&#x5F55; &#xB7; COS &#x7F51;&#x76D8;</title>
<style>
:root{--primary:#3573FF;--text:#1f2329;--muted:#9aa0a8}
body.dark{--primary:#4c8dff;--text:#e8eaed;--muted:#6b7280}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif,"Apple Color Emoji","Segoe UI Emoji","Segoe UI Symbol";background:#f7f8fa;color:var(--text);display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;transition:background .2s,color .2s}
body.dark{background:#0f1013}
.card{width:min(92vw,360px);background:#fff;border-radius:12px;padding:36px 30px 26px;box-shadow:0 10px 30px -5px rgba(0,0,0,.08);text-align:center}
body.dark .card{background:#1b1d21;box-shadow:0 10px 30px -5px rgba(0,0,0,.5)}
.logo{width:52px;height:52px;margin:0 auto 12px;color:var(--primary)}
h1{font-size:21px;margin:0 0 6px;font-weight:700}
.sub{font-size:13px;color:var(--muted);margin:0 0 24px}
input[type=password]{width:100%;height:45px;border:1px solid #e4e7ec;border-radius:12px;padding:0 15px;font-size:15px;outline:none;background:#f7f8fa;margin-bottom:14px;color:var(--text);transition:border .15s,background .15s}
input[type=password]:focus{border-color:var(--primary);background:#fff}
body.dark input[type=password]{background:#232529;border-color:#2a2c30}
body.dark input[type=password]:focus{background:#232529}
.cf-turnstile{margin-bottom:14px;display:flex;justify-content:center}
button[type=submit]{width:100%;height:45px;border:0;border-radius:12px;background:var(--primary);color:#fff;font-size:16px;font-weight:bold;cursor:pointer;transition:background .15s,opacity .15s}
button[type=submit]:hover{background:#2B5CD9}
button[type=submit]:active{background:#1E40AF}
button[type=submit]:disabled{opacity:.5;cursor:not-allowed}
.err{min-height:20px;margin:10px 0 0;font-size:13px;color:#e5484d;line-height:20px}
.hint{margin-top:22px;font-size:11px;color:#b9bec6}
body.dark .hint{color:#626a78}
.theme-btn{position:fixed;top:14px;right:14px;width:36px;height:36px;border:0;border-radius:10px;background:#fff;color:#1f2329;font-size:16px;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,.08)}
body.dark .theme-btn{background:#1b1d21;color:#e8eaed}
</style></head><body>
<button class="theme-btn" id="themeBtn" title="&#x4E3B;&#x9898;">&#x1F319;</button>
<div class="card">
  <svg class="logo" viewBox="0 0 24 24" fill="currentColor"><path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z"/></svg>
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
function setDark(d){
  document.body.classList.toggle('dark',d);
  try{ localStorage.setItem('browseLoginDark',d?'1':'0'); }catch(e){}
  var b=document.getElementById('themeBtn');
  if(b){ b.innerHTML=d?'&#x2600;&#xFE0F;':'&#x1F319;'; }
}
try{
  var saved=localStorage.getItem('browseLoginDark');
  setDark(saved==='1'||(saved===null&&window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches));
}catch(e){}
var tb=document.getElementById('themeBtn');
if(tb){ tb.onclick=function(){ setDark(!document.body.classList.contains('dark')); }; }
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
<meta name="theme-color" content="#1890ff">
<title>COS &#x7F51;&#x76D8;</title>
<style>
:root{--primary:#1890ff;--primary-weak:rgba(24,144,255,.15);--bg:#f7f8fa;--card:#ffffff;--text:#1f2329;--sub:#7a828e;--muted:#9aa0a8;--hover:rgba(132,133,141,0.18);--line:rgba(0,0,0,.08);--shadow:0 10px 30px -5px rgba(0,0,0,.08);--radius:12px}
body.dark{--primary:#4d9fff;--primary-weak:rgba(77,159,255,.15);--bg:#0f1013;--card:#1b1d21;--text:#e8eaed;--sub:#9aa0aa;--muted:#6b7280;--hover:rgba(255,255,255,.12);--line:rgba(255,255,255,.08);--shadow:0 10px 30px -5px rgba(0,0,0,.5)}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif,"Apple Color Emoji","Segoe UI Emoji","Segoe UI Symbol";background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased;transition:background .2s,color .2s}
button{font-family:inherit;color:var(--text);cursor:pointer}
.topbar{position:sticky;top:0;z-index:60;display:flex;align-items:center;height:60px;padding:0 12px;background:var(--bg);transition:background .2s}
.brand{display:flex;align-items:center;gap:10px;font-size:16px;font-weight:700;cursor:pointer;user-select:none;white-space:nowrap}
.brand .logo{width:30px;height:30px;color:var(--primary)}
.hright{display:flex;align-items:center;gap:8px;margin-left:auto}
.pill{display:inline-flex;align-items:center;gap:6px;height:34px;padding:0 12px;border:0;border-radius:8px;background:var(--primary-weak);color:var(--primary);font-size:14px;cursor:pointer;transition:background .15s}
.pill:hover{background:rgba(24,144,255,.25)}
body.dark .pill:hover{background:rgba(77,159,255,.25)}
.pill svg{width:16px;height:16px}
.pill .kbd{font-size:11px;opacity:.75;border:1px solid currentColor;border-radius:4px;padding:0 4px;font-family:inherit}
.iconbtn{width:34px;height:34px;border:0;border-radius:8px;background:transparent;color:var(--sub);font-size:16px;display:inline-flex;align-items:center;justify-content:center;transition:background .15s,color .15s}
.iconbtn:hover{background:var(--hover);color:var(--text)}
.iconbtn:active{transform:scale(.94)}
.iconbtn svg{width:18px;height:18px}
.layout{display:flex;max-width:min(99%,980px);margin:0 auto;min-height:calc(100vh - 60px);padding:0 12px 30px;gap:14px}
.sidebar{width:180px;flex-shrink:0;padding:16px 6px 12px;display:flex;flex-direction:column}
.sb-item{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:8px;font-size:14px;color:var(--sub);cursor:pointer;user-select:none;transition:background .15s,color .15s}
.sb-item .sic{width:20px;text-align:center;font-size:16px;flex-shrink:0}
.sb-item:hover{background:var(--hover);color:var(--text)}
.sb-item.on{background:var(--primary-weak);color:var(--primary);font-weight:600}
.sb-foot{margin-top:auto;padding:12px 8px 2px;font-size:11px;color:var(--muted)}
.main{flex:1;min-width:0}
.crumbs{display:flex;align-items:center;gap:2px;padding:16px 0 10px;font-size:15px;overflow-x:auto;white-space:nowrap;scrollbar-width:none}
.crumbs::-webkit-scrollbar{display:none}
.crumb{display:inline-flex;align-items:center;gap:4px;color:var(--text);cursor:pointer;padding:4px 6px;border-radius:6px}
.crumb:hover{background:var(--hover)}
.crumb .cico{display:inline-flex;color:var(--primary)}
.crumb .cico svg{width:17px;height:17px}
.crumb.last{font-weight:600;cursor:default}
.crumb.last:hover{background:transparent}
.csep{color:var(--muted);margin:0 2px;user-select:none}
.searchbar{padding:0 0 10px}
.searchbar input{width:100%;height:40px;border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--text);padding:0 14px;font-size:14px;outline:none;transition:border .15s}
.searchbar input:focus{border-color:var(--primary)}
.toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:2px 0 10px}
.tleft{display:flex;align-items:center;gap:6px;margin-right:auto}
select{height:32px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--text);font-size:13px;padding:0 6px;outline:none;cursor:pointer}
.chips{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.chip{height:28px;padding:0 11px;border:1px solid var(--line);border-radius:999px;background:var(--card);color:var(--sub);font-size:12px;display:inline-flex;align-items:center;cursor:pointer;transition:all .15s;user-select:none}
.chip:hover{color:var(--text);border-color:var(--primary)}
.chip.on{background:var(--primary);border-color:var(--primary);color:#fff;font-weight:600}
.objcard{background:var(--card);border-radius:var(--radius);padding:10px;box-shadow:var(--shadow);transition:background .2s,box-shadow .2s}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:6px}
.item{position:relative;padding:6px 4px;border-radius:8px;cursor:pointer;text-align:center;user-select:none;transition:background .15s,transform .1s;animation:itemIn .2s ease}
.item:hover{background:var(--hover);transform:scale(1.05)}
.item:active{transform:scale(.98)}
@keyframes itemIn{from{opacity:0;transform:scale(.9)}to{opacity:1;transform:scale(1)}}
.it-ic{height:90px;display:flex;align-items:center;justify-content:center;color:var(--primary);overflow:hidden}
.it-ic svg{width:60px;height:60px}
.it-ic img.it-img{width:100%;height:100%;object-fit:cover;border-radius:8px;display:block}
.it-name{font-size:14px;line-height:1.4;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;padding:0 2px;margin-top:2px}
.it-more{position:absolute;top:4px;right:4px;width:26px;height:26px;border:0;border-radius:7px;background:rgba(0,0,0,.45);color:#fff;font-size:14px;line-height:1;cursor:pointer;opacity:0;transition:opacity .15s;z-index:3}
.item:hover .it-more,.item:focus-within .it-more{opacity:1}
@media (hover:none){.it-more{opacity:.9}}
.lhead{display:flex;align-items:center;gap:8px;padding:8px 12px;color:var(--muted);font-size:14px;font-weight:700;border-bottom:1px solid var(--line)}
.lhead .lcol{cursor:pointer;user-select:none;white-space:nowrap}
.lhead .lcol:hover{color:var(--primary)}
.lname{flex:1;min-width:0;display:flex;align-items:center;gap:10px;overflow:hidden}
.lhead .lname{cursor:pointer;user-select:none;white-space:nowrap}
.lhead .lname:hover{color:var(--primary)}
.lname .lic{flex-shrink:0;color:var(--primary);display:inline-flex}
.lname .lic svg{width:22px;height:22px}
.lname .lnm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lrow{display:flex;align-items:center;gap:8px;padding:10px 12px;border-radius:8px;cursor:pointer;transition:background .15s;animation:itemIn .2s ease}
.lrow:hover{background:var(--hover)}
.lrow.act{background:var(--hover)}
.lsize{width:28%;text-align:right;flex-shrink:0;color:var(--sub);font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.lmod{width:24%;text-align:right;flex-shrink:0;color:var(--muted);font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.status{display:flex;flex-direction:column;align-items:center;gap:12px;padding:46px 0;color:var(--muted);font-size:14px}
.spinner{width:26px;height:26px;border:3px solid var(--line);border-top-color:var(--primary);border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.pager{padding:6px 0 2px}
.pagerbar{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;padding:10px 2px 6px}
.pg-nav{display:flex;align-items:center;gap:4px;flex-wrap:wrap}
.pg-btn{min-width:30px;height:30px;padding:0 8px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--sub);font-size:13px;cursor:pointer;transition:all .15s;line-height:1}
.pg-btn:hover{border-color:var(--primary);color:var(--primary)}
.pg-btn.cur{background:var(--primary);border-color:var(--primary);color:#fff;font-weight:600}
.pg-dots{color:var(--muted);padding:0 2px;user-select:none}
#perPageSel{height:30px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--text);font-size:13px;padding:0 6px;outline:none;cursor:pointer}
.pg-goto{display:inline-flex;align-items:center;gap:4px;color:var(--muted);font-size:13px;margin-left:6px;white-space:nowrap}
.pg-goto input{width:52px;height:30px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--text);font-size:13px;text-align:center;outline:none;padding:0 4px;-moz-appearance:textfield}
.pg-goto input::-webkit-outer-spin-button,.pg-goto input::-webkit-inner-spin-button{-webkit-appearance:none;margin:0}
.pg-goto input:focus{border-color:var(--primary)}
.pg-goto .pg-btn{min-width:auto;padding:0 10px}
.footer{text-align:center;font-size:12px;color:var(--muted);padding:20px 0 6px}
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
.btn{flex:1;height:38px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--text);font-size:13px;display:inline-flex;align-items:center;justify-content:center;gap:5px;transition:background .15s}
.btn:hover{background:var(--hover)}
.btn.primary{background:var(--primary);border-color:var(--primary);color:#fff}
.btn.primary:hover{filter:brightness(1.06)}
.preview{background:#000;border-radius:10px;overflow:hidden;margin:0 0 12px;min-height:60px}
.preview img{display:block;max-width:100%;max-height:56vh;object-fit:contain;margin:0 auto}
.preview video,.preview audio{width:100%;max-height:56vh;border:0;display:block}
.preview iframe{width:100%;height:56vh;border:0;background:#fff;display:block}
.preview pre{margin:0;padding:12px;font-size:12.5px;white-space:pre-wrap;word-break:break-all;font-family:ui-monospace,Consolas,'Courier New',monospace;background:var(--bg);color:var(--text);max-height:48vh;overflow:auto}
.preview .ph{color:#c5c9d0;text-align:center;padding:30px 12px;font-size:13px}
.preview .ph .big{width:44px;height:44px;display:inline-block;color:#fff;margin-bottom:8px}
#toast{position:fixed;left:50%;bottom:26px;transform:translateX(-50%) translateY(20px);background:rgba(20,22,26,.92);color:#fff;padding:9px 16px;border-radius:10px;font-size:13px;opacity:0;pointer-events:none;transition:all .25s;z-index:200;max-width:86vw;text-align:center}
#toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.scrim{position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:75;opacity:0;pointer-events:none;transition:opacity .25s}
.scrim.show{opacity:1;pointer-events:auto}
@media (max-width:760px){
  #menuBtn{display:inline-flex}
  .sidebar{position:fixed;left:0;top:0;bottom:0;width:240px;z-index:85;background:var(--card);border-right:0;box-shadow:8px 0 30px rgba(0,0,0,.25);transform:translateX(-104%);transition:transform .28s ease;padding-top:20px}
  .sidebar.open{transform:none}
  .sb-foot{display:none}
  .brand .bname{display:none}
  .layout{padding:0 6px 20px;gap:0}
  .grid{grid-template-columns:repeat(auto-fill,minmax(90px,1fr));gap:4px}
  .item{padding:4px 2px}
  .it-ic{height:72px}
  .it-ic svg{width:50px;height:50px}
  .it-name{font-size:13px}
  .lsize{width:76px}
  .lmod{display:none}
  .crumbs{padding:12px 0 8px;font-size:14px}
  .pill .kbd{display:none}
  .searchbar input{height:38px}
}
@media (min-width:761px){
  #menuBtn{display:none}
  #sheet{left:50%;right:auto;bottom:auto;top:50%;transform:translate(-50%,-50%) scale(.96);width:min(560px,94vw);max-height:88vh;border-radius:16px;visibility:hidden}
  #sheet.show{transform:translate(-50%,-50%) scale(1)}
  .sh-grab{display:none}
}
</style></head><body>
<header class="topbar">
  <button class="iconbtn" id="menuBtn" title="&#x83DC;&#x5355;">&#x2630;</button>
  <div class="brand" id="brand">
    <svg class="logo" viewBox="0 0 24 24" fill="currentColor"><path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z"/></svg>
    <span class="bname">COS &#x7F51;&#x76D8;</span>
  </div>
  <div class="hright">
    <button class="pill" id="searchBtn" title="&#x641C;&#x7D22; (Ctrl+K)">
      <svg viewBox="0 0 24 24" fill="currentColor"><path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
      <span class="kbd">Ctrl K</span>
    </button>
    <button class="pill" id="viewBtn" title="&#x5207;&#x6362;&#x89C6;&#x56FE;">
      <svg id="viewIc" viewBox="0 0 24 24" fill="currentColor"><path d="M3 14h4v-4H3v4zm0 5h4v-4H3v4zM3 9h4V5H3v4zm5 5h13v-4H8v4zm0 5h13v-4H8v4zM8 5v4h13V5H8z"/></svg>
    </button>
    <button class="iconbtn" id="themeBtn" title="&#x4E3B;&#x9898;">&#x1F319;</button>
    <button class="iconbtn" id="mailBtn" title="&#x8FD4;&#x56DE;&#x90AE;&#x4EF6;">
      <svg viewBox="0 0 24 24" fill="currentColor"><path d="M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z"/></svg>
    </button>
    <button class="iconbtn" id="logoutBtn" title="&#x9000;&#x51FA;">
      <svg viewBox="0 0 24 24" fill="currentColor"><path d="M10.09 15.59L11.5 17l5-5-5-5-1.41 1.41L12.67 11H3v2h9.67l-2.58 2.59zM19 3H5c-1.11 0-2 .9-2 2v4h2V5h14v14H5v-4H3v4c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2z"/></svg>
    </button>
  </div>
</header>
<div class="layout">
  <div class="scrim" id="scrim"></div>
  <aside class="sidebar" id="sidebar">
    <div class="sb-item on" data-nav="home"><span class="sic">&#x1F3E0;</span><span>&#x9996;&#x9875;</span></div>
    <div class="sb-item" data-nav="recent"><span class="sic">&#x23F3;</span><span>&#x6700;&#x8FD1;</span></div>
    <div class="sb-item" data-nav="fav"><span class="sic">&#x2B50;</span><span>&#x6536;&#x85CF;</span></div>
    <div class="sb-foot">&#x53EA;&#x8BFB;&#x6D4F;&#x89C8; &middot; cos-exchange</div>
  </aside>
  <main class="main">
    <nav class="crumbs" id="crumbs"></nav>
    <div class="searchbar" id="searchbar" style="display:none">
      <input id="search" placeholder="&#x641C;&#x7D22;&#x5F53;&#x524D;&#x76EE;&#x5F55;..." autocomplete="off">
    </div>
    <div class="toolbar">
      <div class="tleft">
        <button class="iconbtn" id="upBtn" title="&#x4E0A;&#x4E00;&#x7EA7;">&#x2191;</button>
        <select id="sort" title="&#x6392;&#x5E8F;">
          <option value="name-asc" selected>&#x540D;&#x79F0; &#x2191;</option>
          <option value="name-desc">&#x540D;&#x79F0; &#x2193;</option>
          <option value="size-desc">&#x5927;&#x5C0F; &#x2193;</option>
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
    <div class="objcard">
      <div id="filelist"></div>
      <div class="pager" id="pager"></div>
    </div>
    <footer class="footer">&#x53EA;&#x8BFB;&#x6D4F;&#x89C8; &middot; cos-exchange</footer>
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
var DOC=['doc','docx','xls','xlsx','ppt','pptx'];
var ARC=['zip','rar','7z','tar','gz','bz2','xz','7zip','tgz'];
var CODE=['js','css','ts','py','sh','json','html','htm','xml','yaml','yml','ini','conf','cfg','bat'];
var TXT=['txt','md','csv','log'];
var SVGICONS={
  folder:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>',
  img:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5-4.5z"/></svg>',
  vid:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M18 4l2 4h-3l-2-4h-2l2 4h-3l-2-4H8l2 4H7L5 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V4h-4z"/></svg>',
  aud:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 3v10.55A4 4 0 1 0 14 17V7h4V3h-6z"/></svg>',
  pdf:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm1 9l-3 3-1.5-1.5L8 15h8l-1-4z"/></svg>',
  arc:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M20.54 5.23l-1.39-1.68C18.88 3.21 18.47 3 18 3H6c-.47 0-.88.21-1.16.55L3.46 5.23C3.17 5.57 3 6.02 3 6.5V19c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V6.5c0-.48-.17-.93-.46-1.27zM12 17.5L6.5 12H10v-2h4v2h3.5L12 17.5zM5.12 5l.81-1h12l.94 1H5.12z"/></svg>',
  doc:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>',
  txt:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>',
  code:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M9.4 16.6L4.8 12l4.6-4.6L8 6l-6 6 6 6 1.4-1.4zm5.2 0l4.6-4.6-4.6-4.6L16 6l6 6-6 6-1.4-1.4z"/></svg>',
  other:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zM16 18H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>'
};
var ext=function(n){return (n.split('.').pop()||'').toLowerCase();};
var icOf=function(o){
  var e=ext(o.name);
  if(o.type==='img'){return SVGICONS.img;}
  if(o.type==='vid'){return SVGICONS.vid;}
  if(o.type==='aud'){return SVGICONS.aud;}
  if(o.type==='arc'){return SVGICONS.arc;}
  if(e==='pdf'){return SVGICONS.pdf;}
  if(CODE.indexOf(e)>=0){return SVGICONS.code;}
  if(o.type==='doc'){return SVGICONS.doc;}
  if(TXT.indexOf(e)>=0){return SVGICONS.txt;}
  return SVGICONS.other;
};
var fmt=function(s){
  if(!s){return '-';}
  var n=1024;
  if(s<n){return s+'B';}
  if(s<n*n){return (s/n).toFixed(2)+'K';}
  if(s<n*n*n){return (s/(n*n)).toFixed(2)+'M';}
  if(s<n*n*n*n){return (s/(n*n*n)).toFixed(2)+'G';}
  return (s/(n*n*n*n)).toFixed(2)+'T';
};
var fmtT=function(t){
  if(!t){return '';}
  var d=new Date(t);
  if(isNaN(d.getTime())){return '';}
  var p=function(x){return String(x).padStart(2,'0');};
  return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes())+':'+p(d.getSeconds());
};
var urlOf=function(k){return '/browse/api/file?key='+encodeURIComponent(k);};
var typeOf=function(n){var e=ext(n);if(IMG.indexOf(e)>=0){return 'img';}if(VID.indexOf(e)>=0){return 'vid';}if(AUD.indexOf(e)>=0){return 'aud';}if(DOC.indexOf(e)>=0){return 'doc';}if(ARC.indexOf(e)>=0){return 'arc';}return 'oth';};
var typeLabel={'img':'\\u56FE\\u7247','vid':'\\u89C6\\u9891','aud':'\\u97F3\\u9891','doc':'\\u6587\\u6863','arc':'\\u538B\\u7F29','oth':'\\u5176\\u4ED6'};
var prefix='';
// \\u5206\\u9875\\uFF08\\u6587\\u4EF6\\u5217\\u8868\\uFF09\\uFF1ACOS continuation-token \\u987A\\u5E8F\\u7FFB\\u9875\\uFF0CpageTokens[i] \\u7F13\\u5B58\\u8FDB\\u5165\\u7B2C i \\u9875\\u6240\\u9700\\u7684 token
var perPage=60;        // \\u6BCF\\u9875\\u6761\\u6570\\uFF0830/60/100\\uFF09
var pageNo=1;          // \\u5F53\\u524D\\u9875
var pageTokens=[];     // pageTokens[i] = \\u7B2C i \\u9875\\u8BF7\\u6C42\\u7528\\u7684 continuation-token\\uFF08\\u7B2C 1 \\u9875\\u4E3A ''\\uFF09
var maxLoadedPage=1;   // \\u5DF2\\u8BBF\\u95EE\\u7684\\u6700\\u5927\\u9875
var hasMore=false;     // \\u662F\\u5426\\u8FD8\\u6709\\u4E0B\\u4E00\\u9875\\uFF08COS IsTruncated\\uFF09
var filter='all';
var keyword='';
var sortVal='name-asc';
var view='list';
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
var localPage=1;       // \\u672C\\u5730\\u9875\\u9762\\uFF08\\u6700\\u8FD1/\\u6536\\u85CF\\uFF09\\u5F53\\u524D\\u9875\\uFF0C\\u6BCF\\u9875 perPage \\u6761
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
function statusHtml(msg,spin){
  return '<div class="status">'+(spin?'<div class="spinner"></div>':'')+esc(msg)+'</div>';
}
function load(reset){
  if(page!=='home'){renderLocal();return;}
  if(reset){pageTokens=[];pageNo=1;maxLoadedPage=1;hasMore=false;}
  loadPage(pageNo);
}
// \\u52A0\\u8F7D\\u7B2C n \\u9875\\uFF08token \\u7F13\\u5B58\\u81EA pageTokens\\uFF0C\\u5DF2\\u8BBF\\u95EE\\u9875\\u53EF\\u56DE\\u7FFB\\uFF1B\\u4E0B\\u4E00\\u9875\\u65F6 maxLoadedPage+1\\uFF09
function loadPage(n){
  var token=pageTokens[n]||'';
  var box=$('filelist');
  var q=new URLSearchParams({prefix:prefix,per_page:String(perPage)});
  if(token){q.set('token',token);}
  box.innerHTML=statusHtml('\\u52A0\\u8F7D\\u4E2D...',true);
  var ctrl=new AbortController();
  var timer=setTimeout(function(){ctrl.abort();},15000);
  fetch('/browse/api/list?'+q.toString(),{signal:ctrl.signal})
  .then(function(res){
    if(res.status===429){
      box.innerHTML=statusHtml('\\u8BF7\\u6C42\\u8FC7\\u4E8E\\u9891\\u7E41(429)\\uFF0C\\u7A0D\\u540E\\u81EA\\u52A8\\u91CD\\u8BD5...',true);
      setTimeout(function(){loadPage(n);},4000);
      return null;
    }
    if(!res.ok){throw new Error('HTTP '+res.status);}
    return res.json();
  })
  .then(function(data){
    if(data===null){return;}
    if(data.error){
      box.innerHTML=statusHtml('\\u52A0\\u8F7D\\u5931\\u8D25: '+data.error,false);
      return;
    }
    allData=data;
    pageTokens[n]=token;
    pageTokens[n+1]=data.token||'';
    hasMore=!!data.truncated;
    folders=data.folders||[];
    files=data.files||[];
    pageNo=n;
    if(n>maxLoadedPage){maxLoadedPage=n;}
    render();
  })
  .catch(function(e){
    if(ctrl.signal.aborted){
      box.innerHTML=statusHtml('\\u52A0\\u8F7D\\u8D85\\u65F6\\uFF0C\\u8BF7\\u91CD\\u8BD5',false);
    }else{
      box.innerHTML=statusHtml('\\u52A0\\u8F7D\\u5931\\u8D25: '+String((e&&e.message)||e),false);
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
    html=gridHtml(folders,list);
    if(!html&&!(allData&&allData.raw)){html=statusHtml('\\uFF08\\u7A7A\\u76EE\\u5F55\\uFF09',false);}
  }else{
    html='<div class="lhead">'
      +'<div class="lname" data-s="name">\\u540D\\u79F0</div>'
      +'<div class="lsize" data-s="size">\\u5927\\u5C0F</div>'
      +'<div class="lmod" data-s="time">\\u4FEE\\u6539\\u65F6\\u95F4</div>'
      +'</div>'
      +listHtml(folders,list);
    if(!list.length&&!folders.length){html=statusHtml('\\uFF08\\u7A7A\\u76EE\\u5F55\\uFF09',false);}
  }
  box.innerHTML=html;
  lazyBind(box);
  bindList(box);
  renderCrumbs();
  renderPager();
}
function renderLocal(){
  var src=(page==='recent')?recents:favs;
  var list=sortList(applyFilter(src.slice())).slice((localPage-1)*perPage,localPage*perPage);
  activeItems=list;
  imgs=list.filter(function(o){return o.type==='img';});
  var box=$('filelist');
  var label=(page==='recent')?'\\u6682\\u65E0\\u6700\\u8FD1\\u6D4F\\u89C8\\u8BB0\\u5F55':'\\u6682\\u65E0\\u6536\\u85CF\\u6587\\u4EF6';
  var ic=(page==='recent')?'&#x23F3;':'&#x2B50;';
  if(!list.length){
    box.innerHTML='<div class="status"><span style="font-size:34px">'+ic+'</span>'+label+'</div>';
  }else if(view==='grid'){
    box.innerHTML=gridHtml([],list);
  }else{
    box.innerHTML='<div class="lhead">'
      +'<div class="lname">\\u540D\\u79F0</div>'
      +'<div class="lsize">\\u5927\\u5C0F</div>'
      +'<div class="lmod">\\u4FEE\\u6539\\u65F6\\u95F4</div>'
      +'</div>'
      +listHtml([],list);
  }
  lazyBind(box);
  bindList(box);
  renderCrumbs();
  renderPager();
}
function gridHtml(folders,list){
  var h='';
  for(var i=0;i<folders.length;i++){
    var f=folders[i];
    var nm=f.slice(0,-1).split('/').pop();
    h+='<div class="item" data-act="open" data-key="'+esc(f)+'">'
      +'<div class="it-ic">'+SVGICONS.folder+'</div>'
      +'<div class="it-name" title="'+esc(nm)+'">'+esc(nm)+'</div></div>';
  }
  for(var j=0;j<list.length;j++){
    var o=list[j];
    var ic=(o.type==='img')
      ?'<img class="it-img" loading="lazy" data-src="'+urlOf(o.key)+'" decoding="async" alt="">'
      :icOf(o);
    h+='<div class="item" data-act="file" data-key="'+esc(o.key)+'">'
      +'<button class="it-more" data-more="'+esc(o.key)+'" title="\\u66F4\\u591A">&#x22EF;</button>'
      +'<div class="it-ic">'+ic+'</div>'
      +'<div class="it-name" title="'+esc(o.name)+'">'+esc(o.name)+'</div></div>';
  }
  return h;
}
function listHtml(folders,list){
  var h='';
  for(var i=0;i<folders.length;i++){
    var f=folders[i];
    var nm=f.slice(0,-1).split('/').pop();
    h+='<div class="lrow" data-act="open" data-key="'+esc(f)+'">'
      +'<div class="lname"><span class="lic">'+SVGICONS.folder+'</span><span class="lnm">'+esc(nm)+'</span></div>'
      +'<div class="lsize">-</div><div class="lmod">-</div></div>';
  }
  for(var j=0;j<list.length;j++){
    var o=list[j];
    h+='<div class="lrow" data-act="file" data-key="'+esc(o.key)+'">'
      +'<div class="lname"><span class="lic">'+icOf(o)+'</span><span class="lnm">'+esc(o.name)+'</span></div>'
      +'<div class="lsize">'+fmt(o.size)+'</div><div class="lmod">'+esc(fmtT(o.mtime))+'</div></div>';
  }
  return h;
}
function bindList(box){
  box.onclick=function(e){
    var th=e.target.closest('[data-s]');
    if(th){sortKey(th.getAttribute('data-s'));return;}
    var m=e.target.closest('[data-more]');
    if(m){e.stopPropagation();var mk=m.getAttribute('data-more');var mo=findItem(mk);if(mo){openDetail(mo);}return;}
    var it=e.target.closest('.item,.lrow');
    if(!it){return;}
    var key=it.getAttribute('data-key')||'';
    if(it.getAttribute('data-act')==='open'){open(key);return;}
    var o=findItem(key);
    if(!o){return;}
    if(o.type==='img'){showLightbox(key);}else{openDetail(o);}
  };
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
  localPage=1;
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
  html='<span class="crumb" data-cr=""><span class="cico">'+SVGICONS.folder+'</span>\\u9996\\u9875</span>';
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
function perPageSelHtml(){
  return '<select id="perPageSel" title="\\u6BCF\\u9875\\u6761\\u6570">'
    +'<option value="30">30 / \\u9875</option>'
    +'<option value="60">60 / \\u9875</option>'
    +'<option value="100">100 / \\u9875</option>'
    +'</select>';
}
function bindPerPageSel(){
  var s=$('perPageSel');
  if(!s){return;}
  s.value=String(perPage);
  s.onchange=function(){
    perPage=parseInt(this.value,10);
    if(page==='home'){load(true);}
    else{localPage=1;renderLocal();}
  };
}
// \\u6587\\u4EF6\\u5217\\u8868\\u5206\\u9875\\u5668\\uFF1ACOS \\u65E0\\u603B\\u6570\\uFF0C\\u6309\\u300C\\u5DF2\\u8BBF\\u95EE\\u9875 + \\u4E0A\\u4E00\\u9875/\\u4E0B\\u4E00\\u9875\\u300D\\u987A\\u5E8F\\u7FFB\\u9875\\uFF08token \\u7F13\\u5B58\\uFF09
function renderPager(){
  var p=$('pager');
  if(page!=='home'){renderLocalPager(p);return;}
  if(!allData){p.innerHTML='';return;}
  if(!folders.length&&!files.length){p.innerHTML='';return;}
  var html='<div class="pagerbar">'
    +'<div class="pg-left">'+perPageSelHtml()+'</div>'
    +'<div class="pg-nav">';
  if(pageNo>1){
    html+='<button class="pg-btn" data-pg="prev" title="\\u4E0A\\u4E00\\u9875">&#x2039;</button>';
  }
  // \\u9875\\u7801\\u6298\\u53E0\\uFF1A\\u53EA\\u663E\\u793A \\u9996\\u98751 / \\u5F53\\u524D\\u9875\\u9644\\u8FD1\\u00B11 / \\u5DF2\\u8BBF\\u95EE\\u6700\\u5927\\u9875\\uFF0C\\u5176\\u4F59\\u7528\\u7701\\u7565\\u53F7\\u3002
  // \\u6587\\u4EF6\\u4E0A\\u4E07\\u3001\\u9875\\u6570\\u518D\\u591A\\u4E5F\\u4E0D\\u4F1A\\u6E32\\u67D3\\u51FA\\u4E00\\u957F\\u4E32\\u9875\\u7801\\uFF08\\u907F\\u514D\\u7FFB\\u9875\\u5668\\u6EA2\\u51FA\\uFF09\\u3002
  var shown=[];
  for(var i=1;i<=maxLoadedPage;i++){
    if(i===1||i===maxLoadedPage||Math.abs(i-pageNo)<=1){shown.push(i);}
  }
  var last=0;
  for(var j=0;j<shown.length;j++){
    var pg=shown[j];
    if(pg-last>1){html+='<span class="pg-dots">&#x2026;</span>';}
    html+='<button class="pg-btn'+(pg===pageNo?' cur':'')+'" data-pg="'+pg+'">'+pg+'</button>';
    last=pg;
  }
  if(hasMore){
    html+='<button class="pg-btn" data-pg="next" title="\\u4E0B\\u4E00\\u9875">&#x203A;</button>';
  }
  // \\u8DF3\\u9875\\u8F93\\u5165\\u6846\\uFF1ACOS \\u65E0\\u603B\\u9875\\u6570\\uFF0C\\u9650\\u5236\\u5728\\u300C\\u5DF2\\u52A0\\u8F7D\\u9875\\u8303\\u56F4\\u300D\\u5185\\uFF081~maxLoadedPage\\uFF09\\uFF0C
  // \\u8D85\\u51FA\\u63D0\\u793A\\uFF0C\\u907F\\u514D\\u8F93\\u5165\\u8FDC\\u8DDD\\u79BB\\u9875\\u53F7\\u65F6\\u65E0\\u9650\\u987A\\u5E8F\\u8BF7\\u6C42\\u89E6\\u53D1\\u9650\\u6D41
  html+='<span class="pg-goto">\\u8DF3\\u81F3<input id="pgInput" type="number" min="1" max="'+maxLoadedPage+'" inputmode="numeric" value="'+pageNo+'" title="\\u5DF2\\u52A0\\u8F7D '+maxLoadedPage+' \\u9875"><button class="pg-btn" id="pgGo" type="button">GO</button></span>';
  html+='</div></div>';
  p.innerHTML=html;
  bindPerPageSel();
  var gi=$('pgInput'),gb=$('pgGo');
  if(gi){gi.addEventListener('keydown',function(e){if(e.key==='Enter'){goToFilePage(parseInt(gi.value,10));}});}
  if(gb){gb.onclick=function(){goToFilePage(parseInt(gi.value,10));};}
  p.onclick=function(e){
    var b=e.target.closest('.pg-btn');
    if(!b){return;}
    var v=b.getAttribute('data-pg');
    if(v==='prev'){if(pageNo>1){loadPage(pageNo-1);window.scrollTo(0,0);}}
    else if(v==='next'){if(hasMore){loadPage(pageNo+1);window.scrollTo(0,0);}}
    else{var n=parseInt(v,10);if(n>=1&&n<=maxLoadedPage){loadPage(n);window.scrollTo(0,0);}}
  };
}
// \\u6587\\u4EF6\\u5217\\u8868\\u8DF3\\u9875\\uFF1A\\u53EA\\u5141\\u8BB8 1~maxLoadedPage\\uFF08COS \\u65E0\\u603B\\u6570\\uFF0C\\u672A\\u8BBF\\u95EE\\u9875\\u9700\\u987A\\u5E8F\\u7FFB\\uFF0C\\u9632\\u9650\\u6D41\\uFF09
function goToFilePage(n){
  if(!Number.isFinite(n)||n<1){toast('\\u8BF7\\u8F93\\u5165\\u6709\\u6548\\u9875\\u7801');return;}
  n=Math.floor(n);
  if(n>maxLoadedPage){toast('\\u5DF2\\u52A0\\u8F7D\\u5230\\u7B2C '+maxLoadedPage+' \\u9875\\uFF0C\\u8D85\\u51FA\\u8303\\u56F4');return;}
  loadPage(n);
  window.scrollTo(0,0);
}
// \\u6700\\u8FD1/\\u6536\\u85CF\\u5206\\u9875\\u5668\\uFF1A\\u672C\\u5730\\u6570\\u636E\\u6709\\u603B\\u6570\\uFF0Calist \\u98CE\\u683C\\u6570\\u5B57\\u5206\\u9875\\uFF081 / \\u5F53\\u524D\\u9644\\u8FD1 / \\u672B\\u9875 + \\u7701\\u7565\\u53F7\\uFF09
function renderLocalPager(p){
  var src=(page==='recent')?recents:favs;
  var full=sortList(applyFilter(src.slice()));
  var pages=Math.max(1,Math.ceil(full.length/perPage));
  if(localPage>pages){localPage=pages;}
  if(full.length<=perPage){p.innerHTML='';return;}
  var html='<div class="pagerbar">'
    +'<div class="pg-left">'+perPageSelHtml()+'</div>'
    +'<div class="pg-nav">';
  if(localPage>1){html+='<button class="pg-btn" data-pg="prev" title="\\u4E0A\\u4E00\\u9875">&#x2039;</button>';}
  var shown=[];
  for(var i=1;i<=pages;i++){
    if(i===1||i===pages||Math.abs(i-localPage)<=1){shown.push(i);}
  }
  var last=0;
  for(var j=0;j<shown.length;j++){
    var pg=shown[j];
    if(pg-last>1){html+='<span class="pg-dots">&#x2026;</span>';}
    html+='<button class="pg-btn'+(pg===localPage?' cur':'')+'" data-pg="'+pg+'">'+pg+'</button>';
    last=pg;
  }
  if(localPage<pages){html+='<button class="pg-btn" data-pg="next" title="\\u4E0B\\u4E00\\u9875">&#x203A;</button>';}
  // \\u8DF3\\u9875\\u8F93\\u5165\\u6846\\uFF1A\\u672C\\u5730\\u9875\\u6709\\u603B\\u6570\\uFF0C\\u4EFB\\u610F 1~pages \\u8DF3\\u8F6C\\uFF0C\\u8D85\\u51FA\\u81EA\\u52A8\\u5C01\\u9876
  html+='<span class="pg-goto">\\u8DF3\\u81F3<input id="pgInput" type="number" min="1" max="'+pages+'" inputmode="numeric" value="'+localPage+'" title="\\u5171 '+pages+' \\u9875"><button class="pg-btn" id="pgGo" type="button">GO</button></span>';
  html+='</div></div>';
  p.innerHTML=html;
  bindPerPageSel();
  var gi=$('pgInput'),gb=$('pgGo');
  if(gi){gi.addEventListener('keydown',function(e){if(e.key==='Enter'){goToLocalPage(parseInt(gi.value,10));}});}
  if(gb){gb.onclick=function(){goToLocalPage(parseInt(gi.value,10));};}
  p.onclick=function(e){
    var b=e.target.closest('.pg-btn');
    if(!b){return;}
    var v=b.getAttribute('data-pg');
    if(v==='prev'){if(localPage>1){localPage--;renderLocal();window.scrollTo(0,0);}}
    else if(v==='next'){if(localPage<pages){localPage++;renderLocal();window.scrollTo(0,0);}}
    else{var n=parseInt(v,10);if(n>=1&&n<=pages){localPage=n;renderLocal();window.scrollTo(0,0);}}
  };
}
// \\u672C\\u5730\\u9875\\u8DF3\\u9875\\uFF1A1~\\u603B\\u9875\\u6570\\uFF0C\\u8D85\\u51FA\\u81EA\\u52A8\\u5C01\\u9876
function goToLocalPage(n){
  var src=(page==='recent')?recents:favs;
  var total=Math.max(1,Math.ceil(sortList(applyFilter(src.slice())).length/perPage));
  if(!Number.isFinite(n)){toast('\\u8BF7\\u8F93\\u5165\\u6709\\u6548\\u9875\\u7801');return;}
  n=Math.floor(n);
  if(n<1){n=1;}
  if(n>total){n=total;}
  localPage=n;
  renderLocal();
  window.scrollTo(0,0);
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
  }else if(e==='txt'||e==='md'||e==='csv'||e==='log'||e==='json'){
    pv.innerHTML='<div class="ph"><span class="big">'+SVGICONS.txt+'</span>\\u52A0\\u8F7D\\u4E2D...</div>';
    fetchText(o.key,pv);
  }else if(t==='img'){
    pv.innerHTML='<img src="'+urlOf(o.key)+'" alt="">';
  }else{
    pv.innerHTML='<div class="ph"><span class="big">'+icOf(o)+'</span>\\u8BE5\\u7C7B\\u578B\\u6682\\u4E0D\\u652F\\u6301\\u5728\\u7EBF\\u9884\\u89C8\\uFF0C\\u53EF\\u4E0B\\u8F7D\\u67E5\\u770B</div>';
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
    pv.innerHTML='<div class="ph"><span class="big">'+SVGICONS.txt+'</span>\\u6587\\u672C\\u52A0\\u8F7D\\u5931\\u8D25</div>';
  });
}
function saveFav(){try{localStorage.setItem('browse_fav',JSON.stringify(favs));}catch(e){}}
function isFav(key){for(var i=0;i<favs.length;i++){if(favs[i].key===key){return true;}}return false;}
function addFav(o){favs=favs.filter(function(x){return x.key!==o.key;});favs.unshift(o);saveFav();}
function removeFav(key){favs=favs.filter(function(x){return x.key!==key;});saveFav();}
function recordRecent(o){
  recents=recents.filter(function(x){return x.key!==o.key;});
  recents.unshift(o);
  if(recents.length>200){recents=recents.slice(0,200);}
  try{localStorage.setItem('browse_recent',JSON.stringify(recents));}catch(e){}
}
var VIEW_ICON={
  grid:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M4 11h5V5H4v6zm0 7h5v-6H4v6zm6 0h5v-6h-5v6zm6 0h4v-6h-4v6zm-6-7h5V5h-5v6zm6-6v6h4V5h-4z"/></svg>',
  list:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M3 14h4v-4H3v4zm0 5h4v-4H3v4zM3 9h4V5H3v4zm5 5h13v-4H8v4zm0 5h13v-4H8v4zM8 5v4h13V5H8z"/></svg>'
};
function updateViewBtn(){
  $('viewIc').innerHTML=view==='grid'?VIEW_ICON.grid:VIEW_ICON.list;
}
var toastTimer=null;
function toast(msg){
  var t=$('toast');
  t.textContent=msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer=setTimeout(function(){t.classList.remove('show');},1800);
}
// \\u7F29\\u7565\\u56FE\\u61D2\\u52A0\\u8F7D + \\u5E76\\u53D1\\u9650\\u6D41\\uFF1A\\u6700\\u591A\\u540C\\u65F6 4 \\u4E2A /browse/api/file \\u8BF7\\u6C42\\uFF0C
// \\u907F\\u514D\\u5927\\u76EE\\u5F55\\u77AC\\u95F4\\u6253\\u6EE1 per-IP \\u9650\\u6D41(120/min)\\u6216\\u6324\\u5360 Worker \\u8D44\\u6E90
var MAX_CONCURRENT=4;
var thumbQueue=[];
var thumbActive=0;
function thumbPump(){
  while(thumbActive<MAX_CONCURRENT&&thumbQueue.length){
    var img=thumbQueue.shift();
    if(!img||img.dataset.src===undefined){continue;}
    thumbActive++;
    img.onload=function(){thumbActive--;thumbPump();};
    img.onerror=function(){this.style.display='none';thumbActive--;thumbPump();};
    img.src=img.dataset.src;
    img.removeAttribute('data-src');
  }
}
var io=null;
if('IntersectionObserver' in window){
  io=new IntersectionObserver(function(entries){
    for(var i=0;i<entries.length;i++){
      var en=entries[i];
      if(en.isIntersecting){
        var im=en.target;
        if(im.dataset.src){thumbQueue.push(im);thumbPump();}
        io.unobserve(im);
      }
    }
  },{rootMargin:'500px'});
}
function lazyBind(root){
  var imgs=(root||document).querySelectorAll('img[data-src]');
  for(var i=0;i<imgs.length;i++){
    if(io){io.observe(imgs[i]);}
    else{thumbQueue.push(imgs[i]);thumbPump();}
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
    localPage=1;
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
var sb=$('searchbar');
var si=$('search');
function showSearch(show){
  if(show){
    sb.style.display='';
    si.focus();
  }else{
    sb.style.display='none';
    si.value='';
    keyword='';
    render();
  }
}
$('searchBtn').onclick=function(){showSearch(sb.style.display==='none');};
si.addEventListener('input',function(){keyword=si.value;render();});
$('viewBtn').onclick=function(){
  view=view==='grid'?'list':'grid';
  try{localStorage.setItem('browseView',view);}catch(e){}
  updateViewBtn();
  render();
};
$('themeBtn').onclick=function(){
  document.body.classList.toggle('dark');
  try{localStorage.setItem('browseDark',document.body.classList.contains('dark')?'1':'0');}catch(e){}
  $('themeBtn').innerHTML=document.body.classList.contains('dark')?'&#x2600;&#xFE0F;':'&#x1F319;';
};
$('mailBtn').onclick=function(){
  window.location.href='https://mail.duckgame-play.top';
};
$('logoutBtn').onclick=function(){
  // HttpOnly cookie \\u524D\\u7AEF JS \\u5220\\u4E0D\\u6389\\uFF0C\\u8D70\\u670D\\u52A1\\u7AEF /browse/logout\\uFF08Set-Cookie \\u6E05\\u9664\\u540E\\u518D\\u8DF3\\u8F6C\\uFF09
  window.location.href='/browse/logout';
};
$('upBtn').onclick=function(){if(page==='home'){up();}};
$('sort').addEventListener('change',function(){sortVal=this.value;render();});
$('chips').addEventListener('click',function(e){
  var c=e.target.closest('.chip');
  if(!c){return;}
  filter=c.getAttribute('data-f');
  var cs=document.querySelectorAll('.chip');
  for(var i=0;i<cs.length;i++){cs[i].classList.toggle('on',cs[i]===c);}
  render();
});
// \\u5173\\u95ED\\u5F39\\u5C42\\u65F6\\u6682\\u505C/\\u91CA\\u653E\\u5A92\\u4F53\\uFF1A\\u5426\\u5219 video/audio \\u5143\\u7D20\\u53EA\\u662F\\u88AB\\u9690\\u85CF\\uFF0C\\u4ECD\\u4F1A\\u7EE7\\u7EED\\u64AD\\u653E\\u4E0E\\u4E0B\\u8F7D
function closeSheet(){
  var pv=$('shPreview');
  var v=pv.querySelector('video');
  var a=pv.querySelector('audio');
  if(v){v.pause();v.removeAttribute('src');v.load();}
  if(a){a.pause();a.removeAttribute('src');a.load();}
  $('sheet').classList.remove('show');
}
$('shClose').onclick=closeSheet;
$('sheet').onclick=function(e){if(e.target===$('sheet')){closeSheet();}};
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
// \\u300C\\u590D\\u5236\\u94FE\\u63A5\\u300D\\u6309\\u94AE\\u5DF2\\u79FB\\u9664\\uFF1A\\u907F\\u514D\\u66B4\\u9732\\u6587\\u4EF6\\u8DEF\\u5F84\\u7ED3\\u6784\\uFF08key \\u76F4\\u63A5\\u51FA\\u73B0\\u5728 URL \\u4E2D\\uFF09\\u3002
// \\u9700\\u8981\\u7684\\u53EA\\u6709\\u300C\\u4E0B\\u8F7D\\u300D\\u4E0E\\u300C\\u6536\\u85CF\\u300D\\uFF0C\\u5176\\u5B83\\u64CD\\u4F5C\\u5728\\u6587\\u4EF6\\u5217\\u8868\\u5185\\u5373\\u53EF\\u5B8C\\u6210\\u3002
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
  if((e.ctrlKey||e.metaKey)&&(e.key==='k'||e.key==='K')){
    e.preventDefault();
    showSearch(sb.style.display==='none');
    return;
  }
  if(e.key==='Escape'){
    if(sb.style.display!=='none'){showSearch(false);render();}
    closeLb();
    closeSheet();
    return;
  }
  if(e.key==='ArrowLeft'&&$('lightbox').classList.contains('show')){imgIdx=(imgIdx-1+imgs.length)%imgs.length;lbShow();}
  else if(e.key==='ArrowRight'&&$('lightbox').classList.contains('show')){imgIdx=(imgIdx+1)%imgs.length;lbShow();}
});
try{
  if(localStorage.getItem('browseDark')==='1'){document.body.classList.add('dark');$('themeBtn').innerHTML='&#x2600;&#xFE0F;';}
  view=localStorage.getItem('browseView')||'list';
}catch(e){}
updateViewBtn();
load(true);
</script>
</body></html>`;
}
