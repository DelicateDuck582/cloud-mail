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
        return await handleBrowse(request, env);
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
async function handleBrowse(request, env) {
  const url = new URL(request.url);

  // 登录（POST）
  if (request.method === 'POST' && url.pathname === '/browse/login') {
    return await browseLogin(request, env);
  }
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  // 密码门控：未配置 BROWSE_PASS 时直接拒绝，防止误配导致整桶裸奔
  if (!env.BROWSE_PASS || !browseAuthed(request, env.BROWSE_PASS)) {
    return new Response(browseLoginHtml(), {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  // 首页
  if (url.pathname === '/browse' || url.pathname === '/browse/') {
    return new Response(browseIndexHtml(), {
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  // 列目录
  if (url.pathname === '/browse/api/list') {
    try {
      const prefix = url.searchParams.get('prefix') || '';
      const token = url.searchParams.get('token') || '';
      const data = await browseList(env, prefix, token);
      return new Response(JSON.stringify(data), {
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
      });
    } catch (e) {
      console.error('browse list error:', e);
      return new Response(JSON.stringify({ error: String(e && e.message || e).slice(0, 200) }), { status: 500 });
    }
  }

  // 下载/预览（经本 Worker 回源，不直连 COS）
  if (url.pathname === '/browse/api/file') {
    const key = url.searchParams.get('key') || '';
    if (!key || key.startsWith('/') || key.includes('../')) {
      return new Response('bad key', { status: 400 });
    }
    try {
      return await browseFetchFile(env, key);
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
  const form = await request.formData();
  const p = form.get('p') || '';
  if (p === env.BROWSE_PASS) {
    return new Response('', {
      status: 302,
      headers: {
        Location: '/browse',
        'Set-Cookie': `browse_pwd=${browseFingerprint(env.BROWSE_PASS)}; Path=/; Max-Age=604800; SameSite=Lax`,
      },
    });
  }
  return new Response('&#x5BC6;&#x7801;&#x9519;&#x8BEF;', {
    status: 401,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
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
  const kDate = await hmacHex('AWS4' + sk, dateStamp);
  const kRegion = await hmacHex(kDate, region);
  const kService = await hmacHex(kRegion, 's3');
  return await hmacHex(kService, 'aws4_request');
}

// 列目录：GET ?list-type=2&delimiter=/&prefix=...&continuation-token=...
async function browseList(env, prefix, token) {
  const host = new URL(env.S3_ENDPOINT).host;
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
  const scope = `${dateStamp}/${env.REGION}/s3/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, await sha256Hex(canonicalRequest)].join('\n');
  const key = await signingKey(env.AWS_SECRET_ACCESS_KEY, dateStamp, env.REGION);
  const signature = await hmacHex(key, stringToSign);
  const auth = `AWS4-HMAC-SHA256 Credential=${env.AWS_ACCESS_KEY_ID}/${scope}, SignedHeaders=${signedHeadersStr}, Signature=${signature}`;

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
    // 打印我们算出的 stringToSign，便于与 COS 返回的 StringToSign 对照排错
    console.error('browseList stringToSign:', stringToSign.replace(/\n/g, ' | '));
    throw new Error(`list failed ${res.status}: ${body}`);
  }
  return parseListXml(await res.text());
}

function parseListXml(xml) {
  const folders = [];
  const reFolder = /<CommonPrefixes><Prefix>([^<]*)<\/Prefix><\/CommonPrefixes>/g;
  let m;
  while ((m = reFolder.exec(xml))) {
    try { folders.push(decodeURIComponent(m[1])); } catch (e) { folders.push(m[1]); }
  }
  const files = [];
  const reFile = /<Contents>[\s\S]*?<Key>([^<]*)<\/Key>[\s\S]*?<Size>(\d+)<\/Size>[\s\S]*?<\/Contents>/g;
  while ((m = reFile.exec(xml))) {
    let k = m[1];
    try { k = decodeURIComponent(k); } catch (e) {}
    files.push({ key: k, size: Number(m[2]) });
  }
  const truncated = /<IsTruncated>true<\/IsTruncated>/.test(xml);
  const tm = xml.match(/<NextContinuationToken>([^<]*)<\/NextContinuationToken>/);
  return { folders, files, truncated, token: tm ? tm[1] : '' };
}

// 下载：经本 Worker 回源 COS（S3 签名 GET），不直连 COS 默认域名
async function browseFetchFile(env, key) {
  const rawEndpoint = (env.S3_ENDPOINT || '').trim().replace(/\/+$/, '');
  const region = (env.REGION || '').trim();
  const encodedPath = '/' + key.split('/').map(enc).join('/');
  const targetUrl = new URL(encodedPath, rawEndpoint);

  const signedHeaders = await getS3v4Headers({
    method: 'GET',
    url: targetUrl,
    region: region,
    accessKeyId: env.AWS_ACCESS_KEY_ID,
    secretAccessKey: env.AWS_SECRET_ACCESS_KEY,
  });
  const headersForFetch = { ...signedHeaders };
  delete headersForFetch['host'];
  delete headersForFetch['Host'];

  const res = await fetch(targetUrl.toString(), { method: 'GET', headers: headersForFetch, signal: AbortSignal.timeout(10000) });
  const newHeaders = new Headers(res.headers);
  newHeaders.delete('x-cos-request-id');
  newHeaders.delete('x-cos-hash-crc64ecma');
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: newHeaders });
}

// ---- 页面（全部 ASCII：中文/emoji 用 HTML 实体，免疫粘贴编码问题）----
function browseLoginHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>&#x767B;&#x5F55; - COS &#x6587;&#x4EF6;&#x6D4F;&#x89C8;</title>
<style>
body{font-family:system-ui,-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;background:#f5f6f8;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#fff;border-radius:12px;padding:32px;width:min(90vw,340px);box-shadow:0 4px 24px rgba(0,0,0,.08)}
h1{font-size:18px;margin:0 0 20px;text-align:center;color:#1a1a2e}
input{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #ddd;border-radius:8px;margin-bottom:14px;font-size:15px}
button{width:100%;padding:11px;border:0;border-radius:8px;background:#3b82f6;color:#fff;font-size:15px;cursor:pointer}
</style></head><body>
<div class="card"><h1>&#x1F510; COS &#x6587;&#x4EF6;&#x6D4F;&#x89C8;</h1>
<form method="post" action="/browse/login"><input type="password" name="p" placeholder="&#x8BBF;&#x95EE;&#x5BC6;&#x7801;" required autofocus><button type="submit">&#x767B; &#x5F55;</button></form>
</div></body></html>`;
}

function browseIndexHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>COS &#x6587;&#x4EF6;&#x6D4F;&#x89C8;</title>
<style>
body{font-family:system-ui,-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;background:#f5f6f8;margin:0;color:#1a1a2e}
header{position:sticky;top:0;background:#1a1a2e;color:#fff;padding:12px 16px;display:flex;align-items:center;justify-content:space-between;z-index:10}
header h1{font-size:16px;margin:0}
#crumbs{padding:10px 16px;font-size:14px;background:#fff;border-bottom:1px solid #eee;overflow-x:auto;white-space:nowrap;position:sticky;top:49px;z-index:9}
#crumbs a,#crumbs .crumb{color:#3b82f6;text-decoration:none;margin-right:6px;cursor:pointer}
#list{max-width:720px;margin:0 auto;padding:8px 12px 80px}
.row{display:flex;align-items:center;background:#fff;border-radius:10px;padding:12px;margin-bottom:8px;box-shadow:0 1px 4px rgba(0,0,0,.05);cursor:pointer}
.row .icon{font-size:22px;margin-right:12px;flex-shrink:0}
.row .name{flex:1;font-size:15px;word-break:break-all}
.row .meta{font-size:12px;color:#999;flex-shrink:0;margin-left:12px}
#loadmore{display:block;width:100%;padding:10px;border:1px solid #ddd;background:#fff;border-radius:10px;color:#3b82f6;font-size:14px;cursor:pointer}
#status{text-align:center;color:#999;font-size:13px;padding:24px}
footer{position:fixed;bottom:0;left:0;right:0;text-align:center;font-size:12px;color:#bbb;padding:8px;background:#fff}
</style></head><body>
<header><h1>&#x1F4C1; COS &#x6587;&#x4EF6;&#x6D4F;&#x89C8;</h1></header>
<div id="crumbs"></div>
<div id="list"><div id="status">&#x52A0;&#x8F7D;&#x4E2D;&#x2026;</div></div>
<footer>&#x53EA;&#x8BFB;&#x6D4F;&#x89C8; &#xB7; &#x7ECF; cos-exchange</footer>
<script>
let prefix = '';
let token = '';
let truncated = false;

const icons = {jpg:'&#x1F5BC;&#xFE0F;',jpeg:'&#x1F5BC;&#xFE0F;',png:'&#x1F5BC;&#xFE0F;',gif:'&#x1F5BC;&#xFE0F;',webp:'&#x1F5BC;&#xFE0F;',bmp:'&#x1F5BC;&#xFE0F;',pdf:'&#x1F4D5;',zip:'&#x1F5DC;&#xFE0F;',rar:'&#x1F5DC;&#xFE0F;',7z:'&#x1F5DC;&#xFE0F;',tar:'&#x1F5DC;&#xFE0F;',gz:'&#x1F5DC;&#xFE0F;',mp3:'&#x1F3B5;',wav:'&#x1F3B5;',flac:'&#x1F3B5;',mp4:'&#x1F3AC;',mkv:'&#x1F3AC;',mov:'&#x1F3AC;',avi:'&#x1F3AC;',doc:'&#x1F4C4;',docx:'&#x1F4C4;',xls:'&#x1F4CA;',xlsx:'&#x1F4CA;',ppt:'&#x1F4FD;&#xFE0F;',pptx:'&#x1F4FD;&#xFE0F;',txt:'&#x1F4C3;',md:'&#x1F4C3;',html:'&#x1F310;',exe:'&#x2699;&#xFE0F;',apk:'&#x1F4F1;'};
const ext = n => (n.split('.').pop() || '').toLowerCase();
const iconOf = n => icons[ext(n)] || '&#x1F4E6;';
const fmt = s => s < 1024 ? s+' B' : s < 1048576 ? (s/1024).toFixed(1)+' KB' : (s/1048576).toFixed(1)+' MB';

async function load(reset) {
  if (reset) { token = ''; truncated = false; }
  const q = new URLSearchParams({prefix});
  if (token) q.set('token', token);
  const box = document.getElementById('list');
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 15000);
    const res = await fetch('/browse/api/list?' + q, { signal: ctrl.signal });
    clearTimeout(timer);
    const data = await res.json();
    if (data.error) {
      box.innerHTML = '<div id="status">&#x52A0;&#x8F7D;&#x5931;&#x8D25;: ' + esc(data.error) + '</div>';
      return;
    }
    render(data);
  } catch (e) {
    box.innerHTML = '<div id="status">&#x52A0;&#x8F7D;&#x5931;&#x8D25;: ' + esc(String((e && e.message) || e)) + '</div>';
  }
}

function render(d) {
  const box = document.getElementById('list');
  const crumb = document.getElementById('crumbs');
  let html = '';
  if (prefix) html += '<div class="row" data-act="up"><span class="icon">&#x2B06;&#xFE0F;</span><span class="name">&#x8FD4;&#x56DE;&#x4E0A;&#x7EA7;</span></div>';
  for (const f of d.folders) {
    const name = f.slice(0, -1).split('/').pop();
    html += '<div class="row" data-act="open" data-key="' + escAttr(f) + '"><span class="icon">&#x1F4C1;</span><span class="name">' + esc(name) + '</span><span class="meta">&#x6587;&#x4EF6;&#x5939;</span></div>';
  }
  for (const f of d.files) {
    const name = f.key.split('/').pop();
    html += '<div class="row" data-act="dl" data-key="' + escAttr(f.key) + '"><span class="icon">' + iconOf(name) + '</span><span class="name">' + esc(name) + '</span><span class="meta">' + fmt(f.size) + '</span></div>';
  }
  if (d.truncated) html += '<button id="loadmore" onclick="more()">&#x52A0;&#x8F7D;&#x66F4;&#x591A;</button>';
  box.innerHTML = html || '<div id="status">&#xFF08;&#x7A7A;&#x76EE;&#x5F55;&#xFF09;</div>';

  box.onclick = (e) => {
    const row = e.target.closest('.row');
    if (!row) return;
    const act = row.dataset.act;
    const key = row.dataset.key || '';
    if (act === 'up') up();
    else if (act === 'open') open(key);
    else if (act === 'dl') dl(key);
  };

  const parts = prefix.split('/').filter(Boolean);
  let cr = '<span class="crumb" data-cr="">&#x6839;&#x76EE;&#x5F55;</span>';
  let acc = '';
  parts.forEach((p) => {
    acc += p + '/';
    cr += ' / <span class="crumb" data-cr="' + escAttr(acc) + '">' + esc(p) + '</span>';
  });
  crumb.innerHTML = cr;
  crumb.onclick = (e) => {
    const c = e.target.closest('.crumb');
    if (c) go(c.dataset.cr || '');
  };

  truncated = d.truncated;
  token = d.token || '';
}

const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/'/g,'&#39;').replace(/"/g,'&quot;');
const escAttr = s => String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;');
const go = p => { prefix = p; load(true); window.scrollTo(0,0); };
const up = () => { const parts = prefix.split('/').filter(Boolean); parts.pop(); prefix = parts.length ? parts.join('/') + '/' : ''; load(true); window.scrollTo(0,0); };
const open = p => { prefix = p; load(true); window.scrollTo(0,0); };
const dl = k => { window.location.href = '/browse/api/file?key=' + encodeURIComponent(k); };
const more = () => load(false);

load(true);
</script></body></html>`;
}




