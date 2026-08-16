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

