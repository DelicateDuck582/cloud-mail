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
      // 1.2 【临时网盘】/temp —— 独立密码（TEMP_PASS）+ 独立 KV
      //     普通密码登录（无 2FA），与只读网盘互不影响
      // =====================================================
      if (url.pathname === '/temp' || url.pathname.startsWith('/temp/')) {
        return await handleTemp(request, env, ctx);
      }

      // =====================================================
      // 1.3 【文件浏览器】/browse —— 个人只读网盘
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

      // /static/ 无签名（仅 Referer/Sec-Fetch，可被脚本伪造）：加 per-IP 限流，
      // 防攻击者用随机 static/* 路径刷 COS 回源（每个唯一路径都会打一次 COS）
      if (url.pathname.startsWith('/static/')) {
        const rlStatic = rateLimitCheck('static:' + clientIP(request), 120, 60000);
        if (rlStatic.limited) {
          return rateLimitResp(request, rlStatic, '静态资源', '每 IP 每分钟最多 120 次');
        }
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
      // 超时 10s + 429/5xx 重试一次（600ms 退避），与 /browse 下载路径行为一致，
      // 抵抗 COS 偶发限流/抖动（附件路径此前无重试，COS 抖动会直接 5xx）
      const fetchOrigin = async () => fetch(targetUrl.toString(), {
        method: request.method,
        headers: headersForFetch,
        signal: AbortSignal.timeout(10000),
      });
      let response;
      try {
        response = await fetchOrigin();
        if (response.status === 429 || response.status >= 500) {
          await new Promise(r => setTimeout(r, 600));
          response = await fetchOrigin();
        }
      } catch (err) {
        // 首次请求超时（AbortError）也重试一次
        try {
          await new Promise(r => setTimeout(r, 600));
          response = await fetchOrigin();
        } catch (err2) {
          throw err2;
        }
      }

      // 设置跨域 Header（只放行邮件域）并去除敏感头
      const newHeaders = new Headers(response.headers);
      newHeaders.set('Access-Control-Allow-Origin', 'https://mail.duckgame-play.top');
      newHeaders.delete('x-cos-request-id');
      newHeaders.delete('x-cos-hash-crc64ecma');
      newHeaders.set('X-Content-Type-Options', 'nosniff');

      // =====================================================
      // 7. 回源成功后写入 Cache API（按 path；内容哈希不变则无需重复回源）
      //    缓存的响应不带 s-maxage，避免 Cloudflare HTTP 缓存命中时绕过 Worker 验签
      // =====================================================
      if (response.status === 200 && request.method === 'GET') {
        // 附件 key 为内容哈希，文件不变则缓存内容永远有效；
        // TTL 设为 7 天，同文件最多每 7 天回源一次（文件被删除时最迟 7 天失效）
        // 只缓存 GET：HEAD 首次请求如果把空 body 写入缓存，会污染同路径的
        // GET 命中（Cache API 对 GET/HEAD 按同一 key 匹配）→ 附件下载/预览返回空内容
        newHeaders.set('Cache-Control', 'private, max-age=604800');
        const cacheResp = new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: newHeaders,
        });
        ctx.waitUntil(caches.default.put(cacheKey, cacheResp.clone()));
        return cacheResp;
      }

      // HEAD 且回源成功（200）：透传状态与响应头（无 body）。
      // 注意：不能落入下方「非 200」脱敏分支，否则 HEAD 会被改写成 404
      // （upstream>=500?502:404），使下载管理器 / 邮件客户端的 HEAD 预检误判文件不存在。
      if (response.status === 200 && request.method === 'HEAD') {
        return new Response(null, { status: 200, statusText: response.statusText, headers: newHeaders });
      }

      // 非 200：不缓存
      // - 206/3xx：透传（206 供未来 Range/内嵌媒体场景；3xx 如 COS 临时重定向）
      // - 4xx/5xx：不向客户端透传 COS 原始 XML（其含真实桶名/错误细节），统一脱敏
      const upstream = response.status;
      if (upstream === 206 || (upstream >= 300 && upstream < 400)) {
        return new Response(response.body, {
          status: upstream,
          statusText: response.statusText,
          headers: newHeaders,
        });
      }
      if (upstream === 429) {
        return new Response('Too Many Requests', { status: 429, headers: { 'Retry-After': '60', 'X-Content-Type-Options': 'nosniff' } });
      }
      return new Response(upstream >= 500 ? 'Upstream Error' : 'Not Found', {
        status: upstream >= 500 ? 502 : 404,
        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'X-Content-Type-Options': 'nosniff' },
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
export {
  verifySignature, hmacSha256Hex, timingSafeEqual,
  base32Encode, base32Decode, totpAt, verifyTotp,
  tempConfig, tempList, tempPut, tempGet, tempDelete, tempUsage, tempUsageSet,
  authStore, tempStore,
};

// =====================================================================
// 【两步验证 2FA（TOTP）】+【KV 会话】+【临时网盘存储（KV 默认 / COS 预留）】
// ---------------------------------------------------------------------
// KV 绑定（两个命名空间各自独立，均可选；只绑一个时两个功能都能用）：
//   BROWSE_KV   只读网盘 /browse 的 2FA 密钥 + 登录会话（优先）
//   TEMP_KV     临时网盘 /temp 的文件存储（优先）
//   回退规则：authStore = BROWSE_KV || TEMP_KV；tempStore = TEMP_KV || BROWSE_KV
//   —— 两个都绑定：数据按命名空间分开；只绑一个：共用该命名空间（前缀隔离）
//
// 其他环境变量：
//   TEMP_PASS        临时网盘 /temp 独立访问密码（必填，普通密码登录，无 2FA）
//   TEMP_STORAGE     kv（默认）| cos（预留位，暂未启用）
//   TEMP_TOTAL_MB    临时文件「总容量」上限（默认 800，可取 1~900，单位 MiB）
//                    —— 只限总量：单文件大小、文件数量均不再设业务上限
//   TEMP_FILE_MAX_MB 单文件上限（默认 24，只能调小；KV 单值硬上限 25 MiB，属平台限制）
//   TEMP_TTL         临时文件保存秒数（默认 604800=7 天，60~2592000）
//   TOTP_ISSUER      验证器显示的发行方（默认 COS-Exchange）
//   TOTP_ACCOUNT     验证器显示的账户名（默认 cos-exchange）
//   SESSION_TTL      会话有效期秒数（默认 604800=7 天，3600~2592000）
//
// KV 键设计（命名空间内按前缀隔离）：
//   auth:totp   → {secret, at}   TOTP 密钥（Base32，仅服务端持有）
//   sess:<id>   → {at, ip}       只读网盘登录会话（expirationTtl 自动过期）
//   tmp/<id>    → 临时文件内容（metadata: {name,type,size,at}，到期自动删除）
//   tmp.__usage → {bytes,n,at}   总占用账本（不在 tmp/ 前缀内：用户接口读不到也删不掉）
// =====================================================================
function authStore(env) {
  if (!env) return null;
  return env.BROWSE_KV || env.TEMP_KV || null;
}

function tempStore(env) {
  if (!env) return null;
  return env.TEMP_KV || env.BROWSE_KV || null;
}

function jsonResp(obj, status, extraHeaders) {
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
  };
  if (extraHeaders) for (const k of Object.keys(extraHeaders)) headers[k] = extraHeaders[k];
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers,
  });
}

// 统一 429（限速）响应 —— 解决「点太快只看到 HTTP 429 / Too Many Requests」的问题：
//  - API 路径（含 /api/）→ JSON {error, retryAfter}，前端可读文案 + 可编程退避
//  - 页面/表单路径 → 纯文本中文（浏览器直接显示「请慢一点，等 N 秒」）
// 两者都带 Retry-After（秒），取自固定窗口的真实剩余时间（不再一律写 60）。
function rateLimitResp(request, info, what, detail) {
  const secs = Math.max(1, Math.ceil((info && info.retryAfter) || 60));
  let path = '';
  try { path = new URL(request.url).pathname; } catch (e) {}
  const msg = '操作太快了，请慢一点：' + (what || '请求') + '过于频繁，请在 ' + secs + ' 秒后重试'
    + (detail ? '（' + detail + '）' : '');
  if (path.indexOf('/api/') >= 0) {
    return jsonResp({ error: msg, retryAfter: secs }, 429, { 'Retry-After': String(secs) });
  }
  return new Response(msg, {
    status: 429,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Retry-After': String(secs),
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
    },
  });
}

// ---------- TOTP（RFC 6238：HMAC-SHA1 / 6 位 / 30 秒）----------
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(input) {
  const s = String(input || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of s) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error('bad base32');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

function randomBase32(byteLen) {
  const b = crypto.getRandomValues(new Uint8Array(byteLen || 20));
  return base32Encode(b);
}

async function totpAt(secret, counter) {
  const key = await crypto.subtle.importKey(
    'raw',
    base32Decode(secret),
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  const msg = new ArrayBuffer(8);
  const dv = new DataView(msg);
  dv.setUint32(0, Math.floor(counter / 0x100000000) >>> 0);
  dv.setUint32(4, counter >>> 0);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const off = sig[19] & 0x0f;
  const num = ((sig[off] & 0x7f) << 24) | (sig[off + 1] << 16) | (sig[off + 2] << 8) | sig[off + 3];
  return String(num % 1000000).padStart(6, '0');
}

// 校验 TOTP：允许前后各 1 个时间窗（时钟漂移 ±30 秒）
async function verifyTotp(secret, code, nowSec) {
  const c = String(code || '').replace(/\s/g, '');
  if (!/^[0-9]{6}$/.test(c)) return false;
  const now = Number.isFinite(nowSec) ? nowSec : Math.floor(Date.now() / 1000);
  const counter = Math.floor(now / 30);
  for (const d of [-1, 0, 1]) {
    if (timingSafeEqual(await totpAt(secret, counter + d), c)) return true;
  }
  return false;
}

function otpauthUri(env, secret) {
  const issuer = (env.TOTP_ISSUER || 'COS-Exchange').trim() || 'COS-Exchange';
  const account = (env.TOTP_ACCOUNT || 'cos-exchange').trim() || 'cos-exchange';
  return 'otpauth://totp/' + encodeURIComponent(issuer + ':' + account) +
    '?secret=' + secret + '&issuer=' + encodeURIComponent(issuer) +
    '&algorithm=SHA1&digits=6&period=30';
}

async function getTotp(env, strict) {
  const store = authStore(env);
  if (!store) return null;
  try {
    const v = await store.get('auth:totp', { type: 'json' });
    return v && v.secret ? v : null;
  } catch (e) {
    // strict=true（登录等安全关键路径）：KV 读取失败必须抛错，禁止「读不到就当作未绑定」
    // 否则 KV 抖动期间会退化为仅密码登录（2FA 被静默绕过）
    if (strict) throw e;
    return null;
  }
}

// 跨站 POST 防护（纵深防御，SameSite=Lax 之外再校验 Origin）：
// 浏览器跨站表单/脚本 POST 会带 Origin；无 Origin（curl/旧客户端）放行由 SameSite 兜底。
function sameSitePostOk(request) {
  const origin = request.headers.get('Origin');
  if (!origin) return true;
  let oh = '';
  try { oh = new URL(origin).hostname; } catch (e) { return false; }
  let rh = '';
  try { rh = new URL(request.url).hostname; } catch (e) {}
  return oh === rh || oh === 'mail.duckgame-play.top';
}

// ---------- 会话（KV 随机 token；未绑定 KV 时回退旧版密码指纹 cookie）----------
const SESSION_COOKIE = 'browse_sess';
const sessionCache = new Map(); // sid -> 校验缓存到期时间（毫秒），减少 KV 读取
const SESSION_CACHE_MS = 60 * 1000;

function sessionTtl(env) {
  let ttl = Number(env.SESSION_TTL || 604800);
  if (!Number.isFinite(ttl) || ttl < 3600) ttl = 604800;
  if (ttl > 2592000) ttl = 2592000;
  return Math.floor(ttl);
}

function cookieValue(request, name) {
  const cookies = (request.headers.get('Cookie') || '').split(';');
  for (const c of cookies) {
    const i = c.indexOf('=');
    if (i < 0) continue;
    if (c.slice(0, i).trim() === name) return c.slice(i + 1).trim();
  }
  return '';
}

async function createSession(env, request) {
  const store = authStore(env);
  if (!store) throw new Error('未绑定 KV');
  const sid = crypto.randomUUID();
  const ttl = sessionTtl(env);
  await store.put(
    'sess:' + sid,
    JSON.stringify({ at: Date.now(), ip: clientIP(request) }),
    { expirationTtl: ttl }
  );
  if (sessionCache.size > 500) sessionCache.clear();
  sessionCache.set(sid, Date.now() + SESSION_CACHE_MS);
  return { sid, ttl };
}

async function checkSession(env, sid) {
  if (!sid || !/^[0-9a-f-]{36}$/.test(sid)) return false;
  const store = authStore(env);
  if (!store) return false;
  const cached = sessionCache.get(sid);
  if (cached && cached > Date.now()) return true;
  try {
    const v = await store.get('sess:' + sid);
    if (!v) return false;
  } catch (e) {
    return false;
  }
  if (sessionCache.size > 500) sessionCache.clear();
  sessionCache.set(sid, Date.now() + SESSION_CACHE_MS);
  return true;
}

// ---------- 临时网盘存储（KV 默认；COS 预留位）----------
// 容量策略（2026-09-25 调整）：单文件大小与文件数量都不再设业务上限，
// 只校验「命名空间总占用」——免费额度 1 GB，默认只用 800 MiB（TEMP_TOTAL_MB），
// 余量留给 sess:/auth: 等其它键、键名与 metadata 计费、以及过期/删除清理的滞后。
function tempConfig(env) {
  let storage = String(env.TEMP_STORAGE || 'kv').trim().toLowerCase();
  if (storage !== 'cos') storage = 'kv';
  // 单文件：无业务上限，只受 KV 单值硬上限 25 MiB 约束（平台限制，无法绕过），默认留 1 MiB 余量
  let fmb = Number(env.TEMP_FILE_MAX_MB || 24);
  if (!Number.isFinite(fmb) || fmb < 1) fmb = 24;
  if (fmb > 24) fmb = 24;
  // 总容量上限：默认 800 MiB；可调 1~900（>900 会把 1 GB 免费额度顶满，故封顶）
  let tmb = Number(env.TEMP_TOTAL_MB || 800);
  if (!Number.isFinite(tmb) || tmb < 1) tmb = 800;
  if (tmb > 900) tmb = 900;
  let ttl = Number(env.TEMP_TTL || 604800);
  if (!Number.isFinite(ttl) || ttl < 60) ttl = 604800;
  if (ttl > 2592000) ttl = 2592000;
  // 调用速率（每 IP 每分钟）：上传默认 20（≈每 3 秒 1 个），/temp/api/* 合计默认 90，页面默认 60。
  // 前端会按 uploadPerMin 自动算出排队间隔（uploadGapMs），从源头避免撞 429。
  let upm = Number(env.TEMP_UPLOAD_PER_MIN || 20);
  if (!Number.isFinite(upm) || upm < 1) upm = 20;
  if (upm > 600) upm = 600;
  let apm = Number(env.TEMP_API_PER_MIN || 90);
  if (!Number.isFinite(apm) || apm < 5) apm = 90;
  if (apm > 3000) apm = 3000;
  let ppm = Number(env.TEMP_PAGE_PER_MIN || 60);
  if (!Number.isFinite(ppm) || ppm < 2) ppm = 60;
  if (ppm > 600) ppm = 600;
  return {
    storage,
    fileMaxMb: fmb,
    fileMaxBytes: Math.floor(fmb * 1024 * 1024),
    totalMb: tmb,
    totalBytes: Math.floor(tmb * 1024 * 1024),
    ttl: Math.floor(ttl),
    uploadPerMin: Math.floor(upm),
    apiPerMin: Math.floor(apm),
    pagePerMin: Math.floor(ppm),
    // 排队间隔：略大于 60s/次上限（+10% 余量），避免正好踩在窗口边界又被 429
    uploadGapMs: Math.ceil((60000 / upm) * 1.1),
  };
}

// ---------- 总占用账本（KV 无原子自增 → 「账本 + 全量校准」两层）----------
// 账本键 tmp.__usage：不是 tmp/ 前缀（list({prefix:'tmp/'}) 看不到），也不匹配
// TEMP_KEY_RE → 用户接口既读不到也删不掉。
// 账本允许「偏小」而绝不允许「偏大」（偏大会误拒上传），故：
//   1) 每次上传/删除都按「绝对值」写账本（避免丢增量后持续偏小）；
//   2) 预检发现「账本 + 本次 > 上限」时，先用 list() 全量校准再判（不会误拒）；
//   3) 列表接口用 list() 的结果顺手纠偏（0 额外 KV 操作）；
//   4) KV 限制「同一键 1 写/秒」，写账本失败只记日志（下次校准兜底）。
const TEMP_USAGE_KEY = 'tmp.__usage';
const TEMP_USAGE_TTL = 2592000;      // 账本 30 天不写就过期；读不到时用 list() 重建
const TEMP_USAGE_CACHE_MS = 5000;    // 单 isolate 内短缓存（按 KV 绑定对象区分）
const TEMP_USAGE_REPAIR_MS = 60000;  // 列表纠偏的最小写间隔（防列表轮询造成写放大）
let tempUsageCache = { store: null, at: 0, bytes: 0, n: 0, repairedAt: 0 };

async function tempUsageRead(env) {
  const store = tempStore(env);
  if (!store) return null;
  try {
    const u = await store.get(TEMP_USAGE_KEY, { type: 'json' });
    if (u && typeof u === 'object') {
      return {
        bytes: Math.max(0, Math.floor(Number(u.bytes) || 0)),
        n: Math.max(0, Math.floor(Number(u.n) || 0)),
      };
    }
  } catch (e) {}
  return null;
}

// 用 list() 汇总真实占用：每页最多 1000 个键且自带 metadata.size，
// 不读取任何文件内容，也不回源 COS。
async function tempUsageScan(env) {
  const store = tempStore(env);
  if (!store) return { bytes: 0, n: 0 };
  let bytes = 0, n = 0, cursor;
  for (let i = 0; i < 20; i++) {
    const page = await store.list({ prefix: 'tmp/', cursor, limit: 1000 });
    for (const k of (page.keys || [])) {
      bytes += Math.max(0, Number((k.metadata || {}).size) || 0);
      n++;
    }
    if (page.list_complete || !page.cursor) break;
    cursor = page.cursor;
  }
  return { bytes, n };
}

async function tempUsageWrite(env, bytes, n) {
  const store = tempStore(env);
  bytes = Math.max(0, Math.floor(bytes));
  n = Math.max(0, Math.floor(n));
  tempUsageCache = { store, at: Date.now(), bytes, n, repairedAt: Date.now() };
  if (!store) return;
  try {
    await store.put(TEMP_USAGE_KEY, JSON.stringify({ bytes, n, at: Date.now() }), { expirationTtl: TEMP_USAGE_TTL });
  } catch (e) {
    console.warn('temp usage ledger write failed'); // 账本偏小可由校准兜底，不影响本次上传
  }
}

// 当前占用：账本优先（5 秒缓存，按 KV 绑定对象区分 isolate/环境）；
// force=true 或账本不存在 → 用 list() 全量校准并落盘（准确性优先路径）。
async function tempUsage(env, force) {
  const cfg = tempConfig(env);
  const store = tempStore(env);
  const nowMs = Date.now();
  if (!store) return { bytes: 0, n: 0, total: cfg.totalBytes };
  if (!force && tempUsageCache.store === store && nowMs - tempUsageCache.at < TEMP_USAGE_CACHE_MS) {
    return { bytes: tempUsageCache.bytes, n: tempUsageCache.n, total: cfg.totalBytes };
  }
  let u = force ? null : await tempUsageRead(env);
  if (!u) {
    u = await tempUsageScan(env);
    await tempUsageWrite(env, u.bytes, u.n);
  } else {
    tempUsageCache = { store, at: nowMs, bytes: u.bytes, n: u.n, repairedAt: tempUsageCache.store === store ? tempUsageCache.repairedAt : 0 };
  }
  return { bytes: u.bytes, n: u.n, total: cfg.totalBytes };
}

// 记账（绝对值）：调用方按「已调整后的用量」传入
async function tempUsageSet(env, bytes, n) {
  await tempUsageWrite(env, bytes, n);
}

// 列表接口顺手纠偏：list() 已拿到全部 metadata，偏差较大时把账本写回真实值。
// 受 TEMP_USAGE_REPAIR_MS 节流，避免高频刷新触发 KV 写放大（免费额度 1000 写/天）。
async function tempUsageRepairFromList(env, sumBytes, count) {
  const store = tempStore(env);
  if (!store) return;
  const nowMs = Date.now();
  if (nowMs - tempUsageCache.repairedAt < TEMP_USAGE_REPAIR_MS) return;
  tempUsageCache.repairedAt = nowMs;
  const cfg = tempConfig(env);
  const known = tempUsageCache.store === store && tempUsageCache.at > 0;
  const diff = known ? Math.abs(tempUsageCache.bytes - sumBytes) : Infinity;
  const nearCap = sumBytes >= Math.floor(cfg.totalBytes * 0.9);
  if (!known || diff > 1024 * 1024 || (nearCap && diff > 65536) || (known && tempUsageCache.n !== count)) {
    await tempUsageWrite(env, sumBytes, count);
  }
}

// 临时文件键：服务端生成的键一律为小写（tmp/ + 36 进制时间戳 + 小写 hex）
// 故正则不加 i 标志：`TMP/x` 这类大小写变体直接判非法，避免"看似存在的键"歧义
const TEMP_KEY_RE = /^tmp\/[a-z0-9-]+$/;

function tempNewKey() {
  const b = crypto.getRandomValues(new Uint8Array(8));
  const id = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
  return 'tmp/' + Date.now().toString(36) + '-' + id;
}

function tempSafeName(name) {
  let n = String(name || 'file').replace(/[\u0000-\u001f\u007f]/g, '').replace(/[\\/]/g, '_').trim();
  if (!n) n = 'file';
  if (n.length > 120) n = n.slice(0, 120);
  return n;
}

// 文件类型（Content-Type）由客户端提供，可被构造成任意字符串：
//  - 含 CR/LF 会让 Headers.set('Content-Type', ...) 抛错（下载 500）、也属响应头注入面
//  - 超长值会撑爆 KV metadata（1KiB 上限）导致上传写入失败
// 故：剥离控制字符 → 限长 → 校验 type/subtype[;参数] 形态，非法一律回退 octet-stream。
// 写入（metadata）与读取（列表/下载回显）两侧都过一遍，兼容历史脏数据。
function tempSafeType(type) {
  let t = String(type || '').replace(/[\u0000-\u001f\u007f]/g, '').trim();
  if (t.length > 120) t = t.slice(0, 120);
  const re = /^[A-Za-z0-9][A-Za-z0-9.+-]*\/[A-Za-z0-9][A-Za-z0-9.+-]*(\s*;[\x20-\x7e]*)?$/;
  if (!re.test(t)) return 'application/octet-stream';
  return t;
}

function tempAsciiName(name) {
  const n = String(name || 'file').replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
  return n || 'file';
}

// 可安全 inline 展示的类型（HTML/SVG 强制下载，防存储型 XSS）
function tempInlineOk(type) {
  const t = String(type || '').toLowerCase().split(';')[0].trim();
  if (t === 'image/svg+xml') return false;
  if (t === 'application/pdf' || t === 'text/plain') return true;
  return t.indexOf('image/') === 0 || t.indexOf('video/') === 0 || t.indexOf('audio/') === 0;
}

// 受限 body 读取：没有 Content-Length（chunked 等）时用它包一层再交给 formData()，
// 一旦累计超过 maxBytes 立即中断 → 内存占用有界（不会把任意大的 body 读进 isolate）。
function tempLimitedBody(body, maxBytes, onTruncate) {
  let total = 0;
  const reader = body.getReader();
  return new ReadableStream({
    async pull(controller) {
      let r;
      try {
        r = await reader.read();
      } catch (e) {
        controller.error(e);
        return;
      }
      if (r.done) { controller.close(); return; }
      total += r.value.byteLength;
      if (total > maxBytes) {
        if (onTruncate) onTruncate();
        try { await reader.cancel(); } catch (e) {}
        controller.error(new Error('body too large'));
        return;
      }
      controller.enqueue(r.value);
    },
  });
}

async function tempList(env) {
  const cfg = tempConfig(env);
  if (cfg.storage === 'cos') return tempCosList(env); // 预留
  const store = tempStore(env);
  if (!store) return [];
  const out = [];
  let cursor;
  for (let i = 0; i < 10; i++) {
    const page = await store.list({ prefix: 'tmp/', cursor, limit: 1000 });
    for (const k of (page.keys || [])) {
      const m = k.metadata || {};
      out.push({
        key: k.name,
        name: m.name || k.name.split('/').pop(),
        type: tempSafeType(m.type || ''),
        size: Number(m.size) || 0,
        at: Number(m.at) || 0,
        expireAt: k.expiration ? k.expiration * 1000 : 0,
      });
    }
    if (page.list_complete || !page.cursor) break;
    cursor = page.cursor;
  }
  out.sort((a, b) => (b.at || 0) - (a.at || 0));
  return out;
}

async function tempPut(env, name, type, buf) {
  const cfg = tempConfig(env);
  type = tempSafeType(type);
  if (cfg.storage === 'cos') return tempCosPut(env, name, type, buf); // 预留
  const store = tempStore(env);
  if (!store) throw new Error('未绑定 KV（TEMP_KV / BROWSE_KV）');
  const key = tempNewKey();
  const at = Date.now();
  await store.put(key, buf, {
    expirationTtl: cfg.ttl,
    metadata: { name, type, size: buf.byteLength, at },
  });
  return { key, name, type, size: buf.byteLength, at, expireAt: at + cfg.ttl * 1000 };
}

async function tempGet(env, key) {
  const cfg = tempConfig(env);
  if (cfg.storage === 'cos') return tempCosGet(env, key); // 预留
  const store = tempStore(env);
  if (!store || !TEMP_KEY_RE.test(key || '')) return null;
  const obj = await store.getWithMetadata(key, { type: 'arrayBuffer' });
  if (!obj || !obj.value) return null;
  return { buf: obj.value, meta: obj.metadata || {} };
}

// KV 单键最长保留（秒）：与 TEMP_TTL 的内部上限一致（30 天），
// 续期不会把"临时"文件变成永久文件。
const TEMP_KEEP_MAX = 2592000;

// 续期：KV 没有 touch / 延期接口，只能「读回原值 → 用新的 expirationTtl 重写」
// （metadata 原样带回，name/type/size/at 不变）。
// 语义：从"当前到期时间"再延长一个保存期限（默认 7 天）；总保留上限 TEMP_KEEP_MAX。
// 返回 null 表示文件不存在 / 已过期。
async function tempRenew(env, key) {
  const cfg = tempConfig(env);
  if (cfg.storage === 'cos') throw tempCosNotReady(); // 预留位
  const store = tempStore(env);
  if (!store) throw new Error('未绑定 KV（TEMP_KV / BROWSE_KV）');
  if (!TEMP_KEY_RE.test(key || '')) throw new Error('bad key');

  const now = Date.now();
  const obj = await store.getWithMetadata(key, { type: 'arrayBuffer' });
  if (!obj || !obj.value) return null;

  // 当前到期时间：list({ prefix: key }) 会带上该键的 expiration（秒）。
  // 取不到（KV list 最终一致 / 旧数据）时按"从现在起"计算，等价于重置为一个完整期限。
  let baseMs = now;
  try {
    const page = await store.list({ prefix: key });
    const hit = (page.keys || []).find(x => x.name === key);
    if (hit && hit.expiration) baseMs = Math.max(now, hit.expiration * 1000);
  } catch (e) {}

  let remainSec = Math.ceil((baseMs + cfg.ttl * 1000 - now) / 1000);
  if (!Number.isFinite(remainSec) || remainSec < 60) remainSec = cfg.ttl;
  let capped = false;
  if (remainSec > TEMP_KEEP_MAX) { remainSec = TEMP_KEEP_MAX; capped = true; }

  await store.put(key, obj.value, { expirationTtl: remainSec, metadata: obj.metadata || {} });

  const meta = obj.metadata || {};
  return {
    added: Math.max(0, Math.floor((now + remainSec * 1000 - baseMs) / 1000)),
    capped,
    file: {
      key,
      name: tempSafeName(meta.name),
      type: tempSafeType(meta.type || ''),
      size: Number(meta.size) || (obj.value.byteLength || 0),
      at: Number(meta.at) || 0,
      expireAt: now + remainSec * 1000,
    },
  };
}

async function tempDelete(env, key) {
  const cfg = tempConfig(env);
  if (cfg.storage === 'cos') return tempCosDelete(env, key); // 预留
  const store = tempStore(env);
  if (!store) throw new Error('未绑定 KV（TEMP_KV / BROWSE_KV）');
  if (!TEMP_KEY_RE.test(key || '')) throw new Error('bad key');
  // 释放账本前先取回该键的 metadata.size（list 一次即可，不读文件内容）
  let size = 0, found = false;
  try {
    const page = await store.list({ prefix: key });
    const hit = (page.keys || []).find(x => x.name === key);
    if (hit) {
      found = true;
      size = Math.max(0, Number((hit.metadata || {}).size) || 0);
    }
  } catch (e) {}
  await store.delete(key);
  const used = await tempUsage(env, false);
  const next = Math.max(0, used.bytes - size);
  await tempUsageSet(env, next, Math.max(0, used.n - (found ? 1 : 0)));
  return { key, size, found, used: next, total: cfg.totalBytes };
}

// ---- 预留位：腾讯云 COS 临时存储（暂未启用）----
// 启用时需要的环境变量（与 /browse 只读子账号隔离，需读写权限）：
//   TEMP_COS_BUCKET / TEMP_COS_REGION / TEMP_COS_ENDPOINT / TEMP_COS_AK / TEMP_COS_SK
// 实现要求：对象键用 tmp/<id>；上传/下载/删除全部经本 Worker 鉴权，禁止直链。
function tempCosNotReady() {
  return Object.assign(new Error('COS 临时存储暂未启用（TEMP_STORAGE=cos 为预留位）'), { status: 501 });
}
/** @returns {never} */
function tempCosPut(env, name, type, buf) { throw tempCosNotReady(); }
/** @returns {never} */
function tempCosList(env) { throw tempCosNotReady(); }
/** @returns {never} */
function tempCosGet(env, key) { throw tempCosNotReady(); }
/** @returns {never} */
function tempCosDelete(env, key) { throw tempCosNotReady(); }


// =====================================================================
// 【临时网盘】/temp —— 独立于只读网盘 /browse 的临时文件存储
// ---------------------------------------------------------------------
//   - 独立密码 TEMP_PASS（普通密码登录，不使用 2FA）
//   - 独立 KV：TEMP_KV（未绑定时回退 BROWSE_KV）
//   - 独立 cookie（HMAC 指纹，密钥常量 cos-temp-cookie-fp-v1）
//   - 文件到期由 KV expirationTtl 自动删除
// =====================================================================
const TEMP_SESSION_COOKIE = 'temp_pwd';
let tempFpCachePass = '';
let tempFpCacheVal = '';

async function tempFingerprint(pass) {
  if (tempFpCachePass === pass && tempFpCacheVal) return tempFpCacheVal;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode('cos-temp-cookie-fp-v1'),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(pass));
  tempFpCachePass = pass;
  tempFpCacheVal = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  return tempFpCacheVal;
}

async function tempAuthed(request, env) {
  const pass = (env.TEMP_PASS || '').trim();
  if (!pass) return false;
  return timingSafeEqual(cookieValue(request, TEMP_SESSION_COOKIE), await tempFingerprint(pass));
}

async function tempLogin(request, env) {
  if (!sameSitePostOk(request)) {
    return new Response('Forbidden', { status: 403 });
  }
  const ip = 'temp:' + clientIP(request);
  if (loginBlocked(ip)) {
    return new Response('密码错误次数过多，请 10 分钟后再试（临时网盘登录已锁定）', {
      status: 429,
      headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Retry-After': '600', 'X-Content-Type-Options': 'nosniff' },
    });
  }
  const form = await request.formData();
  const p = String(form.get('p') || '');
  const pass = (env.TEMP_PASS || '').trim();
  if (pass && timingSafeEqual(p, pass)) {
    loginOk(ip);
    const fp = await tempFingerprint(pass);
    return new Response('', {
      status: 302,
      headers: {
        Location: '/temp',
        'Set-Cookie': TEMP_SESSION_COOKIE + '=' + fp + '; Path=/; Max-Age=604800; SameSite=Lax; HttpOnly; Secure',
      },
    });
  }
  // 登录失败：计数（同 IP 5 次/10 分钟锁定）+ 强制延迟 1 秒
  loginFailRecord(ip);
  await new Promise(r => setTimeout(r, 1000));
  return new Response('密码错误', {
    status: 401,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

async function handleTemp(request, env, ctx) {
  const url = new URL(request.url);

  // 跨站 POST 防护（纵深防御；SameSite=Lax 之外再校验 Origin）
  if (request.method === 'POST' && !sameSitePostOk(request)) {
    return new Response('Forbidden', { status: 403 });
  }

  // 国家/地区白名单（可选）：与 /browse 共用 BROWSE_ALLOW_COUNTRY
  const allowC = (env.BROWSE_ALLOW_COUNTRY || '').trim();
  if (allowC) {
    const c = (request.headers.get('CF-IPCountry') || '').toUpperCase();
    if (!allowC.toUpperCase().split(',').map(s => s.trim()).includes(c)) {
      return new Response('Forbidden', { status: 403 });
    }
  }

  // 全局速率护栏（每 IP，固定窗口 60 秒；放在密码门控之前 → 未登录也受限，防爆破/刷量）：
  //   /temp 页面 GET/HEAD  pagePerMin（默认 60）
  //   /temp/api/* 合计     apiPerMin （默认 90）
  // 命中时返回统一 429：API 走 JSON（含 retryAfter），页面走可读中文 + Retry-After。
  const tLim = tempConfig(env);
  if ((url.pathname === '/temp' || url.pathname === '/temp/') && (request.method === 'GET' || request.method === 'HEAD')) {
    const rlPage = rateLimitCheck('tpage:' + clientIP(request), tLim.pagePerMin, 60000);
    if (rlPage.limited) {
      return rateLimitResp(request, rlPage, '页面刷新', '每 IP 每分钟最多 ' + tLim.pagePerMin + ' 次');
    }
  }
  if (url.pathname.indexOf('/temp/api/') === 0) {
    const rlApi = rateLimitCheck('tapi:' + clientIP(request), tLim.apiPerMin, 60000);
    if (rlApi.limited) {
      return rateLimitResp(request, rlApi, '接口调用', '每 IP 每分钟最多 ' + tLim.apiPerMin + ' 次');
    }
  }

  // 登录（POST）
  if (request.method === 'POST' && url.pathname === '/temp/login') {
    return await tempLogin(request, env);
  }
  // 退出登录
  if (url.pathname === '/temp/logout') {
    return new Response('', {
      status: 302,
      headers: {
        Location: '/temp',
        'Set-Cookie': TEMP_SESSION_COOKIE + '=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly; Secure',
      },
    });
  }

  // POST 白名单：上传 / 删除 / 续期（其余一律 405）
  const isPostRoute = request.method === 'POST' && (
    url.pathname === '/temp/api/upload' || url.pathname === '/temp/api/delete' ||
    url.pathname === '/temp/api/renew'
  );
  if (request.method !== 'GET' && request.method !== 'HEAD' && !isPostRoute) {
    return new Response('Method Not Allowed', { status: 405 });
  }

  // 未配置 TEMP_PASS 或未绑定 KV：返回配置提示页（不暴露内部细节）
  const store = tempStore(env);
  const tempPass = (env.TEMP_PASS || '').trim();
  if (!store || !tempPass) {
    const reason = !tempPass
      ? '未配置环境变量 TEMP_PASS（临时网盘访问密码）。'
      : '未绑定 KV 命名空间（TEMP_KV 或 BROWSE_KV）。';
    return new Response(tempDisabledHtml(reason), {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Cache-Control': 'no-store' },
    });
  }

  // 密码门控（独立 cookie，无 2FA）
  if (!(await tempAuthed(request, env))) {
    return new Response(tempLoginHtml(env), {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Cache-Control': 'no-store' },
    });
  }

  // POST-only 接口：非 POST 一律 405（原先落到 404，HTTP 语义不精确）
  // 放在密码门控之后：未登录访问仍先看到登录页，不额外暴露接口面
  if ((url.pathname === '/temp/api/upload' ||
       url.pathname === '/temp/api/delete' ||
       url.pathname === '/temp/api/renew') && request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'POST' } });
  }

  // 首页
  if (url.pathname === '/temp' || url.pathname === '/temp/') {
    const tcfg = tempConfig(env);
    const usage = await tempUsage(env, false);
    const cfg = {
      tempStorage: tcfg.storage,
      tempFileMaxMb: tcfg.fileMaxMb,
      tempTotalMb: tcfg.totalMb,
      tempUsedBytes: usage.bytes,
      tempTtlSec: tcfg.ttl,
      tempUploadPerMin: tcfg.uploadPerMin,
      tempUploadGapMs: tcfg.uploadGapMs,
      kvName: env.TEMP_KV ? 'TEMP_KV' : 'BROWSE_KV',
    };
    return new Response(tempIndexHtml(cfg), {
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Cache-Control': 'no-store' },
    });
  }

  // 列表
  if (url.pathname === '/temp/api/list') {
    const rlList = rateLimitCheck('tlist:' + clientIP(request), 60, 60000);
    if (rlList.limited) {
      return rateLimitResp(request, rlList, '列表刷新', '每 IP 每分钟最多 60 次');
    }
    const tcfg = tempConfig(env);
    try {
      const files = await tempList(env);
      // 顺手用 list() 结果纠偏账本（0 额外 KV 操作；到期/已删文件会被扣回）
      let sum = 0;
      for (const f of files) sum += Math.max(0, Number(f.size) || 0);
      await tempUsageRepairFromList(env, sum, files.length);
      const usage = await tempUsage(env, false);
      return jsonResp({
        files, storage: tcfg.storage, ttl: tcfg.ttl,
        fileMaxMb: tcfg.fileMaxMb, totalMb: tcfg.totalMb,
        used: usage.bytes, total: tcfg.totalBytes, count: files.length,
        uploadPerMin: tcfg.uploadPerMin, uploadGapMs: tcfg.uploadGapMs,
      });
    } catch (e) {
      console.error('temp list error:', e);
      return jsonResp({ error: (e && e.message) || '临时存储读取失败', files: [] }, e && e.status === 501 ? 501 : 500);
    }
  }

  // 上传（multipart 字段 file）
  if (url.pathname === '/temp/api/upload' && request.method === 'POST') {
    const tcfg = tempConfig(env);
    const rlUp = rateLimitCheck('tup:' + clientIP(request), tcfg.uploadPerMin, 60000);
    if (rlUp.limited) {
      // 前端按 uploadPerMin 自动限速排队，正常不会撞到这里；撞到则给出等待秒数
      return rateLimitResp(request, rlUp, '上传', '每 IP 每分钟最多 ' + tcfg.uploadPerMin + ' 次');
    }
    if (tcfg.storage === 'cos') return jsonResp({ error: 'COS 临时存储暂未启用（预留位）' }, 501);

    // 单文件上限只来自 KV 平台硬限制（单值 25 MiB），不是业务策略
    const overhead = 8192; // multipart 边界/头部/其它字段的安全余量
    const formMaxBytes = tcfg.fileMaxBytes + overhead;
    const tooBigFile = () => jsonResp(
      { error: '单文件受 KV 平台硬上限限制（最大 ' + tcfg.fileMaxMb + ' MB）', fileMaxMb: tcfg.fileMaxMb }, 413);
    // 1) 能拿到 Content-Length 就按体积先拒（读 body 之前即拒，省流量也更安全）
    let clen = NaN;
    const clRaw = request.headers.get('Content-Length');
    if (clRaw !== null && Number.isFinite(Number(clRaw)) && Number(clRaw) >= 0) clen = Number(clRaw);
    if (Number.isFinite(clen) && clen > formMaxBytes) return tooBigFile();
    // 3) 总容量预检（在读取 body 之前先拒，避免白读大 body）。
    //    用「体积下界」（clen 减去 multipart 边框余量）比较：宁可放行后由精确检查拒绝，
    //    也不因 multipart 开销把「正好装满剩余容量」的文件误拒。
    const needLow = Math.max(0, clen - overhead);
    const tooBigTotal = (used) => jsonResp(
      { error: '存储空间不足：已用 ' + used + ' / 上限 ' + tcfg.totalBytes + ' 字节（可删除文件或等其到期自动释放）', used, total: tcfg.totalBytes }, 507);
    let usage = await tempUsage(env, false);
    if (usage.bytes + needLow > tcfg.totalBytes) {
      // 账本可能滞后（文件已过期未清理 / 并发丢增量）→ 强制全量校准后再判，避免误拒
      usage = await tempUsage(env, true);
      if (usage.bytes + needLow > tcfg.totalBytes) return tooBigTotal(usage.bytes);
    }
    let form;
    if (Number.isFinite(clen)) {
      try {
        form = await request.formData();
      } catch (e) {
        return jsonResp({ error: '上传内容解析失败' }, 400);
      }
    } else {
      // 2) 无 Content-Length（chunked/流式客户端）：包一层「受限 body」再解析，
      //    超过 formMaxBytes 立即中断 → 内存有界；精确体积仍由下面检查兜底。
      //    （本站页面 XHR 上传始终带 Content-Length，此分支只为兼容其它客户端）
      if (!request.body) return jsonResp({ error: '缺少 file 字段' }, 400);
      let truncated = false;
      try {
        const bounded = new Request(request.url, {
          method: 'POST',
          headers: request.headers,
          body: tempLimitedBody(request.body, formMaxBytes, () => { truncated = true; }),
          duplex: 'half',
        });
        form = await bounded.formData();
      } catch (e) {
        if (truncated) return tooBigFile();
        return jsonResp({ error: '上传内容解析失败' }, 400);
      }
    }
    const f = form.get('file');
    if (!f || typeof f === 'string' || typeof f.arrayBuffer !== 'function') {
      return jsonResp({ error: '缺少 file 字段' }, 400);
    }
    if (f.size > tcfg.fileMaxBytes) return tooBigFile();
    try {
      // 4) 拿到精确体积（multipart 头尾不计入）后再判一次总量
      if (usage.bytes + f.size > tcfg.totalBytes) {
        usage = await tempUsage(env, true);
        if (usage.bytes + f.size > tcfg.totalBytes) return tooBigTotal(usage.bytes);
      }
      const buf = await f.arrayBuffer();
      if (buf.byteLength > tcfg.fileMaxBytes) return tooBigFile();
      const name = tempSafeName(f.name);
      const type = tempSafeType(f.type);
      const item = await tempPut(env, name, type, buf);
      // 5) 记账：按绝对值写（偏小可由 list() 校准纠正；偏大会误拒上传）
      const used = usage.bytes + item.size;
      await tempUsageSet(env, used, usage.n + 1);
      return jsonResp({ ok: true, file: item, used, total: tcfg.totalBytes });
    } catch (e) {
      console.error('temp upload error:', e);
      return jsonResp({ error: (e && e.message) || '上传失败' }, e && e.status === 501 ? 501 : 500);
    }
  }

  // 下载/预览（?key=&dl=1）
  if (url.pathname === '/temp/api/file') {
    const rlGet = rateLimitCheck('tget:' + clientIP(request), 120, 60000);
    if (rlGet.limited) {
      return rateLimitResp(request, rlGet, '下载/预览', '每 IP 每分钟最多 120 次');
    }
    const key = url.searchParams.get('key') || '';
    let obj;
    try {
      obj = await tempGet(env, key);
    } catch (e) {
      return jsonResp({ error: (e && e.message) || '临时存储读取失败' }, e && e.status === 501 ? 501 : 500);
    }
    if (!obj) return new Response('Not Found', { status: 404 });
    const meta = obj.meta || {};
    const type = tempSafeType(meta.type || 'application/octet-stream');
    const name = tempSafeName(meta.name);
    const dl = url.searchParams.get('dl') === '1' || !tempInlineOk(type);
    const headers = new Headers();
    headers.set('Content-Type', type);
    headers.set('Content-Length', String(obj.buf.byteLength));
    headers.set('Content-Disposition', (dl ? 'attachment' : 'inline') + "; filename=\"" + tempAsciiName(name) + "\"; filename*=UTF-8''" + encodeURIComponent(name));
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('Cache-Control', 'private, max-age=300');
    return new Response(obj.buf, { status: 200, headers });
  }

  // 续期（字段 key）：每次 +一个保存期限（默认 7 天），总保留上限 30 天（TEMP_KEEP_MAX）
  if (url.pathname === '/temp/api/renew' && request.method === 'POST') {
    const rlRenew = rateLimitCheck('trenew:' + clientIP(request), 30, 60000);
    if (rlRenew.limited) {
      return rateLimitResp(request, rlRenew, '续期', '每 IP 每分钟最多 30 次');
    }
    const form = await request.formData();
    const key = String(form.get('key') || '');
    try {
      const r = await tempRenew(env, key);
      if (!r) return jsonResp({ error: '文件不存在或已过期' }, 404);
      return jsonResp({ ok: true, added: r.added, capped: r.capped, file: r.file });
    } catch (e) {
      console.error('temp renew error:', e);
      return jsonResp({ error: (e && e.message) || '续期失败' }, e && e.status === 501 ? 501 : 400);
    }
  }

  // 删除（字段 key）
  if (url.pathname === '/temp/api/delete' && request.method === 'POST') {
    const rlDel = rateLimitCheck('tdel:' + clientIP(request), 60, 60000);
    if (rlDel.limited) {
      return rateLimitResp(request, rlDel, '删除', '每 IP 每分钟最多 60 次');
    }
    const form = await request.formData();
    const key = String(form.get('key') || '');
    try {
      const r = await tempDelete(env, key);
      return jsonResp({ ok: true, used: r.used, total: r.total, size: r.size });
    } catch (e) {
      console.error('temp delete error:', e);
      return jsonResp({ error: (e && e.message) || '删除失败' }, e && e.status === 501 ? 501 : 400);
    }
  }

  return new Response('Not Found', { status: 404 });
}


// =====================================================================
// 【文件浏览器】/browse —— 个人只读网盘（请求全部经本 Worker，手机不直连 COS）
// ---------------------------------------------------------------------
// 需要：
//   env.BROWSE_PASS                访问密码（必设；未配置时 /browse 一律拒绝）
//   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / S3_ENDPOINT / REGION
//                                  复用上面的只读子账号（策略需含 GetObject + GetBucket）
// 说明：/browse 是独立密码门控的个人浏览入口，不参与附件签名体系
// =====================================================================
// =====================================================================
// COS 健康探测：COS 关闭/验证失败时，在登录界面/首页直接提示，
// 避免用户输入密码后才在文件列表看到报错。
// 带 30 秒缓存，避免每个页面请求都去打一次 COS。
// =====================================================================
let cosProbeCache = { at: 0, ok: true };
const COS_PROBE_WINDOW = 30 * 1000;

async function probeCosHealth(env) {
  const now = Date.now();
  if (now - cosProbeCache.at < COS_PROBE_WINDOW) return cosProbeCache.ok;
  cosProbeCache.at = now;
  try {
    // 复用列表接口做一次最小探测（MaxKeys=1），签名逻辑与浏览列表完全一致
    await browseList(env, '', '', 1);
    cosProbeCache.ok = true;
  } catch (e) {
    // 仅记录状态，不泄露 COS 排错细节（bucket 域名/签名中间值只在 browseList 的 throw 里）
    console.warn('cos-proxy: COS 探测失败，网盘暂时关闭服务');
    cosProbeCache.ok = false;
  }
  return cosProbeCache.ok;
}

// COS 不可用提示页（纯 ASCII，中文用 HTML 实体）
function cosDownHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>&#x670D;&#x52A1;&#x6682;&#x65F6;&#x4E0D;&#x53EF;&#x7528;</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { min-height:100vh; display:flex; align-items:center; justify-content:center; background:#f7f8fa; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,'PingFang SC','Microsoft YaHei',sans-serif; }
  .box { text-align:center; padding:48px 32px; background:#fff; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,.06); max-width:420px; }
  .box .icon { font-size:48px; }
  .box h1 { font-size:18px; color:#333; margin:16px 0 8px; font-weight:600; }
  .box p { font-size:13px; color:#888; }
</style>
</head>
<body>
  <div class="box">
    <div class="icon">&#x1F4E5;</div>
    <h1>COS&#x5BF9;&#x8C61;&#x5B58;&#x50A8;&#x9519;&#x8BEF;&#xFF0C;&#x6682;&#x65F6;&#x5173;&#x95ED;&#x670D;&#x52A1;</h1>
    <p>&#x8BF7;&#x7A0D;&#x540E;&#x518D;&#x8BD5;&#x6216;&#x8054;&#x7CFB;&#x7BA1;&#x7406;&#x5458;</p>
  </div>
</body>
</html>`;
}

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
  // 退出登录：会话/密码 cookie 都是 HttpOnly，前端 JS 的 document.cookie 无法删除，
  // 必须由服务端 Set-Cookie 清除，并删除 KV 会话（立即失效）。放在密码门控之前，
  // 保证已登录用户一定能退出；未登录访问也无害。
  if (url.pathname === '/browse/logout') {
    const sid = cookieValue(request, SESSION_COOKIE);
    if (sid && authStore(env)) {
      try { await authStore(env).delete('sess:' + sid); } catch (e) {}
      sessionCache.delete(sid);
    }
    const h = new Headers();
    h.set('Location', '/browse');
    h.append('Set-Cookie', SESSION_COOKIE + '=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly; Secure');
    h.append('Set-Cookie', 'browse_pwd=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly; Secure');
    return new Response('', { status: 302, headers: h });
  }
  // POST 白名单：仅 2FA 绑定/关闭（临时文件上传/删除已迁移到独立的 /temp）
  const isPostRoute = request.method === 'POST' && (
    url.pathname === '/browse/api/2fa/bind' ||
    url.pathname === '/browse/api/2fa/disable'
  );
  if (request.method !== 'GET' && request.method !== 'HEAD' && !isPostRoute) {
    return new Response('Method Not Allowed', { status: 405 });
  }

  // COS 健康探测：COS 关闭/错误时，登录界面与首页直接提示（30 秒缓存）
  // 仅对页面请求探测；/browse/api/* 由列表/下载接口自身报错兜底
  if (url.pathname === '/browse' || url.pathname === '/browse/') {
    const cosOk = await probeCosHealth(env);
    if (!cosOk) {
      return new Response(cosDownHtml(), {
        status: 503,
        headers: { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Cache-Control': 'no-store' },
      });
    }
  }

  // 密码门控：未配置 BROWSE_PASS 时直接拒绝，防止误配导致整桶裸奔
  if (!env.BROWSE_PASS || !(await browseAuthed(request, env))) {
    return new Response(await browseLoginHtml(env), {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Cache-Control': 'no-store' },
    });
  }

  // 首页（注入页面配置：2FA 状态、临时网盘入口）
  if (url.pathname === '/browse' || url.pathname === '/browse/') {
    const totp = await getTotp(env);
    const cfg = {
      kvBound: !!authStore(env),
      totpBound: !!totp,
      needs2faBind: !!authStore(env) && !totp,
      tempEnabled: !!(tempStore(env) && (env.TEMP_PASS || '').trim()),
    };
    return new Response(browseIndexHtml(cfg), {
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Cache-Control': 'no-store' },
    });
  }

  // =====================================================
  // 两步验证（2FA / TOTP）
  //   /browse/api/2fa/new     候选密钥（尚未生效，确认验证码后才写入 KV）
  //   /browse/api/2fa/bind    确认绑定（已绑定时需提供当前验证码 current）
  //   /browse/api/2fa/disable 关闭 2FA（需要当前验证码）
  // =====================================================
  if (url.pathname === '/browse/api/2fa/new') {
    if (!authStore(env)) return jsonResp({ error: '未绑定 KV（BROWSE_KV / TEMP_KV），无法使用 2FA' }, 501);
    const rl2fa = rateLimitCheck('2fa:' + clientIP(request), 20, 60000);
    if (rl2fa.limited) {
      return rateLimitResp(request, rl2fa, '2FA 校验', '每 IP 每分钟最多 20 次');
    }
    const secret = randomBase32(20);
    return jsonResp({ secret, otpauth: otpauthUri(env, secret), bound: !!(await getTotp(env)) });
  }

  if (url.pathname === '/browse/api/2fa/bind' && request.method === 'POST') {
    if (!sameSitePostOk(request)) return new Response('Forbidden', { status: 403 });
    if (!authStore(env)) return jsonResp({ error: '未绑定 KV（BROWSE_KV / TEMP_KV），无法使用 2FA' }, 501);
    const rlBind = rateLimitCheck('2fabind:' + clientIP(request), 10, 60000);
    if (rlBind.limited) {
      return rateLimitResp(request, rlBind, '2FA 绑定', '每 IP 每分钟最多 10 次');
    }
    const form = await request.formData();
    const secret = String(form.get('secret') || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
    const code = String(form.get('code') || '');
    const current = String(form.get('current') || '');
    if (!/^[A-Z2-7]{16,64}$/.test(secret)) return jsonResp({ error: '密钥格式不正确' }, 400);
    let bound = null;
    try {
      bound = await getTotp(env, true);
    } catch (e) {
      return jsonResp({ error: '服务暂时不可用，请稍后重试' }, 503);
    }
    if (bound && !(await verifyTotp(bound.secret, current))) {
      await new Promise(r => setTimeout(r, 600));
      return jsonResp({ error: '当前验证码错误' }, 401);
    }
    if (!(await verifyTotp(secret, code))) {
      await new Promise(r => setTimeout(r, 600));
      return jsonResp({ error: '验证码错误，请确认身份验证器时间准确后重试' }, 400);
    }
    await authStore(env).put('auth:totp', JSON.stringify({ secret, at: Date.now() }));
    return jsonResp({ ok: true });
  }

  if (url.pathname === '/browse/api/2fa/disable' && request.method === 'POST') {
    if (!sameSitePostOk(request)) return new Response('Forbidden', { status: 403 });
    if (!authStore(env)) return jsonResp({ error: '未绑定 KV' }, 501);
    const rlDis = rateLimitCheck('2fadisable:' + clientIP(request), 10, 60000);
    if (rlDis.limited) {
      return rateLimitResp(request, rlDis, '2FA 关闭', '每 IP 每分钟最多 10 次');
    }
    const form = await request.formData();
    const code = String(form.get('code') || '');
    let bound = null;
    try {
      bound = await getTotp(env, true);
    } catch (e) {
      return jsonResp({ error: '服务暂时不可用，请稍后重试' }, 503);
    }
    if (bound && !(await verifyTotp(bound.secret, code))) {
      await new Promise(r => setTimeout(r, 600));
      return jsonResp({ error: '当前验证码错误' }, 401);
    }
    await authStore(env).delete('auth:totp');
    return jsonResp({ ok: true });
  }

  // 列目录
  if (url.pathname === '/browse/api/list') {
    const rlBList = rateLimitCheck('list:' + clientIP(request), 40, 60000);
    if (rlBList.limited) {
      return rateLimitResp(request, rlBList, '目录列表', '每 IP 每分钟最多 40 次');
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
      // 魔数嗅探：对"扩展名无法识别"的文件读 COS 头部(0-15B)识别真实类型，
      // 解决无扩展名/伪扩展名内嵌图（如 063A2F5D_247B9635.D22C7B6A00000000 实为 JPEG）
      // 在查看器里无法显示的问题。只嗅探 oth 项，且带结果缓存避免重复请求 COS。
      await sniffUnknownTypes(env, data.files);
      return new Response(JSON.stringify(data), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' },
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
    const rlBFile = rateLimitCheck('file:' + clientIP(request), 120, 60000);
    if (rlBFile.limited) {
      return rateLimitResp(request, rlBFile, '文件读取', '每 IP 每分钟最多 120 次');
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

async function browseAuthed(request, env) {
  // 绑定 KV 后：只认 KV 会话（随机 token）。
  // 若继续接受旧版密码指纹 cookie，知道密码的人可自行算出 cookie 绕过 2FA。
  if (authStore(env)) {
    return await checkSession(env, cookieValue(request, SESSION_COOKIE));
  }
  // 未绑定 KV：回退旧版密码指纹 cookie（与升级前行为一致）
  const fingerprint = await browseFingerprint(env.BROWSE_PASS);
  return timingSafeEqual(cookieValue(request, 'browse_pwd'), fingerprint);
}

async function browseLogin(request, env) {
  if (!sameSitePostOk(request)) {
    return new Response('Forbidden', { status: 403 });
  }
  const ip = clientIP(request);
  if (loginBlocked(ip)) {
    return new Response('密码错误次数过多，请 10 分钟后再试（网盘登录已锁定）', {
      status: 429,
      headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Retry-After': '600', 'X-Content-Type-Options': 'nosniff' },
    });
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
  const p = String(form.get('p') || '');
  // 恒定时间比较（timingSafeEqual 长度不同直接 false，只泄露长度）
  const passOk = !!env.BROWSE_PASS && timingSafeEqual(p, env.BROWSE_PASS);
  // 2FA：绑定后必须同时校验动态验证码。
  // 失败信息不区分「密码错误 / 验证码错误」，避免账号密码被探测。
  // getTotp 用 strict：KV 读取失败 → 503 拒绝登录（fail-closed），不得退化为仅密码登录。
  let totpOk = true;
  if (passOk) {
    let totp = null;
    try {
      totp = await getTotp(env, true);
    } catch (e) {
      console.error('2FA 读取失败（KV 异常），拒绝登录:', e);
      return new Response('服务暂时不可用，请稍后重试', {
        status: 503,
        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Retry-After': '30' },
      });
    }
    if (totp) totpOk = await verifyTotp(totp.secret, form.get('code') || '');
  }
  if (passOk && totpOk) {
    loginOk(ip);
    // 绑定 KV：签发随机会话（KV 存储 + HttpOnly cookie）
    if (authStore(env)) {
      const { sid, ttl } = await createSession(env, request);
      return new Response('', {
        status: 302,
        headers: {
          Location: '/browse',
          'Set-Cookie': SESSION_COOKIE + '=' + sid + '; Path=/; Max-Age=' + ttl + '; SameSite=Lax; HttpOnly; Secure',
        },
      });
    }
    // 未绑定 KV：回退旧版密码指纹 cookie
    const fp = await browseFingerprint(env.BROWSE_PASS);
    return new Response('', {
      status: 302,
      headers: {
        Location: '/browse',
        'Set-Cookie': 'browse_pwd=' + fp + '; Path=/; Max-Age=604800; SameSite=Lax; HttpOnly; Secure',
      },
    });
  }
  // 登录失败：计数（同 IP 5 次/10 分钟锁定）+ 强制延迟 1 秒
  loginFailRecord(ip);
  await new Promise(r => setTimeout(r, 1000));
  return new Response('密码或动态验证码错误', {
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

// ---- per-IP 速率限制（内存实现；配合 CF 边缘 Rate Limiting 更稳）----
// 固定窗口：窗口自「该 key 的首次请求」起算；返回剩余等待秒数供 Retry-After 使用
// （旧实现一律回 60 秒，可能比实际剩余时间更长，导致客户端白等）。
const rateMap = new Map();
function rateLimitCheck(key, max, windowMs) {
  if (rateMap.size > 5000) rateMap.clear();
  const now = Date.now();
  const rec = rateMap.get(key);
  if (!rec || now - rec.t > windowMs) {
    rateMap.set(key, { c: 1, t: now });
    return { limited: false, retryAfter: 0, remaining: Math.max(0, max - 1) };
  }
  rec.c++;
  if (rec.c > max) {
    return { limited: true, retryAfter: Math.max(1, Math.ceil((rec.t + windowMs - now) / 1000)), remaining: 0 };
  }
  return { limited: false, retryAfter: 0, remaining: Math.max(0, max - rec.c) };
}
function rateLimited(key, max, windowMs) {
  return rateLimitCheck(key, max, windowMs).limited;
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
  // 只信任 CF 注入的 CF-Connecting-IP：X-Forwarded-For 可被非 CF 直达请求伪造，
  // 用于绕过登录锁定/限流（生产全走 CF 无影响；直连 workers.dev 时更严格）。
  return request.headers.get('CF-Connecting-IP') || 'unknown';
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
    // 客户端只看到状态码；COS 原始 XML（可能含 <Resource> 桶域名）与两侧
    // StringToSign 全部留在服务端日志，避免信息泄露给已登录用户
    throw new Error(JSON.stringify({
      error: `list failed ${res.status}`,
      cosBody: cos ? '' : body.slice(0, 300),
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

// =====================================================================
// 魔数嗅探：识别无扩展名/伪扩展名的图片等（读 COS 对象头 0-15 字节）
// 例：邮件内嵌图 key 形如 063A2F5D_247B9635.D22C7B6A00000000（无 .jpg 后缀）
//     —— mail web 靠 DB mimeType 可看，本查看器此前靠扩展名判定看不了。
// 仅对"扩展名无法归类"(type 会判为 oth)的文件嗅探；命中缓存避免重复请求。
// =====================================================================
const sniffCache = new Map();           // key -> { t: expireTs, type: 'img'|'vid'|'aud'|null }
const SNIFF_CACHE_TTL = 7 * 24 * 3600 * 1000; // 与文件缓存一致；COS key=内容哈希，类型恒定
const SNIFF_CACHE_MAX = 5000;           // 内存保护：超限时清空最旧一半，防长期运行无限增长
function sniffCacheSet(key, val) {
  sniffCache.set(key, val);
  if (sniffCache.size > SNIFF_CACHE_MAX) {
    const cutoff = Math.floor(SNIFF_CACHE_MAX / 2);
    let i = 0;
    for (const k of sniffCache.keys()) {
      if (i++ >= cutoff) break;
      sniffCache.delete(k);
    }
  }
}

// 由扩展名得到的"可信类型"：命中则无需嗅探（返回 null 表示不用管）
function extGuessType(name) {
  const e = String(name || '').split('.').pop().toLowerCase();
  const IMG = ['png','jpg','jpeg','gif','webp','bmp','svg','ico','heic','avif','jfif'];
  const VID = ['mp4','mkv','mov','avi','webm','m4v','wmv','flv','ts','3gp','rmvb'];
  const AUD = ['mp3','wav','flac','ogg','m4a','aac','opus','ape','amr'];
  if (IMG.includes(e)) return 'img';
  if (VID.includes(e)) return 'vid';
  if (AUD.includes(e)) return 'aud';
  return null; // 无法归类 -> 需要嗅探
}

// 前若干字节 -> 类型（魔数，与 mail-worker 魔数嗅探思路一致）
function sniffTypeFromBytes(buf) {
  if (!buf || buf.length < 12) return null;
  const b = new Uint8Array(buf);
  // JPEG: FF D8 FF
  if (b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) return 'img';
  // PNG: 89 50 4E 47
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47) return 'img';
  // GIF: 47 49 46 38
  if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) return 'img';
  // WEBP: RIFF....WEBP
  if (b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
      b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return 'img';
  // BMP: 42 4D
  if (b[0] === 0x42 && b[1] === 0x4D) return 'img';
  // AVIF/HEIC: ....ftyp(avif|heic|heix|hevc|mif1)
  if (b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70) {
    const brand = String.fromCharCode(b[8], b[9], b[10], b[11]).toLowerCase();
    if (['avif','heic','heix','hevc','mif1','msf1'].includes(brand)) return 'img';
  }
  // MP4/M4V 视频: ....ftyp(....)
  if (b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70) {
    const brand = String.fromCharCode(b[8], b[9], b[10], b[11]).toLowerCase();
    if (['mp42','mp41','isom','iso2','avc1','m4v ','dash'].includes(brand)) return 'vid';
  }
  // MP3: ID3 或 FF FB / FF F3 / FF F2
  if (b[0] === 0x49 && b[1] === 0x44 && b[2] === 0x33) return 'aud';
  if (b[0] === 0xFF && (b[1] === 0xFB || b[1] === 0xF3 || b[1] === 0xF2)) return 'aud';
  // FLAC: 66 4C 61 43
  if (b[0] === 0x66 && b[1] === 0x4C && b[2] === 0x61 && b[3] === 0x43) return 'aud';
  // OGG: 4F 67 67 53
  if (b[0] === 0x4F && b[1] === 0x67 && b[2] === 0x67 && b[3] === 0x53) return 'aud';
  return null;
}

// 对单个 COS 对象做 Range GET(0-15B) 读魔数
async function sniffOne(env, key) {
  const cached = sniffCache.get(key);
  if (cached && cached.t > Date.now()) return cached.type;
  if (cached && cached.type === null && cached.attempts > 3) return null; // 之前嗅探失败过，不再重复打 COS

  const rawEndpoint = (env.S3_ENDPOINT || '').trim().replace(/\/+$/, '');
  const region = (env.REGION || '').trim();
  const ak = (env.AWS_ACCESS_KEY_ID || '').trim();
  const sk = (env.AWS_SECRET_ACCESS_KEY || '').trim();
  const encodedPath = '/' + key.split('/').map(enc).join('/');
  const targetUrl = new URL(encodedPath, rawEndpoint);
  try {
    const signedHeaders = await getS3v4Headers({ method: 'GET', url: targetUrl, region, accessKeyId: ak, secretAccessKey: sk });
    const headersForFetch = { ...signedHeaders };
    delete headersForFetch['host'];
    delete headersForFetch['Host'];
    headersForFetch['Range'] = 'bytes=0-15';
    const res = await fetch(targetUrl.toString(), { method: 'GET', headers: headersForFetch, signal: AbortSignal.timeout(5000) });
    if (!res.ok || (res.status !== 200 && res.status !== 206)) {
      sniffCacheSet(key, { t: Date.now() + 3600000, type: null, attempts: (cached?.attempts || 0) + 1 });
      return null;
    }
    const ab = await res.arrayBuffer();
    const type = sniffTypeFromBytes(ab);
    sniffCacheSet(key, { t: Date.now() + SNIFF_CACHE_TTL, type, attempts: 0 });
    return type;
  } catch (e) {
    sniffCacheSet(key, { t: Date.now() + 3600000, type: null, attempts: (cached?.attempts || 0) + 1 });
    return null;
  }
}

// 只嗅探无法靠扩展名归类的文件；受限并发（同时 ≤4）+ 单次上限，避免瞬时打满 COS/超时
async function sniffUnknownTypes(env, files) {
  if (!files || files.length === 0) return;
  const unknown = files.filter(f => f && f.key && !extGuessType(f.key.split('/').pop()));
  if (unknown.length === 0) return;
  const MAX_SNIFF = 24;   // 单次 list 最多嗅探 24 个（列表页已 ≥分页，防止极端目录拖慢响应）
  const pool = unknown.slice(0, MAX_SNIFF);
  let idx = 0;
  const worker = async () => {
    while (idx < pool.length) {
      const cur = idx++;
      const type = await sniffOne(env, pool[cur].key);
      if (type) pool[cur].type = type;
    }
  };
  await Promise.all([worker(), worker(), worker(), worker()]);
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
    newHeaders.set('Cache-Control', 'private, max-age=604800');
    const cacheResp = new Response(final.body, { status: final.status, statusText: final.statusText, headers: newHeaders });
    ctx.waitUntil(caches.default.put(cacheKey, cacheResp.clone()));
    return cacheResp;
  }
  return new Response(final.body, { status: final.status, statusText: final.statusText, headers: newHeaders });
}

// ---- 页面（全部 ASCII：中文/emoji 用 HTML 实体，免疫粘贴编码问题）----

// ===== BROWSE-PAGES-START =====
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
// 新增（2026-09）：
//   - 两步验证 2FA（TOTP）：首次登录主动弹出绑定提示；绑定后登录需
//     「访问密码 + 动态验证码」；侧栏「安全」可重新绑定/关闭。
//   - 临时网盘已拆分为独立入口 /temp（独立密码 TEMP_PASS、独立 KV、
//     普通密码登录无 2FA）；本页面仅在顶栏保留入口按钮。
//     临时网盘页面见本文件末尾 tempLoginHtml / tempIndexHtml。
// 实现方式：本文件由 _parts/ 分块拼接（_build-pages.mjs），再由
// _build-browse.mjs 合并进 cos-proxy-worker.js（原附件代理/签名/浏览后端
// 逻辑保持逐字节不变）。中文/emoji 由构建器转成 <script> 内 \uXXXX、
// 其余 HTML 实体，保证 served 页面纯 ASCII。手写模板时不要引入反引号
// 与 ${}（页面内声明的插值除外），也不要在内联 JS 里写反斜杠正则。
// =====================================================================
async function browseLoginHtml(env) {
  const sitekey = (env && env.TURNSTILE_SITEKEY) || '';
  const tsScript = sitekey ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' : '';
  const tsWidget = sitekey ? '<div class="cf-turnstile" data-sitekey="' + sitekey + '" data-callback="onTs"></div>' : '';
  const tsJs = sitekey ? '<script>function onTs(){var b=document.getElementById("loginBtn");if(b){b.disabled=false;}}</script>' : '';
  // 已绑定 2FA 时显示动态验证码输入框（服务端渲染，避免前端多一次请求）
  // 注意：必须用 authStore(env)（= BROWSE_KV || TEMP_KV）判断，不能只看 env.BROWSE_KV：
  // 只绑定 TEMP_KV 时 2FA 密钥也存在那里，若此处判为「未绑定」则不渲染验证码输入框，
  // 而服务端登录仍要求动态码 → 用户被永久锁在登录页。
  const bound = authStore(env) ? !!(await getTotp(env)) : false;
  const codeField = bound ? '<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="动态验证码" required>' : '';
  const subText = bound ? '已开启两步验证，请输入访问密码与动态验证码' : '输入访问密码以继续';
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
input[type=password],input[type=text]{width:100%;height:45px;border:1px solid #e4e7ec;border-radius:12px;padding:0 15px;font-size:15px;outline:none;background:#f7f8fa;margin-bottom:14px;color:var(--text);transition:border .15s,background .15s}
input[type=password]:focus,input[type=text]:focus{border-color:var(--primary);background:#fff}
body.dark input[type=password],body.dark input[type=text]{background:#232529;border-color:#2a2c30}
body.dark input[type=password]:focus,body.dark input[type=text]:focus{background:#232529}
.cf-turnstile{margin-bottom:14px;display:flex;justify-content:center}
button[type=submit]{width:100%;height:45px;border:0;border-radius:12px;background:var(--primary);color:#fff;font-size:16px;font-weight:bold;cursor:pointer;transition:background .15s,opacity .15s}
button[type=submit]:hover{background:#2B5CD9}
button[type=submit]:active{background:#1E40AF}
button[type=submit]:disabled{opacity:.5;cursor:not-allowed}
.err{min-height:20px;margin:10px 0 0;font-size:13px;color:#e5484d;line-height:20px}
.hint{margin-top:22px;font-size:11px;color:#b9bec6}
body.dark .hint{color:#626a78}
/* copyright link: keep original footer look (no blue, no underline) */
.cp{color:inherit;text-decoration:none;cursor:pointer}
.cp:link,.cp:visited{color:inherit;text-decoration:none}
.cp:hover,.cp:active{color:inherit;text-decoration:none}
.theme-btn{position:fixed;top:14px;right:14px;width:36px;height:36px;border:0;border-radius:10px;background:#fff;color:#1f2329;font-size:16px;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,.08)}
body.dark .theme-btn{background:#1b1d21;color:#e8eaed}
</style></head><body>
<button class="theme-btn" id="themeBtn" title="&#x4E3B;&#x9898;">&#x1F319;</button>
<div class="card">
  <svg class="logo" viewBox="0 0 24 24" fill="currentColor"><path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z"/></svg>
  <h1>COS &#x7F51;&#x76D8;</h1>
  <p class="sub">${subText}</p>
  <form method="post" action="/browse/login" id="loginForm">
    <input type="password" name="p" placeholder="&#x8BBF;&#x95EE;&#x5BC6;&#x7801;" required autofocus>
    ${codeField}
    ${tsWidget}
    <button type="submit" id="loginBtn"${sitekey ? ' disabled' : ''}>&#x767B;&#x5F55;</button>
  </form>
  <div class="err" id="loginErr"></div>
  <div class="hint">&#x53EA;&#x8BFB;&#x6D4F;&#x89C8; &middot; cos-exchange&nbsp;&nbsp;<a class="cp" href="https://github.com/DelicateDuck582/cloud-mail" target="_blank" rel="noopener noreferrer">&#xA9; 2026 DelicateDuck582</a></div>
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
function browseIndexHtml(cfg) {
  const cfgJson = JSON.stringify(cfg || {}).replace(/</g, '\\u003c');
  const tempBtnHtml = (cfg && cfg.tempEnabled)
    ? '<a class="iconbtn" href="/temp" title="临时网盘" style="text-decoration:none"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z"/></svg></a>'
    : '';
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
/* copyright link: keep original footer look (no blue, no underline) */
.cp{color:inherit;text-decoration:none;cursor:pointer}
.cp:link,.cp:visited{color:inherit;text-decoration:none}
.cp:hover,.cp:active{color:inherit;text-decoration:none}
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
.modal{position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:130;display:none;align-items:center;justify-content:center;padding:18px}
.modal.show{display:flex}
.modal-box{width:min(520px,94vw);max-height:88vh;overflow:auto;background:var(--card);border-radius:14px;box-shadow:var(--shadow);display:flex;flex-direction:column}
.modal-head{display:flex;align-items:center;gap:8px;padding:14px 16px;border-bottom:1px solid var(--line)}
.modal-title{flex:1;font-size:15px;font-weight:600}
.modal-body{padding:14px 16px;font-size:13px;color:var(--text)}
.modal-foot{display:flex;gap:8px;padding:12px 16px calc(12px + env(safe-area-inset-bottom));border-top:1px solid var(--line)}
.mstep{margin:0 0 12px;line-height:1.8;color:var(--sub)}
.mstep input{height:38px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--text);padding:0 10px;font-size:15px;outline:none;width:150px;letter-spacing:2px;margin-left:6px}
.mstep input:focus{border-color:var(--primary)}
.msecret{display:flex;align-items:center;gap:8px;margin:0 0 12px;flex-wrap:wrap}
.msecret code{flex:1;min-width:180px;background:var(--bg);border:1px dashed var(--line);border-radius:8px;padding:9px 10px;font-family:ui-monospace,Consolas,'Courier New',monospace;font-size:13px;word-break:break-all;user-select:all;color:var(--text)}
.muri{margin:0 0 12px;word-break:break-all;font-size:12px}
.muri a{color:var(--primary)}
.merr{min-height:18px;color:#e5484d;font-size:12px}
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
    ${tempBtnHtml}
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
    <div class="sb-item" data-nav="sec"><span class="sic">&#x1F512;</span><span>&#x5B89;&#x5168;</span></div>
    <div class="sb-foot">&#x53EA;&#x8BFB;&#x6D4F;&#x89C8; &middot; cos-exchange&nbsp;&nbsp;<a class="cp" href="https://github.com/DelicateDuck582/cloud-mail" target="_blank" rel="noopener noreferrer">&#xA9; 2026 DelicateDuck582</a></div>
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
    <footer class="footer">&#x53EA;&#x8BFB;&#x6D4F;&#x89C8; &middot; cos-exchange&nbsp;&nbsp;<a class="cp" href="https://github.com/DelicateDuck582/cloud-mail" target="_blank" rel="noopener noreferrer">&#xA9; 2026 DelicateDuck582</a></footer>
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
<div id="bindModal" class="modal">
  <div class="modal-box">
    <div class="modal-head"><span class="modal-title" id="bindTitle">&#x7ED1;&#x5B9A;&#x4E24;&#x6B65;&#x9A8C;&#x8BC1;&#xFF08;2FA&#xFF09;</span><button class="iconbtn" id="bindClose" type="button">&#x2715;</button></div>
    <div class="modal-body">
      <div class="mstep">1. &#x5728;&#x8EAB;&#x4EFD;&#x9A8C;&#x8BC1;&#x5668; App&#xFF08;Google Authenticator / Microsoft Authenticator / 1Password &#x7B49;&#xFF09;&#x4E2D;&#x6DFB;&#x52A0;&#x8D26;&#x6237;</div>
      <div class="msecret"><code id="bindSecret">&#x52A0;&#x8F7D;&#x4E2D;...</code><button class="btn" id="bindCopy" type="button">&#x590D;&#x5236;&#x5BC6;&#x94A5;</button></div>
      <div class="mstep">2. &#x4E5F;&#x53EF;&#x70B9;&#x51FB;&#x94FE;&#x63A5;&#x76F4;&#x63A5;&#x6DFB;&#x52A0;&#xFF1A;<a id="bindUri" href="#">otpauth &#x94FE;&#x63A5;</a></div>
      <div class="mstep" id="bindCurStep" style="display:none">&#x5F53;&#x524D;&#x52A8;&#x6001;&#x9A8C;&#x8BC1;&#x7801;&#xFF08;&#x539F;&#x7ED1;&#x5B9A;&#xFF09;&#xFF1A;<input id="bindCurrent" type="text" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="6 &#x4F4D;&#x6570;&#x5B57;"></div>
      <div class="mstep">&#x8F93;&#x5165; App &#x663E;&#x793A;&#x7684; 6 &#x4F4D;&#x9A8C;&#x8BC1;&#x7801;&#xFF1A;<input id="bindCode" type="text" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="6 &#x4F4D;&#x6570;&#x5B57;"></div>
      <div class="merr" id="bindErr"></div>
    </div>
    <div class="modal-foot">
      <button class="btn" id="bindLater" type="button">&#x7A0D;&#x540E;</button>
      <button class="btn primary" id="bindOk" type="button">&#x786E;&#x8BA4;&#x7ED1;&#x5B9A;</button>
    </div>
  </div>
</div>
<div id="secModal" class="modal">
  <div class="modal-box">
    <div class="modal-head"><span class="modal-title">&#x5B89;&#x5168;&#x8BBE;&#x7F6E;</span><button class="iconbtn" id="secClose" type="button">&#x2715;</button></div>
    <div class="modal-body">
      <div class="mstep">&#x4E24;&#x6B65;&#x9A8C;&#x8BC1;&#xFF08;2FA&#xFF09;&#xFF1A;<b id="secStatus">&#x672A;&#x7ED1;&#x5B9A;</b></div>
      <div class="mstep">&#x5F00;&#x542F;&#x540E;&#xFF0C;&#x767B;&#x5F55;&#x9700;&#x8981;&#x300C;&#x8BBF;&#x95EE;&#x5BC6;&#x7801; + &#x52A8;&#x6001;&#x9A8C;&#x8BC1;&#x7801;&#x300D;&#xFF1B;&#x52A8;&#x6001;&#x9A8C;&#x8BC1;&#x7801;&#x6BCF; 30 &#x79D2;&#x66F4;&#x65B0;&#x4E00;&#x6B21;&#x3002;</div>
      <div class="mstep" id="secCodeStep" style="display:none">&#x5F53;&#x524D;&#x52A8;&#x6001;&#x9A8C;&#x8BC1;&#x7801;&#xFF1A;<input id="secCode" type="text" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="6 &#x4F4D;&#x6570;&#x5B57;"></div>
      <div class="merr" id="secErr"></div>
    </div>
    <div class="modal-foot">
      <button class="btn" id="secDisable" type="button">&#x5173;&#x95ED; 2FA</button>
      <button class="btn primary" id="secBind" type="button">&#x7ED1;&#x5B9A; 2FA</button>
    </div>
  </div>
</div>
<div id="toast"></div>
<script>
var CFG=${cfgJson};
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
var typeOf=function(n,serverType){if(serverType){return serverType;}var e=ext(n);if(IMG.indexOf(e)>=0){return 'img';}if(VID.indexOf(e)>=0){return 'vid';}if(AUD.indexOf(e)>=0){return 'aud';}if(DOC.indexOf(e)>=0){return 'doc';}if(ARC.indexOf(e)>=0){return 'arc';}return 'oth';};
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
  return {key:f.key,name:n,size:f.size||0,mtime:f.mtime||'',type:typeOf(n,f.type)};
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
    if(n==='sec'){ updateSecUI(); openModal('secModal'); closeSidebar(); return; }
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
    closeModal('bindModal');
    closeModal('secModal');
    return;
  }
  if(e.key==='ArrowLeft'&&$('lightbox').classList.contains('show')){imgIdx=(imgIdx-1+imgs.length)%imgs.length;lbShow();}
  else if(e.key==='ArrowRight'&&$('lightbox').classList.contains('show')){imgIdx=(imgIdx+1)%imgs.length;lbShow();}
});
try{
  if(localStorage.getItem('browseDark')==='1'){document.body.classList.add('dark');$('themeBtn').innerHTML='&#x2600;&#xFE0F;';}
  view=localStorage.getItem('browseView')||'list';
}catch(e){}
// =====================================================================
// \\u4E24\\u6B65\\u9A8C\\u8BC1\\uFF082FA / TOTP\\uFF09\\u5F39\\u6846\\uFF1A\\u9996\\u6B21\\u767B\\u5F55\\u4E3B\\u52A8\\u63D0\\u793A\\u7ED1\\u5B9A\\uFF1B\\u300C\\u5B89\\u5168\\u300D\\u53EF\\u7BA1\\u7406
// =====================================================================
function openModal(id){var m=$(id);if(m){m.classList.add('show');}}
function closeModal(id){var m=$(id);if(m){m.classList.remove('show');}}
var bindSecretVal='';
function openBind(needCurrent){
  $('bindErr').innerHTML='';
  $('bindCode').value='';
  $('bindCurrent').value='';
  $('bindCurStep').style.display=needCurrent?'':'none';
  $('bindTitle').textContent=needCurrent?'\\u91CD\\u65B0\\u7ED1\\u5B9A\\u4E24\\u6B65\\u9A8C\\u8BC1\\uFF082FA\\uFF09':'\\u7ED1\\u5B9A\\u4E24\\u6B65\\u9A8C\\u8BC1\\uFF082FA\\uFF09';
  $('bindSecret').textContent='\\u52A0\\u8F7D\\u4E2D...';
  $('bindUri').setAttribute('href','#');
  bindSecretVal='';
  fetch('/browse/api/2fa/new')
  .then(function(r){return r.json();})
  .then(function(j){
    if(j&&j.secret){
      bindSecretVal=j.secret;
      $('bindSecret').textContent=j.secret.replace(/(.{4})/g,'$1 ').trim();
      $('bindUri').setAttribute('href',j.otpauth);
      $('bindUri').textContent='\\u70B9\\u51FB\\u6253\\u5F00 otpauth \\u94FE\\u63A5';
    }else{
      $('bindErr').innerHTML=(j&&j.error)||'\\u83B7\\u53D6\\u5BC6\\u94A5\\u5931\\u8D25';
    }
  })
  .catch(function(e){$('bindErr').innerHTML='\\u83B7\\u53D6\\u5BC6\\u94A5\\u5931\\u8D25\\uFF1A'+String((e&&e.message)||e);});
  openModal('bindModal');
}
$('bindCopy').onclick=function(){
  if(!bindSecretVal){return;}
  var s=bindSecretVal;
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(s).then(function(){toast('\\u5BC6\\u94A5\\u5DF2\\u590D\\u5236');},function(){toast('\\u590D\\u5236\\u5931\\u8D25\\uFF0C\\u8BF7\\u624B\\u52A8\\u9009\\u62E9');});
  }else{
    var ta=document.createElement('textarea');
    ta.value=s;
    document.body.appendChild(ta);
    ta.select();
    try{document.execCommand('copy');toast('\\u5BC6\\u94A5\\u5DF2\\u590D\\u5236');}catch(e){toast('\\u590D\\u5236\\u5931\\u8D25\\uFF0C\\u8BF7\\u624B\\u52A8\\u9009\\u62E9');}
    document.body.removeChild(ta);
  }
};
$('bindClose').onclick=function(){closeModal('bindModal');};
$('bindLater').onclick=function(){closeModal('bindModal');try{sessionStorage.setItem('skip2fa','1');}catch(e){}};
$('bindOk').onclick=function(){
  if(!bindSecretVal){return;}
  var code=$('bindCode').value.replace(/[^0-9]/g,'');
  var cur=$('bindCurrent').value.replace(/[^0-9]/g,'');
  if(code.length!==6){$('bindErr').innerHTML='\\u8BF7\\u8F93\\u5165 App \\u663E\\u793A\\u7684 6 \\u4F4D\\u9A8C\\u8BC1\\u7801';return;}
  var fd=new FormData();
  fd.append('secret',bindSecretVal);
  fd.append('code',code);
  if(CFG.totpBound){fd.append('current',cur);}
  $('bindOk').disabled=true;
  fetch('/browse/api/2fa/bind',{method:'POST',body:fd})
  .then(function(r){return r.json().then(function(j){return {s:r.status,j:j};});})
  .then(function(o){
    $('bindOk').disabled=false;
    if(o.s===200&&o.j&&o.j.ok){
      CFG.totpBound=true;
      CFG.needs2faBind=false;
      try{sessionStorage.removeItem('skip2fa');}catch(e){}
      updateSecUI();
      closeModal('bindModal');
      toast('\\u4E24\\u6B65\\u9A8C\\u8BC1\\u5DF2\\u5F00\\u542F');
    }else{
      $('bindErr').innerHTML=(o.j&&o.j.error)||('\\u7ED1\\u5B9A\\u5931\\u8D25 HTTP '+o.s);
    }
  })
  .catch(function(e){$('bindOk').disabled=false;$('bindErr').innerHTML='\\u7ED1\\u5B9A\\u5931\\u8D25\\uFF1A'+String((e&&e.message)||e);});
};
function updateSecUI(){
  $('secStatus').textContent=CFG.totpBound?'\\u5DF2\\u7ED1\\u5B9A':'\\u672A\\u7ED1\\u5B9A';
  $('secCodeStep').style.display=CFG.totpBound?'':'none';
  $('secBind').textContent=CFG.totpBound?'\\u91CD\\u65B0\\u7ED1\\u5B9A':'\\u7ED1\\u5B9A 2FA';
  $('secDisable').style.display=CFG.totpBound?'':'none';
}
$('secClose').onclick=function(){closeModal('secModal');};
$('secBind').onclick=function(){
  if(!CFG.kvBound){toast('\\u672A\\u7ED1\\u5B9A BROWSE_KV\\uFF0C\\u65E0\\u6CD5\\u4F7F\\u7528 2FA');return;}
  $('secErr').innerHTML='';
  if(CFG.totpBound){
    var c=$('secCode').value.replace(/[^0-9]/g,'');
    if(c.length!==6){$('secErr').innerHTML='\\u8BF7\\u5148\\u8F93\\u5165\\u5F53\\u524D 6 \\u4F4D\\u9A8C\\u8BC1\\u7801';return;}
  }
  openBind(CFG.totpBound);
  if(CFG.totpBound){$('bindCurrent').value=$('secCode').value.replace(/[^0-9]/g,'');}
};
$('secDisable').onclick=function(){
  var c=$('secCode').value.replace(/[^0-9]/g,'');
  if(c.length!==6){$('secErr').innerHTML='\\u8BF7\\u8F93\\u5165\\u5F53\\u524D 6 \\u4F4D\\u9A8C\\u8BC1\\u7801';return;}
  if(!window.confirm('\\u786E\\u5B9A\\u5173\\u95ED\\u4E24\\u6B65\\u9A8C\\u8BC1\\uFF1F')){return;}
  var fd=new FormData();
  fd.append('code',c);
  fetch('/browse/api/2fa/disable',{method:'POST',body:fd})
  .then(function(r){return r.json().then(function(j){return {s:r.status,j:j};});})
  .then(function(o){
    if(o.s===200&&o.j&&o.j.ok){
      CFG.totpBound=false;
      updateSecUI();
      $('secErr').innerHTML='';
      toast('\\u4E24\\u6B65\\u9A8C\\u8BC1\\u5DF2\\u5173\\u95ED');
    }else{
      $('secErr').innerHTML=(o.j&&o.j.error)||('\\u64CD\\u4F5C\\u5931\\u8D25 HTTP '+o.s);
    }
  })
  .catch(function(e){$('secErr').innerHTML='\\u64CD\\u4F5C\\u5931\\u8D25\\uFF1A'+String((e&&e.message)||e);});
};
// \\u9996\\u6B21\\u767B\\u5F55\\uFF08\\u5C1A\\u672A\\u7ED1\\u5B9A 2FA\\uFF09\\u4E3B\\u52A8\\u5F39\\u51FA\\u7ED1\\u5B9A\\u63D0\\u793A\\uFF1B\\u672C\\u6B21\\u4F1A\\u8BDD\\u70B9\\u8FC7\\u300C\\u7A0D\\u540E\\u300D\\u5219\\u4E0D\\u518D\\u6253\\u6270
if(CFG.needs2faBind){
  var skip2fa=false;
  try{skip2fa=sessionStorage.getItem('skip2fa')==='1';}catch(e){}
  if(!skip2fa){setTimeout(function(){openBind(false);},500);}
}
updateSecUI();
updateViewBtn();
load(true);
</script>
</body></html>`;
}
// =====================================================================
// 【临时网盘】/temp —— 独立于只读网盘 /browse 的临时文件存储
// ---------------------------------------------------------------------
//   - 独立密码 TEMP_PASS（普通密码登录，不使用 2FA）
//   - 独立 KV：TEMP_KV（未绑定时回退 BROWSE_KV）
//   - 文件到期由 KV expirationTtl 自动删除
//   - 未配置 TEMP_PASS 或未绑定 KV 时显示配置提示页
//   - 上传：右下角任务面板（仿 Alist）显示进度条/速度/日志，支持重试与取消；
//     上传成功后本地乐观并入列表（KV list 最终一致，避免数秒内看不到新文件）
// =====================================================================
function tempDisabledHtml(reason) {
  return `<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>&#x4E34;&#x65F6;&#x7F51;&#x76D8; &#xB7; &#x672A;&#x542F;&#x7528;</title>
<style>
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f7f8fa;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;color:#1f2329;padding:20px}
  .box{max-width:440px;background:#fff;border-radius:12px;box-shadow:0 10px 30px -5px rgba(0,0,0,.08);padding:36px 30px;text-align:center}
  .box h1{font-size:18px;margin:0 0 10px}
  .box p{font-size:13px;color:#7a828e;line-height:1.9;margin:0}
  .box code{background:#f7f8fa;border:1px solid rgba(0,0,0,.08);border-radius:6px;padding:1px 6px;font-family:ui-monospace,Consolas,monospace}
</style></head><body>
<div class="box">
  <h1>&#x4E34;&#x65F6;&#x7F51;&#x76D8;&#x672A;&#x542F;&#x7528;</h1>
  <p>${reason}<br>&#x8BF7;&#x5728; Worker &#x73AF;&#x5883;&#x53D8;&#x91CF;&#x4E2D;&#x914D;&#x7F6E; <code>TEMP_PASS</code>&#xFF0C;&#x5E76;&#x7ED1;&#x5B9A; KV &#x547D;&#x540D;&#x7A7A;&#x95F4; <code>TEMP_KV</code>&#xFF08;&#x6216; <code>BROWSE_KV</code>&#xFF09;&#x3002;</p>
</div>
</body></html>`;
}

function tempLoginHtml(env) {
  return `<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#1890ff">
<title>&#x767B;&#x5F55; &#xB7; &#x4E34;&#x65F6;&#x7F51;&#x76D8;</title>
<style>
:root{--primary:#1890ff;--text:#1f2329;--muted:#9aa0a8}
body.dark{--primary:#4d9fff;--text:#e8eaed;--muted:#6b7280}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;background:#f7f8fa;color:var(--text);display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;transition:background .2s,color .2s}
body.dark{background:#0f1013}
.card{width:min(92vw,360px);background:#fff;border-radius:12px;padding:36px 30px 26px;box-shadow:0 10px 30px -5px rgba(0,0,0,.08);text-align:center}
body.dark .card{background:#1b1d21;box-shadow:0 10px 30px -5px rgba(0,0,0,.5)}
.logo{width:52px;height:52px;margin:0 auto 12px;color:var(--primary)}
h1{font-size:21px;margin:0 0 6px;font-weight:700}
.sub{font-size:13px;color:var(--muted);margin:0 0 24px}
input[type=password]{width:100%;height:45px;border:1px solid #e4e7ec;border-radius:12px;padding:0 15px;font-size:15px;outline:none;background:#f7f8fa;margin-bottom:14px;color:var(--text);transition:border .15s,background .15s}
input[type=password]:focus{border-color:var(--primary);background:#fff}
body.dark input[type=password]{background:#232529;border-color:#2a2c30}
button[type=submit]{width:100%;height:45px;border:0;border-radius:12px;background:var(--primary);color:#fff;font-size:16px;font-weight:bold;cursor:pointer;transition:background .15s,opacity .15s}
button[type=submit]:hover{background:#147ad6}
button[type=submit]:disabled{opacity:.5;cursor:not-allowed}
.err{min-height:20px;margin:10px 0 0;font-size:13px;color:#e5484d;line-height:20px}
.hint{margin-top:22px;font-size:11px;color:#b9bec6}
body.dark .hint{color:#626a78}
/* copyright link: keep original footer look (no blue, no underline) */
.cp{color:inherit;text-decoration:none;cursor:pointer}
.cp:link,.cp:visited{color:inherit;text-decoration:none}
.cp:hover,.cp:active{color:inherit;text-decoration:none}
.theme-btn{position:fixed;top:14px;right:14px;width:36px;height:36px;border:0;border-radius:10px;background:#fff;color:#1f2329;font-size:16px;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,.08)}
body.dark .theme-btn{background:#1b1d21;color:#e8eaed}
</style></head><body>
<button class="theme-btn" id="themeBtn" title="&#x4E3B;&#x9898;">&#x1F319;</button>
<div class="card">
  <svg class="logo" viewBox="0 0 24 24" fill="currentColor"><path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z"/></svg>
  <h1>&#x4E34;&#x65F6;&#x7F51;&#x76D8;</h1>
  <p class="sub">&#x8F93;&#x5165;&#x8BBF;&#x95EE;&#x5BC6;&#x7801;&#x4EE5;&#x7EE7;&#x7EED;</p>
  <form method="post" action="/temp/login" id="loginForm">
    <input type="password" name="p" placeholder="&#x8BBF;&#x95EE;&#x5BC6;&#x7801;" required autofocus>
    <button type="submit" id="loginBtn">&#x767B;&#x5F55;</button>
  </form>
  <div class="err" id="loginErr"></div>
  <div class="hint">&#x4E34;&#x65F6;&#x6587;&#x4EF6; &middot; KV &#x5B58;&#x50A8; &middot; &#x5230;&#x671F;&#x81EA;&#x52A8;&#x5220;&#x9664;<br><a class="cp" href="https://github.com/DelicateDuck582/cloud-mail" target="_blank" rel="noopener noreferrer">&#xA9; 2026 DelicateDuck582</a></div>
</div>
<script>
var btn=document.getElementById('loginBtn');
var form=document.getElementById('loginForm');
var err=document.getElementById('loginErr');
var original=btn.textContent;
function setDark(d){
  document.body.classList.toggle('dark',d);
  try{ localStorage.setItem('tempDark',d?'1':'0'); }catch(e){}
  var b=document.getElementById('themeBtn');
  if(b){ b.innerHTML=d?'&#x2600;&#xFE0F;':'&#x1F319;'; }
}
try{
  var saved=localStorage.getItem('tempDark');
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
    if(r.redirected||(r.ok&&r.url.indexOf('/temp')>=0)){ window.location.href='/temp'; return null; }
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

function tempIndexHtml(cfg) {
  const cfgJson = JSON.stringify(cfg || {}).replace(/</g, '\\u003c');
  return `<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#1890ff">
<title>&#x4E34;&#x65F6;&#x7F51;&#x76D8;</title>
<style>
:root{--primary:#1890ff;--primary-weak:rgba(24,144,255,.15);--bg:#f7f8fa;--card:#ffffff;--text:#1f2329;--sub:#7a828e;--muted:#9aa0a8;--hover:rgba(132,133,141,0.18);--line:rgba(0,0,0,.08);--shadow:0 10px 30px -5px rgba(0,0,0,.08);--radius:12px}
body.dark{--primary:#4d9fff;--primary-weak:rgba(77,159,255,.15);--bg:#0f1013;--card:#1b1d21;--text:#e8eaed;--sub:#9aa0aa;--muted:#6b7280;--hover:rgba(255,255,255,.12);--line:rgba(255,255,255,.08);--shadow:0 10px 30px -5px rgba(0,0,0,.5)}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif,"Apple Color Emoji","Segoe UI Emoji","Segoe UI Symbol";background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased;transition:background .2s,color .2s}
button{font-family:inherit;color:var(--text);cursor:pointer}
.topbar{position:sticky;top:0;z-index:60;display:flex;align-items:center;height:60px;padding:0 12px;background:var(--bg);transition:background .2s}
.brand{display:flex;align-items:center;gap:10px;font-size:16px;font-weight:700;user-select:none;white-space:nowrap}
.brand .logo{width:30px;height:30px;color:var(--primary)}
.hright{display:flex;align-items:center;gap:8px;margin-left:auto}
.pill{display:inline-flex;align-items:center;gap:6px;height:34px;padding:0 12px;border:0;border-radius:8px;background:var(--primary-weak);color:var(--primary);font-size:14px;cursor:pointer;text-decoration:none;transition:background .15s}
.pill:hover{background:rgba(24,144,255,.25)}
body.dark .pill:hover{background:rgba(77,159,255,.25)}
.pill svg{width:16px;height:16px}
.iconbtn{width:34px;height:34px;border:0;border-radius:8px;background:transparent;color:var(--sub);font-size:16px;display:inline-flex;align-items:center;justify-content:center;text-decoration:none;transition:background .15s,color .15s}
.iconbtn:hover{background:var(--hover);color:var(--text)}
.iconbtn:active{transform:scale(.94)}
.iconbtn svg{width:18px;height:18px}
.layout{max-width:min(99%,980px);margin:0 auto;min-height:calc(100vh - 60px);padding:0 12px 30px}
.objcard{background:var(--card);border-radius:var(--radius);padding:10px;box-shadow:var(--shadow);transition:background .2s,box-shadow .2s}
.tmp-bar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:4px 2px 12px}
.btn{height:38px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--text);font-size:13px;display:inline-flex;align-items:center;justify-content:center;gap:5px;padding:0 14px;transition:background .15s}
.btn:hover{background:var(--hover)}
.btn.primary{background:var(--primary);border-color:var(--primary);color:#fff}
.btn.primary:hover{filter:brightness(1.06)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.tmp-hint{font-size:12px;color:var(--muted);line-height:1.6}
.lhead{display:flex;align-items:center;gap:8px;padding:8px 12px;color:var(--muted);font-size:14px;font-weight:700;border-bottom:1px solid var(--line)}
.lname{flex:1;min-width:0;display:flex;align-items:center;gap:10px;overflow:hidden;white-space:nowrap}
.lname .lic{flex-shrink:0;color:var(--primary);display:inline-flex}
.lname .lic svg{width:22px;height:22px}
.lname .lnm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lsize{width:28%;text-align:right;flex-shrink:0;color:var(--sub);font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.lmod{width:24%;text-align:right;flex-shrink:0;color:var(--muted);font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.lrow{display:flex;align-items:center;gap:8px;padding:10px 12px;border-radius:8px;transition:background .15s;animation:itemIn .2s ease}
.lrow:hover{background:var(--hover)}
@keyframes itemIn{from{opacity:0;transform:scale(.98)}to{opacity:1;transform:scale(1)}}
.tmp-act{width:106px;flex-shrink:0;display:flex;justify-content:flex-end;gap:6px}
.tmp-act-h{width:106px;flex-shrink:0}
.tmp-a{width:30px;height:30px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--sub);display:inline-flex;align-items:center;justify-content:center;font-size:13px;text-decoration:none;cursor:pointer}
.tmp-a:hover{border-color:var(--primary);color:var(--primary)}
.tmp-a:disabled{opacity:.5;cursor:not-allowed}
.status{display:flex;flex-direction:column;align-items:center;gap:12px;padding:46px 0;color:var(--muted);font-size:14px}
.spinner{width:26px;height:26px;border:3px solid var(--line);border-top-color:var(--primary);border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.footer{text-align:center;font-size:12px;color:var(--muted);padding:20px 0 6px}
/* copyright link: keep original footer look (no blue, no underline) */
.cp{color:inherit;text-decoration:none;cursor:pointer}
.cp:link,.cp:visited{color:inherit;text-decoration:none}
.cp:hover,.cp:active{color:inherit;text-decoration:none}
#toast{position:fixed;left:50%;bottom:26px;transform:translateX(-50%) translateY(20px);background:rgba(20,22,26,.92);color:#fff;padding:9px 16px;border-radius:10px;font-size:13px;opacity:0;pointer-events:none;transition:all .25s;z-index:200;max-width:86vw;text-align:center}
#toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
/* &#x4E0A;&#x4F20;&#x4EFB;&#x52A1;&#x9762;&#x677F;&#xFF08;&#x4EFF; Alist&#xFF1A;&#x53F3;&#x4E0B;&#x89D2;&#x5C0F;&#x6309;&#x94AE; + &#x8FDB;&#x5EA6;&#x6761;/&#x65E5;&#x5FD7;&#x9762;&#x677F;&#xFF09; */
.task-btn{position:fixed;right:18px;bottom:18px;width:46px;height:46px;border:0;border-radius:50%;background:var(--primary);color:#fff;display:flex;align-items:center;justify-content:center;box-shadow:0 6px 18px rgba(24,144,255,.35);cursor:pointer;z-index:95;transition:transform .15s,filter .15s}
.task-btn:hover{filter:brightness(1.06)}
.task-btn:active{transform:scale(.94)}
.task-btn svg{width:22px;height:22px}
.task-badge{position:absolute;top:-3px;right:-3px;min-width:18px;height:18px;border-radius:9px;background:#e5484d;color:#fff;font-size:11px;line-height:18px;text-align:center;padding:0 4px;box-sizing:border-box}
.task-panel{position:fixed;right:18px;bottom:74px;width:min(92vw,380px);max-height:min(72vh,540px);background:var(--card);border-radius:12px;box-shadow:0 12px 40px rgba(0,0,0,.18);z-index:94;display:none;flex-direction:column;overflow:hidden}
.task-panel.show{display:flex}
.tp-head{display:flex;align-items:center;gap:8px;padding:10px 12px;border-bottom:1px solid var(--line);flex-shrink:0}
.tp-title{flex:1;font-size:14px;font-weight:700}
.tp-mini{height:28px;padding:0 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--sub);font-size:12px;cursor:pointer}
.tp-mini:hover{border-color:var(--primary);color:var(--primary)}
.tp-tasks{overflow:auto;padding:6px 12px 8px;max-height:min(40vh,320px)}
.tp-empty{color:var(--muted);font-size:13px;text-align:center;padding:18px 0}
.tk{padding:8px 0;border-bottom:1px dashed var(--line)}
.tk:last-child{border-bottom:0}
.tk-top{display:flex;align-items:center;gap:8px;font-size:13px}
.tk-name{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tk-pct{color:var(--sub);font-size:12px;flex-shrink:0}
.tk-bar{height:6px;border-radius:3px;background:var(--hover);margin:6px 0 5px;overflow:hidden}
.tk-fill{height:100%;width:0;border-radius:3px;background:var(--primary);transition:width .15s}
.tk.done .tk-fill{background:#2ecc71}
.tk.err .tk-fill{background:#e5484d}
.tk-sub{display:flex;align-items:center;gap:8px;font-size:11px;color:var(--muted)}
.tk-state{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tk-size,.tk-speed{flex-shrink:0}
.tk-act{display:flex;gap:6px;flex-shrink:0}
.tk-abtn{height:24px;padding:0 8px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--sub);font-size:11px;cursor:pointer}
.tk-abtn:hover{border-color:var(--primary);color:var(--primary)}
.tp-log{flex-shrink:0;border-top:1px solid var(--line);padding:6px 12px 10px;max-height:130px;overflow:auto;font-size:11.5px;line-height:1.8;color:var(--sub);font-family:ui-monospace,Consolas,'Courier New',monospace}
.tp-log .lg{word-break:break-all}
.tp-log .lg .lg-t{color:var(--muted);margin-right:6px}
.tp-log .lg.err{color:#e5484d}
@media (max-width:760px){
  .lmod{display:none}
  .lsize{width:76px}
  .tmp-act,.tmp-act-h{width:96px}
  .tmp-hint{width:100%}
  .brand .bname{display:none}
  .task-btn{right:12px;bottom:12px}
  .task-panel{right:10px;bottom:66px;width:min(94vw,380px)}
}
</style></head><body>
<header class="topbar">
  <div class="brand">
    <svg class="logo" viewBox="0 0 24 24" fill="currentColor"><path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z"/></svg>
    <span class="bname">&#x4E34;&#x65F6;&#x7F51;&#x76D8;</span>
  </div>
  <div class="hright">
    <a class="pill" href="/browse" title="&#x53EA;&#x8BFB;&#x7F51;&#x76D8;">
      <svg viewBox="0 0 24 24" fill="currentColor"><path d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>
      <span>&#x53EA;&#x8BFB;&#x7F51;&#x76D8;</span>
    </a>
    <a class="iconbtn" href="https://mail.duckgame-play.top" title="&#x8FD4;&#x56DE;&#x90AE;&#x4EF6;">
      <svg viewBox="0 0 24 24" fill="currentColor"><path d="M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z"/></svg>
    </a>
    <button class="iconbtn" id="themeBtn" title="&#x4E3B;&#x9898;">&#x1F319;</button>
    <a class="iconbtn" href="/temp/logout" title="&#x9000;&#x51FA;">
      <svg viewBox="0 0 24 24" fill="currentColor"><path d="M10.09 15.59L11.5 17l5-5-5-5-1.41 1.41L12.67 11H3v2h9.67l-2.58 2.59zM19 3H5c-1.11 0-2 .9-2 2v4h2V5h14v14H5v-4H3v4c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2z"/></svg>
    </a>
  </div>
</header>
<div class="layout">
  <div class="objcard">
    <div class="tmp-bar">
      <button class="btn primary" id="tempUpBtn" type="button">&#x4E0A;&#x4F20;&#x6587;&#x4EF6;</button>
      <input type="file" id="tempFile" multiple style="display:none">
      <span class="tmp-hint" id="tmpHint"></span>
    </div>
    <div id="filelist"></div>
  </div>
  <footer class="footer">&#x4E34;&#x65F6;&#x6587;&#x4EF6; &middot; &#x5230;&#x671F;&#x81EA;&#x52A8;&#x5220;&#x9664; &middot; cos-exchange<br><a class="cp" href="https://github.com/DelicateDuck582/cloud-mail" target="_blank" rel="noopener noreferrer">&#xA9; 2026 DelicateDuck582</a></footer>
</div>
<button class="task-btn" id="taskBtn" type="button" title="&#x4E0A;&#x4F20;&#x4EFB;&#x52A1;&#x4E0E;&#x65E5;&#x5FD7;">
  <svg viewBox="0 0 24 24" fill="currentColor"><path d="M5 20h14v-2H5v2zM19 9h-4V3H9v6H5l7 7 7-7z"/></svg>
  <span class="task-badge" id="taskBadge" style="display:none">0</span>
</button>
<div class="task-panel" id="taskPanel">
  <div class="tp-head">
    <span class="tp-title">&#x4E0A;&#x4F20;&#x4EFB;&#x52A1;</span>
    <button class="tp-mini" id="taskClear" type="button">&#x6E05;&#x9664;&#x5DF2;&#x5B8C;&#x6210;</button>
    <button class="iconbtn" id="taskClose" type="button">&#x2715;</button>
  </div>
  <div class="tp-tasks" id="taskList"></div>
  <div class="tp-log" id="taskLog"></div>
</div>
<div id="toast"></div>
<script>
var CFG=${cfgJson};
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
var typeOf=function(n){var e=ext(n);if(IMG.indexOf(e)>=0){return 'img';}if(VID.indexOf(e)>=0){return 'vid';}if(AUD.indexOf(e)>=0){return 'aud';}if(DOC.indexOf(e)>=0){return 'doc';}if(ARC.indexOf(e)>=0){return 'arc';}return 'oth';};
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
  if(!t){return '-';}
  var d=new Date(t);
  if(isNaN(d.getTime())){return '-';}
  var p=function(x){return String(x).padStart(2,'0');};
  return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes())+':'+p(d.getSeconds());
};
function statusHtml(msg,spin){
  return '<div class="status">'+(spin?'<div class="spinner"></div>':'')+esc(msg)+'</div>';
}
var tempFiles=[];
var pendingFiles={};
var deletedKeys={};
var PENDING_MS=120000;
var PENDING_KEY='tempPending';
var MAX_PENDING=50;
var toastTimer=null;
// KV \\u7684 list() \\u662F\\u6700\\u7EC8\\u4E00\\u81F4\\u7684\\uFF08\\u5199\\u5165\\u540E\\u6570\\u79D2\\u5185\\u5217\\u8868\\u53EF\\u80FD\\u4ECD\\u770B\\u4E0D\\u5230\\u65B0\\u6587\\u4EF6\\uFF09\\u3002
// pendingFiles \\u8D1F\\u8D23\\u300C\\u4E0A\\u4F20\\u6210\\u529F\\u7ACB\\u5373\\u663E\\u793A\\u300D\\uFF0C\\u518D\\u843D\\u4E00\\u4EFD\\u5230 localStorage\\uFF1A
// \\u5237\\u65B0\\uFF08F5\\uFF09\\u540E\\u5185\\u5B58\\u4F1A\\u4E22\\uFF0C\\u9760\\u8FD9\\u4EFD\\u6301\\u4E45\\u5316\\u4FDD\\u8BC1\\u5237\\u65B0\\u540E\\u4E5F\\u80FD\\u7ACB\\u523B\\u770B\\u5230\\u3002
function loadPending(){
  try{
    var raw=localStorage.getItem(PENDING_KEY);
    if(!raw){return;}
    var obj=JSON.parse(raw);
    var now=Date.now(),n=0;
    for(var k in obj){
      var p=obj[k];
      if(p&&p.item&&p.until>now&&n<MAX_PENDING){pendingFiles[k]=p;n++;}
    }
  }catch(e){}
}
function savePending(){
  try{
    var ids=Object.keys(pendingFiles);
    ids.sort(function(a,b){return (pendingFiles[b].item.at||0)-(pendingFiles[a].item.at||0);});
    var out={};
    for(var i=0;i<ids.length&&i<MAX_PENDING;i++){out[ids[i]]=pendingFiles[ids[i]];}
    localStorage.setItem(PENDING_KEY,JSON.stringify(out));
  }catch(e){}
}
function toast(msg){
  var t=$('toast');
  t.textContent=msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer=setTimeout(function(){t.classList.remove('show');},1800);
}
function ttlText(sec){
  if(!sec||sec<60){return '\\u5230\\u671F\\u81EA\\u52A8\\u5220\\u9664';}
  if(sec>=86400){return Math.round(sec/86400)+' \\u5929';}
  if(sec>=3600){return Math.round(sec/3600)+' \\u5C0F\\u65F6';}
  return Math.round(sec/60)+' \\u5206\\u949F';
}
// \\u7EED\\u671F\\u4E00\\u6B21\\u7684\\u65F6\\u957F\\uFF08\\u5929\\uFF09\\uFF1A\\u6309 TEMP_TTL \\u8BA1\\u7B97\\uFF0C\\u7528\\u4E8E\\u6309\\u94AE title \\u4E0E\\u63D0\\u793A\\u6587\\u6848
function ttlDays(){
  return Math.max(1,Math.round((CFG.tempTtlSec||604800)/86400));
}
// KV \\u7684 list() \\u662F\\u6700\\u7EC8\\u4E00\\u81F4\\u7684\\uFF08\\u5199\\u5165\\u540E\\u6570\\u79D2\\u5185\\u5217\\u8868\\u53EF\\u80FD\\u8FD8\\u770B\\u4E0D\\u5230\\u65B0\\u6587\\u4EF6\\uFF09\\u3002
// \\u4E0A\\u4F20\\u6210\\u529F\\u540E\\u5148\\u628A\\u63A5\\u53E3\\u8FD4\\u56DE\\u7684\\u6587\\u4EF6\\u9879\\u672C\\u5730\\u5E76\\u5165\\u5217\\u8868\\uFF08pendingFiles\\uFF09\\uFF0C
// \\u540E\\u53F0\\u518D\\u591A\\u6B21\\u62C9\\u53D6\\u670D\\u52A1\\u7AEF\\u5217\\u8868\\u6821\\u51C6\\uFF0C\\u907F\\u514D\\u300C\\u4E0A\\u4F20\\u6210\\u529F\\u5374\\u770B\\u4E0D\\u5230\\u300D\\u3002
function mergeFiles(){
  var out=[],seen={},now=Date.now(),i,k;
  for(k in deletedKeys){if(deletedKeys[k]<now){delete deletedKeys[k];}}
  for(i=0;i<tempFiles.length;i++){
    var f=tempFiles[i];
    if(deletedKeys[f.key]&&deletedKeys[f.key]>now){continue;}
    seen[f.key]=1;
    out.push(f);
  }
  for(k in pendingFiles){
    var p=pendingFiles[k];
    if(!p||p.until<now){delete pendingFiles[k];continue;}
    if(seen[k]||(deletedKeys[k]&&deletedKeys[k]>now)){continue;}
    seen[k]=1;
    out.push(p.item);
  }
  out.sort(function(a,b){return (b.at||0)-(a.at||0);});
  return out;
}
function renderList(){
  var list=mergeFiles();
  var box=$('filelist');
  var h='';
  if(!list.length){
    h='<div class="status"><span style="font-size:34px">&#x1F4C1;</span>\\u6682\\u65E0\\u4E34\\u65F6\\u6587\\u4EF6</div>';
  }else{
    h='<div class="lhead"><div class="lname">\\u540D\\u79F0</div><div class="lsize">\\u5927\\u5C0F</div><div class="lmod">\\u5230\\u671F\\u65F6\\u95F4</div><div class="tmp-act-h"></div></div>';
    for(var i=0;i<list.length;i++){
      var f=list[i];
      h+='<div class="lrow">'
        +'<div class="lname"><span class="lic">'+icOf({name:f.name,type:typeOf(f.name)})+'</span><span class="lnm" title="'+esc(f.name)+'">'+esc(f.name)+'</span></div>'
        +'<div class="lsize">'+fmt(f.size)+'</div>'
        +'<div class="lmod">'+esc(fmtT(f.expireAt))+'</div>'
        +'<div class="tmp-act">'
        +'<button class="tmp-a" type="button" data-renew="'+esc(f.key)+'" title="\\u7EED\\u671F\\uFF08+'+ttlDays()+' \\u5929\\uFF09">&#x21BB;</button>'
        +'<a class="tmp-a" href="/temp/api/file?key='+encodeURIComponent(f.key)+'&dl=1" title="\\u4E0B\\u8F7D">&#x2B07;</a>'
        +'<button class="tmp-a" type="button" data-del="'+esc(f.key)+'" title="\\u5220\\u9664">&#x2715;</button>'
        +'</div></div>';
    }
  }
  box.innerHTML=h;
  box.onclick=function(e){
    var rn=e.target.closest('[data-renew]');
    if(rn){renewFile(rn.getAttribute('data-renew'),rn);return;}
    var d=e.target.closest('[data-del]');
    if(d){del(d.getAttribute('data-del'));}
  };
}
function refreshList(showErr){
  fetch('/temp/api/list',{cache:'no-store'})
  .then(function(r){return r.json();})
  .then(function(data){
    if(data&&data.error){
      if(showErr){$('filelist').innerHTML=statusHtml('\\u52A0\\u8F7D\\u5931\\u8D25: '+data.error,false);}
      return;
    }
    tempFiles=(data&&data.files)||[];
    // \\u670D\\u52A1\\u7AEF\\u8D26\\u672C\\u4E3A\\u51C6\\uFF1A\\u987A\\u624B\\u628A\\u672C\\u5730\\u5BB9\\u91CF\\u4F30\\u7B97\\u6821\\u51C6\\u56DE\\u771F\\u5B9E\\u503C
    if(data&&typeof data.used==='number'&&data.used>=0){usageUsed=data.used;}
    if(data&&typeof data.total==='number'&&data.total>0){usageTotal=data.total;}
    renderHint();
    // \\u670D\\u52A1\\u7AEF\\u5217\\u8868\\u5DF2\\u5305\\u542B\\u7684\\u9879\\u8BF4\\u660E KV \\u5DF2\\u4E00\\u81F4\\uFF1A\\u6E05\\u6389\\u5BF9\\u5E94 pending\\uFF08\\u907F\\u514D\\u957F\\u671F\\u9A7B\\u7559\\uFF09
    var pruned=false;
    for(var i=0;i<tempFiles.length;i++){
      var pk=tempFiles[i].key;
      if(pendingFiles[pk]){delete pendingFiles[pk];pruned=true;}
    }
    if(pruned){savePending();}
    renderList();
  })
  .catch(function(e){
    if(showErr){$('filelist').innerHTML=statusHtml('\\u52A0\\u8F7D\\u5931\\u8D25: '+String((e&&e.message)||e),false);}
  });
}
// ---- \\u5BB9\\u91CF\\u72B6\\u6001\\uFF1A\\u670D\\u52A1\\u7AEF\\u53EA\\u9650\\u300C\\u603B\\u5360\\u7528\\u300D\\uFF08\\u5355\\u6587\\u4EF6\\u5927\\u5C0F\\u4E0E\\u6587\\u4EF6\\u6570\\u91CF\\u90FD\\u4E0D\\u8BBE\\u4E0A\\u9650\\uFF09----
// usageUsed \\u521D\\u503C\\u6765\\u81EA\\u670D\\u52A1\\u7AEF\\u8D26\\u672C\\uFF08CFG.tempUsedBytes\\uFF09\\uFF0C\\u4E4B\\u540E\\u6BCF\\u6B21\\u5217\\u8868/\\u4E0A\\u4F20/\\u5220\\u9664\\u90FD\\u4F1A\\u6821\\u51C6
var usageUsed=Number(CFG.tempUsedBytes)||0;
var usageTotal=(Number(CFG.tempTotalMb)||800)*1024*1024;
function fmtUse(s){return (s>0?fmt(s):'0 B');}
function freeSpace(){return Math.max(0,usageTotal-usageUsed);}
// ---- \\u670D\\u52A1\\u7AEF\\u9650\\u901F\\uFF08\\u6BCF IP \\u6BCF\\u5206\\u949F\\uFF09\\uFF1A\\u4E0A\\u4F20\\u9ED8\\u8BA4 20 \\u6B21 \\u2192 \\u524D\\u7AEF\\u6309 uploadGapMs \\u6392\\u961F\\u653E\\u884C\\uFF0C
//      \\u4ECE\\u6E90\\u5934\\u907F\\u514D\\u300C\\u70B9\\u592A\\u5FEB\\u300D\\u649E 429\\uFF1B\\u670D\\u52A1\\u7AEF\\u4ECD\\u4F1A\\u515C\\u5E95\\uFF0C\\u5E76\\u4EE5 JSON \\u56DE {error, retryAfter}\\u3002
var UPLOAD_PER_MIN=Math.max(1,Number(CFG.tempUploadPerMin)||20);
var UPLOAD_GAP_MS=Math.max(1000,Number(CFG.tempUploadGapMs)||Math.ceil(60000/UPLOAD_PER_MIN*1.1));
var lastSendAt=0;
var gapLogged=false;
function renderHint(){
  var h=$('tmpHint');
  if(!h){return;}
  h.textContent='\\u6587\\u4EF6\\u5230\\u671F\\u81EA\\u52A8\\u5220\\u9664\\uFF08\\u4FDD\\u5B58 '+ttlText(CFG.tempTtlSec)+'\\uFF09 \\u00B7 \\u5355\\u6587\\u4EF6\\u4E0A\\u9650 '
    +CFG.tempFileMaxMb+' MB\\uFF08KV \\u5E73\\u53F0\\u786C\\u4E0A\\u9650\\uFF09 \\u00B7 \\u5DF2\\u7528 '+fmtUse(usageUsed)+' / '+fmtUse(usageTotal)
    +'\\uFF08\\u4F59 '+fmtUse(freeSpace())+'\\uFF09 \\u00B7 \\u4E0A\\u4F20\\u9650\\u901F '+UPLOAD_PER_MIN+' \\u6B21/\\u5206 \\u00B7 \\u5B58\\u50A8\\uFF1A'+CFG.kvName;
}
function render(){
  renderHint();
  if(CFG.tempStorage==='cos'){
    $('tempUpBtn').disabled=true;
    $('filelist').innerHTML=statusHtml('COS \\u4E34\\u65F6\\u5B58\\u50A8\\u4E3A\\u9884\\u7559\\u4F4D\\uFF0C\\u6682\\u672A\\u542F\\u7528\\uFF1B\\u8BF7\\u4F7F\\u7528 KV \\u5B58\\u50A8',false);
    return;
  }
  $('filelist').innerHTML=statusHtml('\\u52A0\\u8F7D\\u4E2D...',true);
  refreshList(true);
}
// =====================================================================
// \\u4E0A\\u4F20\\u4EFB\\u52A1\\u9762\\u677F\\uFF08\\u4EFF Alist\\uFF09\\uFF1A\\u53F3\\u4E0B\\u89D2\\u5C0F\\u6309\\u94AE \\u2192 \\u4EFB\\u52A1\\u8FDB\\u5EA6\\u6761 + \\u4E0A\\u4F20\\u65E5\\u5FD7
// \\u961F\\u5217\\u4E32\\u884C\\u4E0A\\u4F20\\uFF08\\u907F\\u514D\\u77AC\\u65F6\\u6253\\u6EE1 Worker \\u9650\\u6D41\\uFF09\\uFF0C429 \\u81EA\\u52A8\\u9000\\u907F\\u91CD\\u8BD5\\uFF0C\\u5931\\u8D25\\u53EF\\u624B\\u52A8\\u91CD\\u8BD5
// =====================================================================
var tasks=[];
var taskSeq=0;
var taskRunning=false;
var pumpTimer=null;
var taskRenderTimer=null;
var batchOk=0;
var batchFail=0;
var RETRY_DELAYS=[4000,12000,30000];
var MAX_LOG=200;
var reconcileTimer=null;
function taskLog(msg,isErr){
  var box=$('taskLog');
  if(!box){return;}
  var d=new Date();
  var p=function(x){return String(x).padStart(2,'0');};
  var row=document.createElement('div');
  row.className='lg'+(isErr?' err':'');
  row.innerHTML='<span class="lg-t">'+p(d.getHours())+':'+p(d.getMinutes())+':'+p(d.getSeconds())+'</span>'+esc(msg);
  box.appendChild(row);
  while(box.childNodes.length>MAX_LOG){box.removeChild(box.firstChild);}
  box.scrollTop=box.scrollHeight;
}
function openPanel(){$('taskPanel').classList.add('show');}
function closePanel(){$('taskPanel').classList.remove('show');}
function activeCount(){
  var n=0;
  for(var i=0;i<tasks.length;i++){
    var s=tasks[i].status;
    if(s==='wait'||s==='up'||s==='proc'){n++;}
  }
  return n;
}
function updateBadge(){
  var b=$('taskBadge');
  if(!b){return;}
  var n=activeCount();
  if(n>0){b.textContent=String(n);b.style.display='';}
  else{b.style.display='none';}
}
function taskStatusText(t){
  if(t.status==='wait'){return '\\u7B49\\u5F85\\u4E2D';}
  if(t.status==='up'){return '\\u4E0A\\u4F20\\u4E2D';}
  if(t.status==='proc'){return '\\u5904\\u7406\\u4E2D\\u2026';}
  if(t.status==='done'){return '\\u5DF2\\u5B8C\\u6210';}
  if(t.status==='fail'){return '\\u5931\\u8D25';}
  if(t.status==='cancel'){return '\\u5DF2\\u53D6\\u6D88';}
  return '';
}
function fmtSpeed(bps){
  if(!bps||bps<1){return '';}
  var n=1024;
  if(bps<n){return Math.round(bps)+' B/s';}
  if(bps<n*n){return (bps/n).toFixed(1)+' KB/s';}
  return (bps/(n*n)).toFixed(1)+' MB/s';
}
function renderTasks(){
  taskRenderTimer=null;
  var box=$('taskList');
  if(!box){return;}
  if(!tasks.length){box.innerHTML='<div class="tp-empty">\\u6682\\u65E0\\u4E0A\\u4F20\\u4EFB\\u52A1</div>';updateBadge();return;}
  var h='';
  var waiting=false;
  for(var i=0;i<tasks.length;i++){
    var t=tasks[i];
    var pct=0;
    if(t.status==='done'){pct=100;}
    else if(t.size>0){pct=Math.min(99,Math.floor(t.loaded*100/t.size));}
    var cls=t.status==='done'?' done':(t.status==='fail'?' err':'');
    var sub='<span class="tk-size">'+fmt(t.size)+'</span>';
    if(t.status==='up'&&t.speed){sub+='<span class="tk-speed">'+fmtSpeed(t.speed)+'</span>';}
    var stateText=taskStatusText(t);
    if(t.status==='wait'&&t.limitWait&&t.gapUntil>Date.now()){
      stateText='\\u9650\\u901F\\u7B49\\u5F85 '+Math.ceil((t.gapUntil-Date.now())/1000)+'s';
      waiting=true;
    }else if(t.status==='wait'&&t.nextAt>Date.now()){
      stateText='\\u7B49\\u5F85\\u91CD\\u8BD5 '+Math.ceil((t.nextAt-Date.now())/1000)+'s';
      waiting=true;
    }
    sub+='<span class="tk-state">'+esc(stateText)+(t.status==='fail'&&t.error?'\\uFF1A'+esc(t.error):'')+'</span>';
    var act='';
    if(t.status==='fail'||t.status==='cancel'){act='<button class="tk-abtn" type="button" data-retry="'+t.id+'">\\u91CD\\u8BD5</button>';}
    else if(t.status==='wait'||t.status==='up'){act='<button class="tk-abtn" type="button" data-cancel="'+t.id+'">\\u53D6\\u6D88</button>';}
    h+='<div class="tk'+cls+'">'
      +'<div class="tk-top"><span class="tk-name" title="'+esc(t.name)+'">'+esc(t.name)+'</span><span class="tk-pct">'+pct+'%</span></div>'
      +'<div class="tk-bar"><div class="tk-fill" style="width:'+pct+'%"></div></div>'
      +'<div class="tk-sub">'+sub+'<span class="tk-act">'+act+'</span></div>'
      +'</div>';
  }
  box.innerHTML=h;
  updateBadge();
  // \\u6709\\u4EFB\\u52A1\\u5728\\u7B49\\u5F85\\u91CD\\u8BD5\\u65F6\\uFF0C\\u6BCF\\u79D2\\u91CD\\u6E32\\u67D3\\u4E00\\u6B21\\u4EE5\\u5237\\u65B0\\u5012\\u8BA1\\u65F6
  if(waiting&&!taskRenderTimer){taskRenderTimer=setTimeout(renderTasks,1000);}
}
function scheduleTaskRender(){
  if(taskRenderTimer){return;}
  taskRenderTimer=setTimeout(renderTasks,120);
}
function findTask(id){
  for(var i=0;i<tasks.length;i++){if(tasks[i].id===id){return tasks[i];}}
  return null;
}
// \\u4EFB\\u52A1\\u5217\\u8868\\u4E0A\\u9650\\u4FDD\\u62A4\\uFF1A\\u8D85\\u9650\\u65F6\\u4E22\\u5F03\\u300C\\u6700\\u65E9\\u7684\\u5DF2\\u7ED3\\u675F\\u4EFB\\u52A1\\u300D\\u5E76\\u91CA\\u653E\\u5176 File \\u5F15\\u7528\\uFF08\\u957F\\u4F1A\\u8BDD\\u5185\\u5B58\\u4E0D\\u589E\\u957F\\uFF09
function trimTasks(){
  var MAX_TASKS=200;
  if(tasks.length<=MAX_TASKS){return;}
  var over=tasks.length-MAX_TASKS;
  var out=[],i;
  for(i=0;i<tasks.length;i++){
    var s=tasks[i].status;
    var active=(s==='wait'||s==='up'||s==='proc');
    if(!active&&over>0){over--;tasks[i].file=null;continue;}
    out.push(tasks[i]);
  }
  tasks=out;
}
function pumpTasks(){
  if(taskRunning){return;}
  var next=null,soonest=0,now=Date.now();
  for(var i=0;i<tasks.length;i++){
    var t=tasks[i];
    if(t.status!=='wait'){continue;}
    if(t.nextAt&&t.nextAt>now){if(!soonest||t.nextAt<soonest){soonest=t.nextAt;}continue;}
    next=t;
    break;
  }
  if(next){
    // \\u4E0A\\u4F20\\u8282\\u6D41\\uFF08\\u672C\\u8F6E\\u65B0\\u589E\\uFF09\\uFF1A\\u670D\\u52A1\\u7AEF\\u9650\\u5236\\u300C\\u6BCF IP \\u6BCF\\u5206\\u949F N \\u6B21\\u4E0A\\u4F20\\u300D\\uFF0C\\u961F\\u5217\\u6309\\u540C\\u4E00\\u8282\\u594F\\u653E\\u884C
    // \\uFF08\\u76F8\\u90BB\\u4E24\\u6B21\\u300C\\u5F00\\u59CB\\u4E0A\\u4F20\\u300D\\u81F3\\u5C11\\u95F4\\u9694 UPLOAD_GAP_MS\\uFF09\\uFF0C\\u907F\\u514D\\u8FDE\\u70B9/\\u6279\\u91CF\\u5C0F\\u6587\\u4EF6\\u649E 429
    // \\u2014\\u2014\\u649E\\u4E86\\u8981\\u7B49\\u6EE1\\u4E00\\u6574\\u5206\\u949F\\uFF0C\\u53CD\\u800C\\u66F4\\u6162\\u3002
    var gap=UPLOAD_GAP_MS-(now-lastSendAt);
    if(lastSendAt>0&&gap>0){
      next.limitWait=true;
      next.gapUntil=now+gap;
      if(!gapLogged){
        gapLogged=true;
        taskLog('\\u4E0A\\u4F20\\u9650\\u901F\\uFF1A\\u6BCF '+Math.round(UPLOAD_GAP_MS/1000)+' \\u79D2 1 \\u4E2A\\uFF08\\u670D\\u52A1\\u7AEF\\u9650 '+UPLOAD_PER_MIN+' \\u6B21/\\u5206\\uFF09');
      }
      scheduleTaskRender();
      if(pumpTimer){clearTimeout(pumpTimer);}
      pumpTimer=setTimeout(function(){pumpTimer=null;pumpTasks();},Math.max(200,gap));
      updateBadge();
      return;
    }
    next.limitWait=false;
    next.gapUntil=0;
    lastSendAt=now;
    taskRunning=true;
    doUpload(next);
    return;
  }
  if(soonest){
    if(pumpTimer){clearTimeout(pumpTimer);}
    pumpTimer=setTimeout(function(){pumpTimer=null;pumpTasks();},Math.max(500,soonest-Date.now()));
  }
}
function doUpload(t){
  if(!reserveSpace(t)){
    t.status='fail';t.error='\\u5B58\\u50A8\\u7A7A\\u95F4\\u4E0D\\u8DB3';t.attempts=RETRY_DELAYS.length;batchFail++;
    taskLog('\\u4E0A\\u4F20\\u5931\\u8D25\\uFF1A'+t.name+'\\uFF08\\u5B58\\u50A8\\u7A7A\\u95F4\\u4E0D\\u8DB3\\uFF0C\\u5269\\u4F59 '+fmtUse(freeSpace())+'\\uFF09',true);
    finishTask();scheduleTaskRender();
    return;
  }
  t.status='up';
  t.loaded=0;
  t.error='';
  t.speed=0;
  t.lastAt=Date.now();
  t.lastLoaded=0;
  taskLog('\\u5F00\\u59CB\\u4E0A\\u4F20\\uFF1A'+t.name);
  scheduleTaskRender();
  var xhr=new XMLHttpRequest();
  t.xhr=xhr;
  var fd=new FormData();
  fd.append('file',t.file,t.name);
  xhr.open('POST','/temp/api/upload');
  xhr.timeout=600000;
  if(xhr.upload){
    xhr.upload.onprogress=function(e){
      if(!e.lengthComputable){return;}
      t.loaded=e.loaded;
      var now=Date.now();
      var dt=(now-t.lastAt)/1000;
      if(dt>=0.4){
        t.speed=Math.max(0,(e.loaded-t.lastLoaded)/dt);
        t.lastAt=now;
        t.lastLoaded=e.loaded;
      }
      if(e.total>0&&e.loaded>=e.total&&t.status==='up'){t.status='proc';}
      scheduleTaskRender();
    };
  }
  xhr.onload=function(){
    var j=null;
    try{j=JSON.parse(xhr.responseText||'{}');}catch(e){}
    if(xhr.status===200&&j&&j.ok){
      t.status='done';
      t.loaded=t.size;
      t.reserved=false;              // \\u7A7A\\u95F4\\u5DF2\\u5B9E\\u9645\\u5360\\u7528\\uFF0C\\u4E0D\\u518D\\u5F52\\u8FD8
      if(typeof j.used==='number'&&j.used>=0){usageUsed=j.used;renderHint();}
      batchOk++;
      if(j.file&&j.file.key){
        // \\u5148\\u628A\\u63A5\\u53E3\\u8FD4\\u56DE\\u7684\\u6587\\u4EF6\\u9879\\u5E76\\u5165\\u672C\\u5730\\u5217\\u8868\\uFF08KV list() \\u6709\\u6570\\u79D2\\u5EF6\\u8FDF\\uFF09\\uFF0C\\u5E76\\u6301\\u4E45\\u5316\\u4EE5\\u6297\\u5237\\u65B0
        pendingFiles[j.file.key]={item:j.file,until:Date.now()+PENDING_MS};
        delete deletedKeys[j.file.key];
        savePending();
      }
      taskLog('\\u4E0A\\u4F20\\u6210\\u529F\\uFF1A'+t.name);
      renderList();
      finishTask();
    }else if(xhr.status===429&&t.attempts<RETRY_DELAYS.length){
      var wait=RETRY_DELAYS[t.attempts];
      // \\u670D\\u52A1\\u7AEF 429 \\u5E26 Retry-After\\uFF08\\u7A97\\u53E3\\u771F\\u5B9E\\u5269\\u4F59\\u79D2\\u6570\\uFF09+ JSON \\u91CC\\u7684 retryAfter\\uFF1A
      // \\u5C0A\\u91CD\\u5B83\\uFF0C\\u907F\\u514D\\u7ACB\\u5373\\u91CD\\u8BD5\\u7EE7\\u7EED\\u649E\\u9650\\u6D41\\uFF08\\u7A97\\u53E3\\u901A\\u5E38 60 \\u79D2\\uFF09
      var ra=parseInt(xhr.getResponseHeader('Retry-After')||'0',10);
      if(j&&j.retryAfter){var rj=parseInt(j.retryAfter,10);if(isFinite(rj)&&rj>ra){ra=rj;}}
      if(isFinite(ra)&&ra>0){wait=Math.min(Math.max(ra*1000,wait),120000);}
      lastSendAt=Date.now(); // \\u9650\\u901F\\u7A97\\u53E3\\u5DF2\\u91CD\\u65B0\\u5F00\\u59CB\\u8BA1\\u65F6\\uFF1A\\u9000\\u907F\\u7ED3\\u675F\\u540E\\u65E0\\u9700\\u518D\\u53E0\\u52A0 gap
      t.attempts++;
      t.status='wait';
      t.nextAt=Date.now()+wait;
      taskLog('\\u8BF7\\u6C42\\u8FC7\\u4E8E\\u9891\\u7E41\\uFF0C'+Math.round(wait/1000)+' \\u79D2\\u540E\\u81EA\\u52A8\\u91CD\\u8BD5\\uFF1A'+t.name,true);
      finishTask();
    }else{
      t.status='fail';
      t.error=(j&&j.error)||('HTTP '+xhr.status);
      releaseSpace(t);
      batchFail++;
      taskLog('\\u4E0A\\u4F20\\u5931\\u8D25\\uFF1A'+t.name+'\\uFF08'+t.error+'\\uFF09',true);
      finishTask();
    }
    scheduleTaskRender();
  };
  xhr.onerror=function(){
    t.status='fail';t.error='\\u7F51\\u7EDC\\u9519\\u8BEF';releaseSpace(t);batchFail++;
    taskLog('\\u4E0A\\u4F20\\u5931\\u8D25\\uFF1A'+t.name+'\\uFF08\\u7F51\\u7EDC\\u9519\\u8BEF\\uFF09',true);
    finishTask();scheduleTaskRender();
  };
  xhr.ontimeout=function(){
    t.status='fail';t.error='\\u4E0A\\u4F20\\u8D85\\u65F6';releaseSpace(t);batchFail++;
    taskLog('\\u4E0A\\u4F20\\u5931\\u8D25\\uFF1A'+t.name+'\\uFF08\\u8D85\\u65F6\\uFF09',true);
    finishTask();scheduleTaskRender();
  };
  xhr.onabort=function(){
    if(t.status==='cancel'){taskLog('\\u5DF2\\u53D6\\u6D88\\uFF1A'+t.name);releaseSpace(t);}
    finishTask();scheduleTaskRender();
  };
  xhr.send(fd);
}
// \\u672C\\u5730\\u7A7A\\u95F4\\u5360\\u7528\\uFF1A\\u961F\\u5217\\u91CC\\u300C\\u5DF2\\u6392\\u961F/\\u4E0A\\u4F20\\u4E2D/\\u5DF2\\u5B8C\\u6210\\u300D\\u90FD\\u7B97\\u5360\\u7528\\uFF08\\u540C\\u6279\\u591A\\u6587\\u4EF6\\u4E0D\\u4F1A\\u91CD\\u590D\\u8D85\\u989D\\uFF09\\uFF0C
// \\u5931\\u8D25/\\u53D6\\u6D88\\u65F6\\u5F52\\u8FD8\\uFF1B\\u670D\\u52A1\\u7AEF\\u8D26\\u672C\\u624D\\u662F\\u6700\\u7EC8\\u6743\\u5A01\\uFF08\\u5217\\u8868\\u5237\\u65B0\\u4F1A\\u8986\\u76D6\\u672C\\u5730\\u4F30\\u7B97\\uFF09\\u3002
function reserveSpace(t){
  if(t.reserved){return true;}
  if(usageUsed+t.size>usageTotal){return false;}
  usageUsed+=t.size;
  t.reserved=true;
  renderHint();
  return true;
}
function releaseSpace(t){
  if(!t.reserved){return;}
  usageUsed=Math.max(0,usageUsed-t.size);
  t.reserved=false;
  renderHint();
}
function finishTask(){
  taskRunning=false;
  pumpTasks();
  if(activeCount()===0){
    if(batchOk+batchFail>0){
      toast('\\u4E0A\\u4F20\\u5B8C\\u6210\\uFF1A\\u6210\\u529F '+batchOk+' \\u4E2A'+(batchFail?('\\uFF0C\\u5931\\u8D25 '+batchFail+' \\u4E2A'):''));
      batchOk=0;batchFail=0;
    }
    reconcileSoon();
  }
}
function reconcileSoon(){
  if(reconcileTimer){clearTimeout(reconcileTimer);}
  var delays=[2500,7000,16000,32000];
  var i=0;
  function step(){
    refreshList(false);
    i++;
    if(i<delays.length){reconcileTimer=setTimeout(step,delays[i]-delays[i-1]);}
  }
  reconcileTimer=setTimeout(step,delays[0]);
}
function upload(files){
  if(!files||!files.length){return;}
  var arr=Array.prototype.slice.call(files);
  var maxBytes=CFG.tempFileMaxMb*1024*1024;
  var queued=0;
  for(var i=0;i<arr.length;i++){
    var f=arr[i];
    taskSeq++;
    // \\u53BB\\u91CD\\uFF08\\u672C\\u8F6E\\u65B0\\u589E\\uFF09\\uFF1A\\u540C\\u540D\\u540C\\u5927\\u5C0F\\u4E14\\u4ECD\\u5728\\u961F\\u5217/\\u4E0A\\u4F20\\u4E2D\\u7684\\u6587\\u4EF6\\u76F4\\u63A5\\u8DF3\\u8FC7\\uFF0C\\u9632\\u8FDE\\u70B9\\u9020\\u6210\\u91CD\\u590D\\u5165\\u961F
    var sig=f.name+'|'+f.size+'|'+(f.lastModified||0);
    var dup=false;
    for(var d=0;d<tasks.length;d++){
      var q=tasks[d];
      if(q.sig===sig&&(q.status==='wait'||q.status==='up'||q.status==='proc')){dup=true;break;}
    }
    if(dup){
      batchFail++;
      taskLog('\\u8DF3\\u8FC7\\u91CD\\u590D\\u6587\\u4EF6\\u300C'+f.name+'\\u300D\\uFF1A\\u5DF2\\u5728\\u961F\\u5217\\u6216\\u4E0A\\u4F20\\u4E2D',true);
      continue;
    }
    if(f.size>maxBytes){
      tasks.push({id:taskSeq,file:f,name:f.name,size:f.size,status:'fail',loaded:0,error:'\\u8D85\\u8FC7 '+CFG.tempFileMaxMb+' MB',attempts:RETRY_DELAYS.length,nextAt:0,speed:0});
      batchFail++;
      taskLog('\\u8DF3\\u8FC7\\u300C'+f.name+'\\u300D\\uFF1A\\u8D85\\u8FC7 KV \\u5355\\u6587\\u4EF6\\u786C\\u4E0A\\u9650 '+CFG.tempFileMaxMb+' MB\\uFF08\\u5E73\\u53F0\\u9650\\u5236\\uFF0C\\u975E\\u672C\\u76D8\\u7B56\\u7565\\uFF09',true);
      continue;
    }
    var t={id:taskSeq,file:f,name:f.name,size:f.size,status:'wait',loaded:0,error:'',attempts:0,nextAt:0,speed:0,reserved:false,sig:sig};
    if(!reserveSpace(t)){
      t.status='fail';
      t.error='\\u5B58\\u50A8\\u7A7A\\u95F4\\u4E0D\\u8DB3';
      t.attempts=RETRY_DELAYS.length;
      tasks.push(t);
      batchFail++;
      taskLog('\\u8DF3\\u8FC7\\u300C'+f.name+'\\u300D\\uFF1A\\u5B58\\u50A8\\u7A7A\\u95F4\\u4E0D\\u8DB3\\uFF08\\u5269\\u4F59 '+fmtUse(freeSpace())+'\\uFF09',true);
      continue;
    }
    tasks.push(t);
    queued++;
  }
  trimTasks();
  renderTasks();
  if(queued>0){
    openPanel();
    pumpTasks();
  }else if(batchOk+batchFail>0){
    toast('\\u4E0A\\u4F20\\u5B8C\\u6210\\uFF1A\\u6210\\u529F '+batchOk+' \\u4E2A'+(batchFail?('\\uFF0C\\u5931\\u8D25 '+batchFail+' \\u4E2A'):''));
    batchOk=0;batchFail=0;
  }
}
function retryTask(id){
  var t=findTask(id);
  if(!t){return;}
  t.status='wait';t.loaded=0;t.error='';t.nextAt=0;t.attempts=0;t.speed=0;
  renderTasks();
  pumpTasks();
}
function cancelTask(id){
  var t=findTask(id);
  if(!t){return;}
  if(t.status==='up'&&t.xhr){t.status='cancel';try{t.xhr.abort();}catch(e){}}
  else if(t.status==='wait'){t.status='cancel';renderTasks();}
  updateBadge();
}
// \\u7EED\\u671F\\uFF1APOST /temp/api/renew \\u2014\\u2014 \\u670D\\u52A1\\u7AEF\\u8BFB\\u56DE\\u539F\\u503C\\u518D\\u7528\\u65B0\\u7684 expirationTtl \\u91CD\\u5199
// \\uFF08KV \\u6CA1\\u6709 touch/\\u5EF6\\u671F\\u63A5\\u53E3\\uFF09\\u3002\\u6210\\u529F\\u540E\\u7528\\u54CD\\u5E94\\u91CC\\u7684\\u65B0\\u5230\\u671F\\u65F6\\u95F4\\u5C31\\u5730\\u66F4\\u65B0\\u672C\\u5730\\u5217\\u8868\\uFF0C
// \\u4E0D\\u5FC5\\u7B49 KV list \\u7684\\u6700\\u7EC8\\u4E00\\u81F4\\u3002
var renewing={};
function renewFile(key,btn){
  if(!key||renewing[key]){return;}
  renewing[key]=1;
  if(btn){btn.disabled=true;}
  var fd=new FormData();
  fd.append('key',key);
  fetch('/temp/api/renew',{method:'POST',body:fd})
  .then(function(r){return r.json().then(function(j){return {s:r.status,j:j};});})
  .then(function(o){
    delete renewing[key];
    if(o.s===200&&o.j&&o.j.ok){
      var nf=o.j.file||{};
      for(var i=0;i<tempFiles.length;i++){
        if(tempFiles[i].key===key){tempFiles[i].expireAt=nf.expireAt;break;}
      }
      if(pendingFiles[key]){pendingFiles[key].item.expireAt=nf.expireAt;savePending();}
      renderList();
      var days=Math.round((o.j.added||0)/86400);
      if(days>0){toast('\\u5DF2\\u7EED\\u671F\\uFF1A+'+days+' \\u5929'+(o.j.capped?'\\uFF08\\u5DF2\\u8FBE\\u4FDD\\u7559\\u4E0A\\u9650\\uFF09':''));}
      else{toast('\\u5DF2\\u5728\\u4FDD\\u7559\\u4E0A\\u9650\\uFF0830 \\u5929\\uFF09\\u5185\\uFF0C\\u672A\\u518D\\u5EF6\\u957F');}
    }else{
      if(btn){btn.disabled=false;}
      toast('\\u7EED\\u671F\\u5931\\u8D25\\uFF1A'+((o.j&&o.j.error)||('HTTP '+o.s)));
      if(o.s===404){refreshList(false);}
    }
  })
  .catch(function(e){
    delete renewing[key];
    if(btn){btn.disabled=false;}
    toast('\\u7EED\\u671F\\u5931\\u8D25\\uFF1A'+String((e&&e.message)||e));
  });
}
function del(key){
  if(!key){return;}
  if(!window.confirm('\\u786E\\u5B9A\\u5220\\u9664\\u8BE5\\u4E34\\u65F6\\u6587\\u4EF6\\uFF1F')){return;}
  var fd=new FormData();
  fd.append('key',key);
  fetch('/temp/api/delete',{method:'POST',body:fd})
  .then(function(r){return r.json();})
  .then(function(j){
    if(j&&j.ok){
      deletedKeys[key]=Date.now()+PENDING_MS;
      delete pendingFiles[key];
      savePending();
      tempFiles=tempFiles.filter(function(x){return x.key!==key;});
      if(typeof j.used==='number'&&j.used>=0){usageUsed=j.used;renderHint();}
      renderList();
      toast('\\u5DF2\\u5220\\u9664');
      setTimeout(function(){refreshList(false);},4000);
    }else{toast('\\u5220\\u9664\\u5931\\u8D25\\uFF1A'+((j&&j.error)||'\\u672A\\u77E5\\u9519\\u8BEF'));}
  })
  .catch(function(e){toast('\\u5220\\u9664\\u5931\\u8D25\\uFF1A'+String((e&&e.message)||e));});
}
var up=$('tempUpBtn'),fi=$('tempFile');
if(up&&fi){
  up.onclick=function(){fi.click();};
  fi.onchange=function(){upload(fi.files);fi.value='';};
}
// \\u4E0A\\u4F20\\u4EFB\\u52A1\\u9762\\u677F\\u4EA4\\u4E92\\uFF1A\\u5C0F\\u6309\\u94AE\\u5F00\\u5173 / \\u5173\\u95ED / \\u6E05\\u9664\\u5DF2\\u5B8C\\u6210 / \\u5931\\u8D25\\u91CD\\u8BD5 / \\u4E0A\\u4F20\\u4E2D\\u53D6\\u6D88
var taskBtnEl=$('taskBtn');
if(taskBtnEl){taskBtnEl.onclick=function(){if($('taskPanel').classList.contains('show')){closePanel();}else{openPanel();}};}
var taskCloseEl=$('taskClose');
if(taskCloseEl){taskCloseEl.onclick=closePanel;}
var taskClearEl=$('taskClear');
if(taskClearEl){taskClearEl.onclick=function(){
  var kept=[];
  for(var i=0;i<tasks.length;i++){
    var s=tasks[i].status;
    if(s==='wait'||s==='up'||s==='proc'){kept.push(tasks[i]);}
  }
  if(kept.length===tasks.length){toast('\\u6682\\u65E0\\u53EF\\u6E05\\u9664\\u7684\\u4EFB\\u52A1');return;}
  tasks=kept;
  renderTasks();
};}
var taskListEl=$('taskList');
if(taskListEl){taskListEl.onclick=function(e){
  var rb=e.target.closest('[data-retry]');
  if(rb){retryTask(parseInt(rb.getAttribute('data-retry'),10));return;}
  var cb=e.target.closest('[data-cancel]');
  if(cb){cancelTask(parseInt(cb.getAttribute('data-cancel'),10));}
};}
renderTasks();
$('themeBtn').onclick=function(){
  document.body.classList.toggle('dark');
  try{localStorage.setItem('tempDark',document.body.classList.contains('dark')?'1':'0');}catch(e){}
  $('themeBtn').innerHTML=document.body.classList.contains('dark')?'&#x2600;&#xFE0F;':'&#x1F319;';
};
try{
  if(localStorage.getItem('tempDark')==='1'){document.body.classList.add('dark');$('themeBtn').innerHTML='&#x2600;&#xFE0F;';}
}catch(e){}
loadPending();
render();
</script>
</body></html>`;
}
