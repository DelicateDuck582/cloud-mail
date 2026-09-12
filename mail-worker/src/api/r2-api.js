import r2Service from '../service/r2-service';
import app from '../hono/hono';
import signUtils from '../utils/sign-utils';
import BizError from '../error/biz-error';
import { t } from '../i18n/i18n';

// 附件直读限流（per-IP）：已登录用户可拿到自己附件的有效签名后反复请求，
// 直读路径不走代理缓存，会直接产生 COS 下行流量 -> 用限流防盗刷
const ossLimitMap = new Map();
const OSS_LIMIT_PER_MIN = 120;
function ossRateLimited(ip) {
	const now = Date.now();
	const rec = ossLimitMap.get(ip);
	if (!rec || now - rec.t > 60000) {
		ossLimitMap.set(ip, { c: 1, t: now });
		return false;
	}
	rec.c++;
	if (rec.c > OSS_LIMIT_PER_MIN) {
		return true;
	}
	if (ossLimitMap.size > 10000) {
		for (const [k, v] of ossLimitMap) {
			if (now - v.t > 60000) ossLimitMap.delete(k);
		}
	}
	return false;
}

// 附件直读端点：必须携带有效签名（与代理 Worker 相同算法），防止绕过签名防伪系统
app.get('/oss/*', async (c) => {
	let key = '';
	try { key = decodeURIComponent((c.req.path.split('/oss/')[1] || '').split('?')[0]); } catch (e) { key = ''; }
	const { expires, sign } = c.req.query();

	if (!key || !expires || !sign) {
		throw new BizError(t('unauthorized'), 403);
	}

	// 过期校验
	const exp = Number(expires);
	if (!Number.isFinite(exp) || Date.now() / 1000 > exp) {
		throw new BizError(t('unauthorized'), 403);
	}

	// 签名校验（与 sign-utils / 代理 Worker 完全一致：HMAC-SHA256(`/attachments/<key>:<expires>`)）
	const secret = (c.env?.ATT_SIGN_SECRET || '').trim();
	if (!secret) {
		throw new BizError(t('unauthorized'), 403);
	}
	const expected = await signUtils.hmacHex(secret, `/${key}:${expires}`);
	if (!signUtils.timingSafeEqual(expected, sign)) {
		throw new BizError(t('unauthorized'), 403);
	}

	// 验签通过后再限流（签名有效才算一次合法请求，避免无签名刷子占限流额度）
	const ip = c.req.header('CF-Connecting-IP') || c.req.header('x-forwarded-for') || 'unknown';
	if (ossRateLimited(ip)) {
		throw new BizError('Too Many Requests', 429);
	}

	const obj = await r2Service.getObj(c, key);

	// 回退 KV 后，历史对象可能仍在 COS（故障前写入），KV 中不存在 → 明确提示
	if (!obj) {
		const cosDown = await r2Service.isCosFallback(c);
		if (cosDown) {
			throw new BizError('文件暂时无法访问--COS错误', 503);
		}
		throw new BizError('Not Found', 404);
	}

	return new Response(obj.body, {
		headers: {
			'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream',
			'Content-Disposition': obj.httpMetadata?.contentDisposition || null
		}
	});
});


