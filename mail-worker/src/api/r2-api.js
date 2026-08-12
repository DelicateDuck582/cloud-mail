import r2Service from '../service/r2-service';
import app from '../hono/hono';
import signUtils from '../utils/sign-utils';
import BizError from '../error/biz-error';
import { t } from '../i18n/i18n';

// 附件直读端点：必须携带有效签名（与代理 Worker 相同算法），防止绕过签名防伪系统
app.get('/oss/*', async (c) => {
	const key = decodeURIComponent((c.req.path.split('/oss/')[1] || '').split('?')[0]);
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
	if (expected !== sign) {
		throw new BizError(t('unauthorized'), 403);
	}

	const obj = await r2Service.getObj(c, key);
	return new Response(obj.body, {
		headers: {
			'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream',
			'Content-Disposition': obj.httpMetadata?.contentDisposition || null
		}
	});
});


