import emailService from './email-service';
import { emailConst } from '../const/entity-const';
import BizError from '../error/biz-error';

const resendService = {

	async webhooks(c, body) {

		const params = {
			resendEmailId: body.data.email_id,
			status: emailConst.status.SENT
		}

		if (body.type === 'email.delivered') {
			params.status = emailConst.status.DELIVERED
			params.message = null
		}

		if (body.type === 'email.complained') {
			params.status = emailConst.status.COMPLAINED
			params.message = null
		}

		if (body.type === 'email.bounced') {
			let bounce = body.data.bounce
			bounce = JSON.stringify(bounce);
			params.status = emailConst.status.BOUNCED
			params.message = bounce
		}

		if (body.type === 'email.delivery_delayed') {
			params.status = emailConst.status.DELAYED
			params.message = null
		}

		if (body.type === 'email.failed') {
			params.status = emailConst.status.FAILED
			params.message = body.data.failed.reason
		}

		const emailRow = await emailService.updateEmailStatus(c, params)

		if (!emailRow) {
			throw new BizError('更新邮件状态记录失败');
		}

	},

	// Resend 使用 Svix 标准 webhook 签名：校验 svix-id / svix-timestamp / svix-signature
	async verifySvixSignature(c, bodyText) {
		const secret = c.env.RESEND_SIGNING_SECRET;

		if (!secret) {
			// 未配置签名密钥：记录警告并放行（强烈建议在 Resend 配置 signing secret 并设置该环境变量）
			console.warn('webhook: RESEND_SIGNING_SECRET 未配置，未校验签名');
			return true;
		}

		const id = c.req.header('svix-id');
		const ts = c.req.header('svix-timestamp');
		const sigHeader = c.req.header('svix-signature') || '';

		if (!id || !ts || !sigHeader) return false;

		// 防重放：时间戳与当前时间差超过 5 分钟直接拒绝
		if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false;

		const signedContent = `${id}.${ts}.${bodyText}`;

		const key = await crypto.subtle.importKey(
			'raw',
			new TextEncoder().encode(secret),
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['sign']
		);
		const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signedContent));
		const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));

		return sigHeader.split(' ').includes(sigB64);
	},
}

export default resendService
