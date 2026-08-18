import emailService from './email-service';
import { emailConst } from '../const/entity-const';
import BizError from '../error/biz-error';
import orm from '../entity/orm';
import email from '../entity/email';
import { eq } from 'drizzle-orm';

const resendService = {

	async webhooks(c, body) {

		// 状态事件映射：只有这里列出的事件才会更新邮件状态
		const statusMap = {
			'email.delivered': emailConst.status.DELIVERED,
			'email.complained': emailConst.status.COMPLAINED,
			'email.bounced': emailConst.status.BOUNCED,
			'email.delivery_delayed': emailConst.status.DELAYED,
			'email.failed': emailConst.status.FAILED,
			'email.opened': emailConst.status.OPENED,	// 已读回执（Resend 打开追踪）
			'email.clicked': emailConst.status.OPENED,	// 点击链接同样视为已读
		}

		const status = statusMap[body.type];

		// 未处理的事件（如 email.received、email.sent 等）直接忽略，不碰邮件状态
		if (status === undefined) {
			return;
		}

		let message = null;
		if (body.type === 'email.bounced') {
			message = JSON.stringify(body.data.bounce);
		}

		if (body.type === 'email.failed') {
			message = body.data.failed?.reason;
		}

		const params = {
			resendEmailId: body.data.email_id,
			status,
			message
		}

		// 状态只允许升级（例如已读 9 后，迟到的 delivered 2 不得把状态回退）
		const currentRow = await orm(c).select({ status: email.status }).from(email).where(eq(email.resendEmailId, params.resendEmailId)).get();

		if (!currentRow) {
			throw new BizError('更新邮件状态记录失败');
		}

		if (Number(currentRow.status) >= Number(params.status)) {
			return;
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
			// 未配置签名密钥：记录警告并放行（⚠️ 强烈建议在 Resend 配置 signing secret 并设置该环境变量，否则 webhook 可被伪造）
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

		// Svix 签名头格式："v1,<base64签名>"；密钥轮换时以空格分隔多个 token。
		// 必须剥离 "v1," 前缀再与计算值比较（恒定时间比较，防时序侧信道）。
		return sigHeader.split(' ').some(token => {
			const [version, signature] = token.split(',');
			if (version !== 'v1' || !signature) return false;
			return timingSafeEqual(signature, sigB64);
		});
	},
}

// 恒定时间字符串比较（长度不一致立即失败，长度一致时逐字节异或）
function timingSafeEqual(a, b) {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) {
		diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}
	return diff === 0;
}

export default resendService
