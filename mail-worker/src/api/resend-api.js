import resendService from '../service/resend-service';
import app from '../hono/hono';

app.post('/webhooks', async (c) => {
	try {
		const raw = await c.req.text();

		// 安全：校验 Resend(Svix) webhook 签名；配置 RESEND_SIGNING_SECRET 后强制校验，防止伪造投递状态
		if (!await resendService.verifySvixSignature(c, raw)) {
			return c.text('invalid signature', 401);
		}

		await resendService.webhooks(c, JSON.parse(raw));
		return c.text('success', 200)
	} catch (e) {
		console.error('webhook error:', e);
		return c.text('error', 500)
	}
})
