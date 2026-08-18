import app from '../hono/hono';
import telegramService from '../service/telegram-service';

app.get('/telegram/getEmail/:token', async (c) => {
	const content = await telegramService.getEmailContent(c, c.req.param());
	// 安全：邮件内容包含隐私，禁止公开缓存
	c.header('Cache-Control', 'private, no-store');
	return c.html(content)
});

