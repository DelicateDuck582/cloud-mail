import app from '../hono/hono';
import emailService from '../service/email-service';
import result from '../model/result';
import userContext from '../security/user-context';
import attService from '../service/att-service';
import BizError from '../error/biz-error';

app.get('/email/list', async (c) => {
	const data = await emailService.list(c, c.req.query(), userContext.getUserId(c));
	return c.json(result.ok(data));
});

app.get('/email/latest', async (c) => {
	const list = await emailService.latest(c, c.req.query(), userContext.getUserId(c));
	return c.json(result.ok(list));
});

app.delete('/email/delete', async (c) => {
	await emailService.delete(c, c.req.query(), userContext.getUserId(c));
	return c.json(result.ok());
});

app.get('/email/attList', async (c) => {
	const attList = await attService.list(c, c.req.query(), userContext.getUserId(c));
	return c.json(result.ok(attList));
});

// 发送请求体与附件大小上限（防超大请求/附件打爆 Worker 内存）
const MAX_SEND_BODY_SIZE = 40 * 1024 * 1024;	// 整个 JSON 请求体（content-length）上限 40MB
const MAX_SINGLE_ATT_SIZE = 25 * 1024 * 1024;	// 单个附件（含内嵌图）解码后上限 25MB
const MAX_TOTAL_ATT_SIZE = 30 * 1024 * 1024;	// 附件 + 内嵌图解码后总量上限 30MB

// base64 内容解码后字节数估算（兼容 data URL 与带空白的 base64）
function base64DecodedSize(content) {
	if (!content) return 0;

	if (typeof content !== 'string') {
		if (content instanceof ArrayBuffer) return content.byteLength;
		if (ArrayBuffer.isView(content)) return content.byteLength;
		return 0;
	}

	let str = content;
	const commaIndex = str.indexOf(',');
	if (str.startsWith('data:') && commaIndex > -1) {
		str = str.slice(commaIndex + 1);
	}

	const clean = str.replace(/\s+/g, '');
	if (!clean) return 0;

	let padding = 0;
	if (clean.endsWith('==')) padding = 2;
	else if (clean.endsWith('=')) padding = 1;

	return Math.max(0, Math.floor((clean.length * 3) / 4) - padding);
}

// 正文内嵌图（data:image/...;base64,）解码后总字节
function inlineImageDecodedSize(html) {
	if (!html || typeof html !== 'string') return 0;

	let total = 0;
	// MIME 后允许一段有限长度的参数段（如 charset），载荷为 base64 字符与空白
	const re = /data:image\/[a-z0-9.+-]+(?:;[^"'(),<>]{0,64})?;base64,([a-z0-9+/=\s]*)/gi;
	let match;
	while ((match = re.exec(html)) !== null) {
		total += base64DecodedSize(match[1]);
		if (total > MAX_TOTAL_ATT_SIZE) return total;
	}
	return total;
}

// JSON 解析后、转发 email-service 之前的大小校验：单文件 >25MB 或总量 >30MB 直接拒绝
function checkSendPayloadSize(params) {
	const attachments = Array.isArray(params?.attachments) ? params.attachments : [];
	let total = 0;

	for (const att of attachments) {
		const size = base64DecodedSize(att?.content);
		if (size > MAX_SINGLE_ATT_SIZE) {
			throw new BizError('附件过大 Attachment too large', 413);
		}
		total += size;
	}

	total += inlineImageDecodedSize(params?.content);

	if (total > MAX_TOTAL_ATT_SIZE) {
		throw new BizError('附件总大小超限 Attachments total size too large', 413);
	}
}

app.post('/email/send', async (c) => {
	// 进入业务前先按 content-length 拒绝超大请求体
	const contentLength = Number(c.req.header('content-length'));
	if (Number.isFinite(contentLength) && contentLength > MAX_SEND_BODY_SIZE) {
		throw new BizError('请求体过大 Payload too large', 413);
	}

	const params = await c.req.json();
	checkSendPayloadSize(params);

	const email = await emailService.send(c, params, userContext.getUserId(c));
	return c.json(result.ok(email));
});

app.put('/email/read', async (c) => {
	await emailService.read(c, await c.req.json(), userContext.getUserId(c));
	return c.json(result.ok());
})

