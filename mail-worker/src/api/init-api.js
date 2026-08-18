import app from '../hono/hono';
import { dbInit } from '../init/init';

// /init 初始化接口：仅 POST + 独立 INIT_SECRET + per-IP 限流。
// 未配置 INIT_SECRET 时接口直接禁用；不再使用 jwt_secret，
// 避免 jwt_secret 泄露（如 git 历史残留）后被任何人重跑数据库初始化。
const initFailMap = new Map();
function initBlocked(ip) {
	const rec = initFailMap.get(ip);
	return !!(rec && Date.now() - rec.t < 60000 && rec.c >= 3);
}
function initRecord(ip) {
	const rec = initFailMap.get(ip);
	const now = Date.now();
	if (!rec || now - rec.t > 60000) initFailMap.set(ip, { c: 1, t: now });
	else rec.c++;
}

app.post('/init', async (c) => {
	const ip = c.req.header('CF-Connecting-IP') || c.req.header('x-forwarded-for') || 'unknown';

	if (!c.env.INIT_SECRET) {
		return c.text('❌ 未配置 INIT_SECRET，初始化接口已禁用', 403);
	}

	if (initBlocked(ip)) {
		return c.text('❌ 请求过于频繁', 429);
	}

	const body = await c.req.json().catch(() => ({}));

	if (body.secret !== c.env.INIT_SECRET) {
		initRecord(ip);
		return c.text('❌ INIT_SECRET mismatch', 403);
	}

	c.set('initSecret', body.secret);
	return dbInit.init(c);
})
