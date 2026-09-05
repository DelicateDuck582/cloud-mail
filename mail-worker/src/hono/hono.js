import { Hono } from 'hono';
const app = new Hono();

import result from '../model/result';
import { cors } from 'hono/cors';

app.use('*', cors({
	// 安全：CORS 白名单 —— 仅放行本机开发与 duckgame-play.top，拒绝其它任意来源
	origin: (origin) => {
		if (!origin) return null;
		try {
			const u = new URL(origin);
			if (u.hostname === 'localhost' || u.hostname === '127.0.0.1') return origin;
			if (u.hostname === 'duckgame-play.top' || u.hostname.endsWith('.duckgame-play.top')) return origin;
		} catch (e) {}
		return null;
	},
	allowHeaders: ['Content-Type', 'Authorization'],
	allowMethods: ['GET', 'HEAD', 'PUT', 'POST', 'DELETE', 'OPTIONS'],
}));

app.onError((err, c) => {
	if (err.name === 'BizError') {
		console.log(err.message);
		return c.json(result.fail(err.message, err.code));
	}

	console.error(err);

	if (err.message === `Cannot read properties of undefined (reading 'get')`) {
		return c.json(result.fail('KV数据库未绑定<br/>KV database not bound',502));
	}

	if (err.message === `Cannot read properties of undefined (reading 'put')`) {
		return c.json(result.fail('KV数据库未绑定<br/>KV database not bound',502));
	}

	if (err.message === `Cannot read properties of undefined (reading 'prepare')`) {
		return c.json(result.fail('D1数据库未绑定<br/>D1 database not bound',502));
	}

	if (err.message?.includes('D1_ERROR: no such column')) {
		return c.json(result.fail('请按照文档更新数据库<br/>Please update the database as documented',502));
	}

	// 安全：非业务异常不把内部错误信息回给客户端，避免泄露实现细节
	return c.json(result.fail('Internal Server Error', 500));
});

export default app;


