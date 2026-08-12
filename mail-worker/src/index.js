import app from './hono/webs';
import { email } from './email/email';
import userService from './service/user-service';
import verifyRecordService from './service/verify-record-service';
import emailService from './service/email-service';
import kvObjService from './service/kv-obj-service';
import oauthService from "./service/oauth-service";
import analysisService from './service/analysis-service';
import attService from './service/att-service';
import signUtils from './utils/sign-utils';
export default {
	 async fetch(req, env, ctx) {

		const url = new URL(req.url)

		if (url.pathname.startsWith('/api/')) {
			url.pathname = url.pathname.replace('/api', '')
			req = new Request(url.toString(), req)
			return app.fetch(req, env, ctx);
		}

		 if (['/static/','/attachments/'].some(p => url.pathname.startsWith(p))) {

			// 附件直读必须携带有效签名，防止绕过签名防伪系统（/static/ 静态资源除外）
			if (url.pathname.startsWith('/attachments/')) {
				const key = decodeURIComponent(url.pathname.substring(1));
				const expires = url.searchParams.get('expires');
				const sign = url.searchParams.get('sign');
				const secret = (env?.ATT_SIGN_SECRET || '').trim();

				if (!key || !expires || !sign || !secret) {
					return new Response(JSON.stringify({ code: 403, message: 'unauthorized' }), { status: 403 });
				}

				const exp = Number(expires);
				if (!Number.isFinite(exp) || Date.now() / 1000 > exp) {
					return new Response(JSON.stringify({ code: 403, message: 'unauthorized' }), { status: 403 });
				}

				const expected = await signUtils.hmacHex(secret, `/${key}:${expires}`);
				if (expected !== sign) {
					return new Response(JSON.stringify({ code: 403, message: 'unauthorized' }), { status: 403 });
				}
			}

			 return await kvObjService.toObjResp( { env }, url.pathname.substring(1));
		 }

		return env.assets.fetch(req);
	},
	email: email,
	async scheduled(c, env, ctx) {
		if (c.cron === '*/30 * * * *') {
			await analysisService.refreshEchartsCache({ env })
			return;
		}

		await verifyRecordService.clearRecord({ env })
		await userService.resetDaySendCount({ env })
		await emailService.completeReceiveAll({ env })
		await oauthService.clearNoBindOathUser({ env })
		await attService.clearTrash({ env })
		await analysisService.refreshEchartsCache({ env })
	},
};
