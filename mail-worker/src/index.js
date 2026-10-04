import app from './hono/webs';
import { email } from './email/email';
import userService from './service/user-service';
import verifyRecordService from './service/verify-record-service';
import emailService from './service/email-service';
import kvObjService from './service/kv-obj-service';
import oauthService from './service/oauth-service';
import analysisService from './service/analysis-service';
import ewsApp from './ews/router.js';
import { EWS_PATH } from './ews/const.js';
export default {
	 async fetch(req, env, ctx) {

		const url = new URL(req.url)

		// EWS（Exchange Web Services）：Thunderbird 145+ 原生 Exchange 账号接入
		// 大小写不敏感（TB 实际请求 /EWS/Exchange.asmx）；独立 Hono 实例、独立 Basic 认证
		if (url.pathname.toLowerCase() === EWS_PATH) {
			return ewsApp.fetch(req, env, ctx);
		}

		if (url.pathname.startsWith('/api/')) {
			url.pathname = url.pathname.replace('/api', '')
			req = new Request(url.toString(), req)
			return app.fetch(req, env, ctx);
		}

		 if (['/static/','/attachments/'].some(p => url.pathname.startsWith(p))) {
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
		await emailService.autoClean({ env })
		await analysisService.refreshEchartsCache({ env })
		await oauthService.clearNoBindOathUser({ env })

		// EWS 物理删除事件（tombstone）保留 30 天：30 天内同步过的客户端都能拿到 Delete 事件，
		// 更老的记录不再有意义；失败只告警，不中断后续定时任务
		try {
			await env.db.prepare(`DELETE FROM ews_tombstone WHERE del_time < datetime('now','-30 day')`).run();
		} catch (e) {
			console.warn(`[ews] tombstone cleanup skipped: ${e.message}`);
		}
	},
};
