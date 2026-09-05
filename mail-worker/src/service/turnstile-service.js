import BizError from '../error/biz-error';
import settingService from './setting-service';
import { t } from '../i18n/i18n'

const turnstileService = {

	async verify(c, token) {

		if (!token) {
			throw new BizError(t('emptyBotToken'),400);
		}

		const settingRow = await settingService.query(c)

		// 安全：remoteip 必须是合法 IP 才传，否则 siteverify 可能直接拒绝校验
		const params = new URLSearchParams({
			secret: settingRow.secretKey,
			response: token,
		})
		const remoteip = c.req.header('cf-connecting-ip');
		if (remoteip && /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$/.test(remoteip)) {
			params.set('remoteip', remoteip);
		}

		const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded'
			},
			body: params
		});

		const result = await res.json();

		if (!result.success) {
			throw new BizError(t('botVerifyFail'),400)
		}
	}
};

export default turnstileService;
