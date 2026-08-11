import domainUtils from './domain-uitls';

/**
 * 附件/图片 URL 短期签名工具
 *
 * 作用：CloudMail 后端在返回邮件正文和附件列表时，给每个 attachments/<key> 的
 * URL 追加 ?expires=<unix>&sign=<hmac>。代理 Worker（COS 前置）只有验签通过才回源。
 *
 * 签名算法（与代理 Worker 保持完全一致）：
 *   sign = hex( HMAC-SHA256( secret, `/attachments/<key>:<expires>` ) )
 *
 * 环境变量：
 *   ATT_SIGN_SECRET  必填，与代理 Worker 的 ATT_SIGN_SECRET 保持一致
 *   ATT_SIGN_TTL     可选，签名有效期（秒），默认 900（15 分钟），范围 60 ~ 86400
 */
const signUtils = {

	// 签名有效期（秒）
	getTtl(c) {
		const v = Number(c?.env?.ATT_SIGN_TTL);
		if (Number.isFinite(v) && v >= 60 && v <= 86400) {
			return Math.floor(v);
		}
		return 900;
	},

	// HMAC-SHA256 -> 小写 hex
	async hmacHex(secret, message) {
		const key = await crypto.subtle.importKey(
			'raw',
			new TextEncoder().encode(secret || ''),
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['sign']
		);
		const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
		return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
	},

	// 批量签名：传入 key 列表（如 attachments/xxx.png），返回 Map<key, {expires, sign}>
	// 同一次调用内所有 key 共用同一个 expires，便于代理侧缓存对齐
	async signKeys(c, keys) {
		const map = new Map();
		const unique = [...new Set((keys || []).filter(Boolean))];
		if (unique.length === 0) {
			return map;
		}

		const expires = Math.floor(Date.now() / 1000) + this.getTtl(c);
		const secret = (c?.env?.ATT_SIGN_SECRET || '').trim();

		const results = await Promise.all(unique.map(async key => {
			const sign = await this.hmacHex(secret, `/${key}:${expires}`);
			return { key, sign };
		}));

		for (const r of results) {
			map.set(r.key, { expires, sign: r.sign });
		}

		return map;
	},

	// 给邮件正文中的 {{domain}}attachments/<key> 占位符追加签名参数
	async signContent(c, content, r2Domain) {
		if (!content) {
			return content;
		}

		const str = String(content);
		if (!str.includes('{{domain}}')) {
			return content;
		}

		const pattern = /\{\{domain\}\}(attachments\/[^\s"'<>?]+)/g;
		const keys = [...new Set(Array.from(str.matchAll(pattern), m => m[1]))];

		if (keys.length === 0) {
			return content;
		}

		const signMap = await this.signKeys(c, keys);
		const base = domainUtils.toOssDomain(r2Domain) || '';

		return str.replace(pattern, (match, key) => {
			const sp = signMap.get(key);
			if (!sp) {
				return match;
			}
			return `{{domain}}${key}?expires=${sp.expires}&sign=${sp.sign}`;
		});
	},

	// 给附件列表的每一项追加 url 字段（完整带签名地址），key 保持原样
	async addAttUrl(c, attList, r2Domain) {
		if (!attList || attList.length === 0) {
			return;
		}

		const keys = attList.filter(a => a && a.key).map(a => a.key);
		const signMap = await this.signKeys(c, keys);
		const base = domainUtils.toOssDomain(r2Domain) || '';

		for (const att of attList) {
			if (!att || !att.key || !signMap.has(att.key)) {
				continue;
			}
			const sp = signMap.get(att.key);
			att.url = `${base}/${att.key}?expires=${sp.expires}&sign=${sp.sign}`;
		}
	}
};

export default signUtils;
