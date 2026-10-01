import domainUtils from './domain-uitls';
import r2Service from '../service/r2-service';
import orm from '../entity/orm';
import { att } from '../entity/att';
import { and, eq, inArray } from 'drizzle-orm';

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

// D1 单条语句最多 100 个绑定参数，统一按 90 分片
const SQL_BIND_LIMIT = 90;

const signUtils = {

	// 签名有效期（秒）
	getTtl(c) {
		const v = Number(c?.env?.ATT_SIGN_TTL);
		if (Number.isFinite(v) && v >= 60 && v <= 86400) {
			return Math.floor(v);
		}
		return 900;
	},

	// 当前登录用户 id（鉴权中间件注入到 Hono context；cron / 内部调用可能没有）
	getUserId(c) {
		try {
			return c?.get?.('user')?.userId ?? null;
		} catch (e) {
			return null;
		}
	},

	// 超级管理员：本身即可通过 all-email 读取全站邮件，故不做归属限制（不构成提权）
	isSuperAdmin(c) {
		try {
			const user = c?.get?.('user');
			return !!(user && c?.env?.admin && user.email === c.env.admin);
		} catch (e) {
			return false;
		}
	},

	// 归属校验：返回 keys 中归 allowedUserIds 任一用户所有的 key 集合（分片查询，规避 D1 绑定参数上限）
	async selectOwnedKeys(c, keys, allowedUserIds) {
		const owned = new Set();
		const unique = [...new Set((keys || []).filter(Boolean))];
		if (unique.length === 0 || !Array.isArray(allowedUserIds) || allowedUserIds.length === 0) {
			return owned;
		}
		const owners = [...new Set(allowedUserIds)].slice(0, SQL_BIND_LIMIT);
		for (let i = 0; i < unique.length; i += SQL_BIND_LIMIT) {
			const chunk = unique.slice(i, i + SQL_BIND_LIMIT);
			const rows = await orm(c).select({ key: att.key }).from(att)
				.where(and(inArray(att.key, chunk), inArray(att.userId, owners)))
				.groupBy(att.key)
				.all();
			rows.forEach(row => owned.add(row.key));
		}
		return owned;
	},

	// 解析本次允许签发的归属用户集合：
	//   null                        → 不做归属限制（仅超管，或调用方显式声明行已按权限过滤的可信场景）
	//   [userId, ...]               → 只允许这些用户拥有的 key
	//   用户无法确定且未显式声明      → 空数组（fail closed，不签发任何签名）
	resolveAllowedUserIds(c, allowedUserIds) {
		if (allowedUserIds === null) {
			return null;
		}
		if (Array.isArray(allowedUserIds)) {
			return allowedUserIds;
		}
		if (this.isSuperAdmin(c)) {
			return null;
		}
		const userId = this.getUserId(c);
		return userId === null || userId === undefined ? [] : [userId];
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
	// 签发前做归属校验：不满足归属的 key 直接跳过（调用方保持原文不签名），防越权引用他人对象
	// opts.allowedUserIds：显式指定允许的归属用户；null 表示不做限制；缺省按当前登录用户校验
	async signKeys(c, keys, opts = {}) {
		const map = new Map();
		let unique = [...new Set((keys || []).filter(Boolean))];
		if (unique.length === 0) {
			return map;
		}

		const allowedUserIds = this.resolveAllowedUserIds(c, opts.allowedUserIds);

		if (allowedUserIds !== null) {
			if (allowedUserIds.length === 0) {
				return map;
			}
			const owned = await this.selectOwnedKeys(c, unique, allowedUserIds);
			unique = unique.filter(key => owned.has(key));
			if (unique.length === 0) {
				return map;
			}
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

	// 按当前存储类型返回附件 URL 基础地址（配合 COS 故障自动回退 KV）：
	//   S3（COS 正常）           → r2Domain（cos-exchange 代理 Worker）
	//   R2                       → 本 Worker 的 /api/oss
	//   KV（含 COS 故障回退）     → 本 Worker 的 /attachments（index.js 直读 KV）
	async getBase(c, r2Domain) {
		const type = await r2Service.storageType(c);
		if (type === 'S3') {
			return domainUtils.toOssDomain(r2Domain) || '';
		}
		let origin = '';
		try {
			origin = new URL(c.req.url).origin;
		} catch (e) {}
		if (type === 'R2') {
			return origin ? `${origin}/api/oss` : domainUtils.toOssDomain(r2Domain) || '';
		}
		return origin ? `${origin}/attachments` : '';
	},

	// 给邮件正文中的 {{domain}}attachments/<key> 占位符追加签名参数
	// 并把 {{domain}} 直接替换为当前存储的基础地址（S3→代理域名；KV/R2 回退→本 Worker）
	// 注：不再保留 {{domain}} 占位符，前端 replace 找不到时无副作用
	// keys 来自用户可控的正文：默认只对当前登录用户拥有的 key 签名（超管不受限），其余保持原文不签名
	// opts.allowedUserIds：调用方已知正文归属时（如按邮件行的 userId）可显式传入放宽归属校验
	async signContent(c, content, r2Domain, opts = {}) {
		if (!content) {
			return content;
		}

		const str = String(content);
		if (!str.includes('{{domain}}')) {
			return content;
		}

		const pattern = /\{\{domain\}\}(attachments\/[^"'<>?]+)/g;
		const keys = [...new Set(Array.from(str.matchAll(pattern), m => m[1]))];

		if (keys.length === 0) {
			return content;
		}

		const signMap = await this.signKeys(c, keys, opts);
		const base = await this.getBase(c, r2Domain);

		return str.replace(pattern, (match, key) => {
			const sp = signMap.get(key);
			if (!sp) {
				return match;
			}
			return `${base}/${key}?expires=${sp.expires}&sign=${sp.sign}`;
		});
	},

	// 给附件列表的每一项追加 url 字段（完整带签名地址），key 保持原样
	// 归属校验：keys 全部来自调用方已按权限过滤的 DB 行，故按行上的 userId 校验归属；
	// opts.allowedUserIds 为显式覆盖（null 表示不做限制）
	async addAttUrl(c, attList, r2Domain, opts = {}) {
		if (!attList || attList.length === 0) {
			return;
		}

		const rows = attList.filter(a => a && a.key);
		const keys = rows.map(a => a.key);

		let allowedUserIds = opts.allowedUserIds;
		if (allowedUserIds === undefined) {
			allowedUserIds = [...new Set(rows.map(a => a.userId).filter(id => id !== null && id !== undefined))];
		}

		const signMap = await this.signKeys(c, keys, { allowedUserIds });
		const base = await this.getBase(c, r2Domain);

		for (const att of attList) {
			if (!att || !att.key || !signMap.has(att.key)) {
				continue;
			}
			const sp = signMap.get(att.key);
			att.url = `${base}/${att.key}?expires=${sp.expires}&sign=${sp.sign}`;
		}
	},

	// 恒定时间比较，防时序侧信道（与 cos-exchange / oauth-service 保持一致）
	timingSafeEqual(a, b) {
		if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) {
			return false;
		}
		let diff = 0;
		for (let i = 0; i < a.length; i++) {
			diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
		}
		return diff === 0;
	}
};

export default signUtils;
