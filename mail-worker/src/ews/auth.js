/**
 * EWS HTTP Basic 认证。
 *
 * 用户名 = CloudMail 登录邮箱，密码 = 登录密码（user 表 salt + SHA-256，见 utils/crypto-utils）。
 * 验证成功把 user 行塞进 Hono context（c.set('user', userRow)），与项目 userContext 约定一致，
 * 后续 handler 可直接复用 email-service / att-service 等现有 service。
 *
 * 防爆破：同 IP 失败 10 次 / 5 分钟锁定（参照 login-service 的 loginFailMap 模式，阈值更宽松以减少误伤）+ 凭据错误 1 秒延迟。
 * 成功结果可写 KV 缓存（ews-auth:sha256(jwt_secret:email:password) → 用户信息，TTL 300s）以减少
 * 每请求查库 + 哈希；键用 jwt_secret 加盐（jwt_secret 未配置时退化为不加盐并告警，生产必配）；
 * 只缓存成功结果，密码变更最多 5 分钟后对 EWS 生效。
 */

import { sql } from 'drizzle-orm';
import orm from '../entity/orm';
import user from '../entity/user';
import { isDel, userConst } from '../const/entity-const';
import saltHashUtils from '../utils/crypto-utils';
import reqUtils from '../utils/req-utils';
import {
	EWS_AUTH_CACHE_TTL,
	EWS_AUTH_FAIL_DELAY_MS,
	EWS_AUTH_FAIL_MAP_MAX,
	EWS_AUTH_FAIL_MAX,
	EWS_AUTH_FAIL_WINDOW_MS
} from './const.js';

const EWS_AUTH_CACHE_PREFIX = 'ews-auth:';

// jwt_secret 缺失只在首个请求告警一次（避免每请求刷日志）
let warnedMissingSalt = false;

const authFailMap = new Map();

function authLocked(ip) {
	const record = authFailMap.get(ip);
	return !!(record && Date.now() - record.t < EWS_AUTH_FAIL_WINDOW_MS && record.c >= EWS_AUTH_FAIL_MAX);
}

function authFailRecord(ip) {
	const record = authFailMap.get(ip);
	const now = Date.now();
	if (!record || now - record.t > EWS_AUTH_FAIL_WINDOW_MS) authFailMap.set(ip, { c: 1, t: now });
	else record.c++;
	if (authFailMap.size > EWS_AUTH_FAIL_MAP_MAX) {
		for (const [key, value] of authFailMap) {
			if (now - value.t > EWS_AUTH_FAIL_WINDOW_MS) authFailMap.delete(key);
		}
	}
}

function authOk(ip) {
	authFailMap.delete(ip);
}

/** 解析 Authorization: Basic base64(user:password) */
export function parseBasicAuth(header) {
	if (!header) return null;
	const match = /^basic\s+([A-Za-z0-9+/=]+)$/i.exec(String(header).trim());
	if (!match) return null;
	let decoded = '';
	try {
		decoded = atob(match[1]);
	} catch (e) {
		return null;
	}
	const index = decoded.indexOf(':');
	if (index < 0) return null;
	const email = decoded.slice(0, index).trim();
	const password = decoded.slice(index + 1);
	if (email === '' || password === '') return null;
	return { email, password };
}

async function sha256Hex(text) {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
	const bytes = new Uint8Array(digest);
	let hex = '';
	for (let i = 0; i < bytes.length; i++) {
		hex += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
	}
	return hex;
}

/**
 * KV 缓存键：sha256(jwt_secret + ':' + email + ':' + password)（email 统一小写）。
 * 用 jwt_secret 加盐，避免仅凭「已知邮箱 + 弱密码字典」离线枚举 KV 键反推/碰撞缓存；
 * jwt_secret 未配置时退化为不加盐的旧键（仅告警一次，生产必须配置 jwt_secret）。
 */
async function authCacheKey(c, email, password) {
	const salt = String(c.env?.jwt_secret ?? '').trim();
	if (salt === '') {
		if (!warnedMissingSalt) {
			warnedMissingSalt = true;
			console.warn('[ews] jwt_secret is not configured: EWS auth cache key is unsalted. Configure jwt_secret in production.');
		}
		return EWS_AUTH_CACHE_PREFIX + await sha256Hex(email.toLowerCase() + ':' + password);
	}
	return EWS_AUTH_CACHE_PREFIX + await sha256Hex(salt + ':' + email.toLowerCase() + ':' + password);
}

function isUsableUser(userRow) {
	return !!userRow && userRow.isDel !== isDel.DELETE && userRow.status !== userConst.status.BAN;
}

async function readCache(c, cacheKey) {
	try {
		const cached = await c.env.kv.get(cacheKey, { type: 'json' });
		if (!cached || !cached.userId) return null;
		return cached;
	} catch (e) {
		return null;
	}
}

async function writeCache(c, cacheKey, userRow) {
	try {
		await c.env.kv.put(cacheKey, JSON.stringify({
			userId: userRow.userId,
			email: userRow.email,
			status: userRow.status,
			isDel: userRow.isDel
		}), { expirationTtl: EWS_AUTH_CACHE_TTL });
	} catch (e) {
		// KV 未绑定/写入失败不影响认证本身
	}
}

async function verifyCredentials(c, email, password) {
	const cacheKey = await authCacheKey(c, email, password);

	const cached = await readCache(c, cacheKey);
	if (cached) {
		if (!isUsableUser(cached)) {
			try {
				await c.env.kv.delete(cacheKey);
			} catch (e) { /* 忽略 */ }
			return null;
		}
		return { userId: cached.userId, email: cached.email };
	}

	const userRow = await orm(c).select().from(user)
		.where(sql`${user.email} COLLATE NOCASE = ${email}`)
		.get();

	if (!isUsableUser(userRow)) return null;

	const passwordOk = await saltHashUtils.verifyPassword(password, userRow.salt, userRow.password);
	if (!passwordOk) return null;

	await writeCache(c, cacheKey, userRow);
	return userRow;
}

/**
 * 认证主入口：成功返回 user 行（已写入 c），失败返回 null（由 router 回 401 + WWW-Authenticate）。
 * 只有「携带了错误的凭据」才计入失败次数：无 Authorization 头的握手探测不计（TB 首次探测即此形态）。
 * 凭据错误返回前统一延迟 EWS_AUTH_FAIL_DELAY_MS（1000ms），与 login-service 的失败延迟对齐。
 */
export async function authenticate(c) {
	const ip = reqUtils.getIp(c);
	const credentials = parseBasicAuth(c.req.header('Authorization'));

	if (!credentials) return null;
	if (authLocked(ip)) return null;

	const userRow = await verifyCredentials(c, credentials.email, credentials.password);

	if (!userRow) {
		authFailRecord(ip);
		// 失败延迟：与 login-service 的 1 秒失败延迟对齐（锁定路径在上面提前返回，不再额外延迟）
		await new Promise((resolve) => setTimeout(resolve, EWS_AUTH_FAIL_DELAY_MS));
		return null;
	}

	authOk(ip);
	return userRow;
}
