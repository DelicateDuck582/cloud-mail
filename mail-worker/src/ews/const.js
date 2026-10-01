/**
 * EWS（Exchange Web Services）桥接层常量。
 *
 * 纯值模块：不 import 任何项目模块，便于 node 直接单测（scripts/test-ews-smoke.mjs）。
 */

// EWS 端点：Thunderbird 145+ 原生「Exchange」账号按服务器 URL 直接访问
// 匹配大小写不敏感（TB 实际请求 /EWS/Exchange.asmx）
export const EWS_PATH = '/ews/exchange.asmx';

// 单次 SyncFolderItems 返回的最大变更数（强制 clamp）：
// Free 计划 CPU 10ms 约束，邮件多时由客户端自动翻页
export const EWS_SYNC_PAGE = 50;

// 认证成功的 KV 缓存 TTL（秒）：减少每请求查库 + SHA-256
// 5 分钟：缓存键含 jwt_secret 加盐，密码变更/封禁最多 5 分钟后对 EWS 生效
export const EWS_AUTH_CACHE_TTL = 300;

// 认证防爆破：同 IP 失败 EWS_AUTH_FAIL_MAX 次后锁 EWS_AUTH_FAIL_WINDOW_MS（与 login-service 同规格）
export const EWS_AUTH_FAIL_MAX = 5;
export const EWS_AUTH_FAIL_WINDOW_MS = 10 * 60 * 1000;
export const EWS_AUTH_FAIL_MAP_MAX = 10000;

// 凭据错误时的响应延迟（毫秒）：与 login-service 的失败延迟对齐，抬高在线爆破成本
export const EWS_AUTH_FAIL_DELAY_MS = 1000;

// 单次请求实际重建 MimeContent（重邮件：MIME + base64 附件）的封数上限：
// 超出部分只回元数据字段，客户端可按需再取，避免一次响应把多封带附件邮件全部重建打爆内存/CPU
export const EWS_MAX_MIME_ITEM_IDS = 20;

// 单个附件（含内嵌图）经 EWS 传输的字节上限：
// Free 计划 10ms CPU 下 base64 编解码的保守值，可用 env.EWS_MAX_ATT_BYTES 调整（付费计划可放大）
export const EWS_DEFAULT_MAX_ATT_BYTES = 1024 * 1024;

// 一次请求原始 XML（含 base64 附件）的上限，防超大 body 打爆 Worker 内存（与 /email/send 的 40MB 对齐）
export const EWS_MAX_REQUEST_BYTES = 40 * 1024 * 1024;

export function ewsMaxAttBytes(env) {
	const value = Number(env?.EWS_MAX_ATT_BYTES);
	return Number.isFinite(value) && value > 0 ? Math.floor(value) : EWS_DEFAULT_MAX_ATT_BYTES;
}

// 单封邮件经 EWS 发送/重建时附件 + 内嵌图的解码后总量上限
export function ewsMaxTotalAttBytes(env) {
	const value = Number(env?.EWS_MAX_TOTAL_ATT_BYTES);
	return Number.isFinite(value) && value > 0 ? Math.floor(value) : ewsMaxAttBytes(env) * 2;
}

// 文件夹：token 即返回给客户端的 FolderId/@Id，客户端回传后按 token 解析
export const EWS_FOLDER_DEFS = [
	{ token: 'root', kind: 'root', displayName: 'CloudMail' },
	{ token: 'inbox', kind: 'inbox', displayName: 'Inbox' },
	{ token: 'sentitems', kind: 'sent', displayName: 'Sent Items' },
	{ token: 'deleteditems', kind: 'trash', displayName: 'Deleted Items' },
	{ token: 'drafts', kind: 'empty', displayName: 'Drafts' },
	{ token: 'outbox', kind: 'empty', displayName: 'Outbox' }
];

// 客户端可能用别的写法回传同一个文件夹（DistinguishedFolderId 名称 + 兼容别名）
export const EWS_FOLDER_ALIASES = {
	msgfolderroot: 'root',
	root: 'root',
	ipm_subtree: 'root',
	allitems: 'inbox',
	inbox: 'inbox',
	sentitems: 'sentitems',
	deleteditems: 'deleteditems',
	drafts: 'drafts',
	outbox: 'outbox'
};

// root 的子文件夹（ChildFolderCount 与层级同步用）
export const EWS_ROOT_CHILDREN = ['inbox', 'sentitems', 'deleteditems', 'drafts', 'outbox'];

export function ewsFolderDef(token) {
	const normalized = String(token ?? '').trim().toLowerCase();
	const canonical = EWS_FOLDER_ALIASES[normalized] || normalized;
	return EWS_FOLDER_DEFS.find((def) => def.token === canonical) || null;
}
