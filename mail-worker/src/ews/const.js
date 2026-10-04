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

// 认证防爆破：同 IP 失败 EWS_AUTH_FAIL_MAX 次后锁 EWS_AUTH_FAIL_WINDOW_MS
// 阈值比 login-service 宽松（10 次 / 5 分钟）：EWS 客户端（Thunderbird）重试频繁，过严易误伤正常用户
export const EWS_AUTH_FAIL_MAX = 10;
export const EWS_AUTH_FAIL_WINDOW_MS = 5 * 60 * 1000;
export const EWS_AUTH_FAIL_MAP_MAX = 10000;

// 凭据错误时的响应延迟（毫秒）：与 login-service 的失败延迟对齐，抬高在线爆破成本
export const EWS_AUTH_FAIL_DELAY_MS = 1000;

// 单次请求实际重建 MimeContent（重邮件：MIME + base64 附件）的封数上限：
// 超出部分只回元数据字段，客户端可按需再取，避免一次响应把多封带附件邮件全部重建打爆内存/CPU
export const EWS_MAX_MIME_ITEM_IDS = 20;

// 单个附件（含内嵌图）经 EWS 传输的字节上限：
// Free 计划 10ms CPU 下 base64 编解码的保守值，可用 env.EWS_MAX_ATT_BYTES 调整（付费计划可放大）
export const EWS_DEFAULT_MAX_ATT_BYTES = 1024 * 1024;

// 整个 MimeContent 输出的 CPU 安全预算（base64 编码 ≈8ms + 组装余量）：
// Free 计划单请求 10ms CPU 红线下的保守值，可用 env.EWS_MIME_SAFE_TOTAL 调整（付费计划可放大）。
// 超预算的正文/附件在构建时按降级阶梯裁剪（见 handlers.js buildMimeForRow），保证 GetItem 永不 5xx
export const EWS_MIME_SAFE_TOTAL = 1024 * 1024;

// 重建 MIME 时正文 HTML 的字节上限：超过即截断并追加「请使用网页版查看」提示，
// 防止超大正文的 base64 编码单独吃掉 CPU 预算
export const EWS_HTML_MAX_BYTES = 256 * 1024;

// 一次请求原始 XML（含 base64 附件）的上限，防超大 body 打爆 Worker 内存（与 /email/send 的 40MB 对齐）
export const EWS_MAX_REQUEST_BYTES = 40 * 1024 * 1024;

// EWS 发信（CreateItem）解码后的邮件/附件总字节上限：默认 35MB，给 Resend 的 40MB 请求体留余量。
// 超限在入口直接回中文 Fault，不再等 Resend 返回英文错误。env.EWS_SEND_MAX_BYTES 可调
export const EWS_SEND_MAX_BYTES = 35 * 1024 * 1024;

export function ewsMaxAttBytes(env) {
	const value = Number(env?.EWS_MAX_ATT_BYTES);
	return Number.isFinite(value) && value > 0 ? Math.floor(value) : EWS_DEFAULT_MAX_ATT_BYTES;
}

export function ewsSendMaxBytes(env) {
	const value = Number(env?.EWS_SEND_MAX_BYTES);
	return Number.isFinite(value) && value > 0 ? Math.floor(value) : EWS_SEND_MAX_BYTES;
}

export function ewsMimeSafeTotal(env) {
	const value = Number(env?.EWS_MIME_SAFE_TOTAL);
	return Number.isFinite(value) && value > 0 ? Math.floor(value) : EWS_MIME_SAFE_TOTAL;
}

// 单封邮件经 EWS 发送/重建时附件 + 内嵌图的解码后总量上限：
// 默认对齐 EWS_MIME_SAFE_TOTAL（不再用 2×单附件——那样 base64 后可到 2.7MB，必然超 10ms CPU）
export function ewsMaxTotalAttBytes(env) {
	const value = Number(env?.EWS_MAX_TOTAL_ATT_BYTES);
	return Number.isFinite(value) && value > 0 ? Math.floor(value) : ewsMimeSafeTotal(env);
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

/**
 * 标准 EWS DistinguishedFolderId 名（小写，MS 文档里的完整枚举），本服务未实现它们。
 *
 * Thunderbird「收取邮件」会在一次 GetFolder 里点名一串 Distinguished 文件夹
 * （msgfolderroot/inbox/junkemail/archive/calendar…），其中未实现的若回 ErrorFolderNotFound，
 * TB 见到「成功 + 失败」混合的 GetFolder 响应会中止整个收取流程（后续不再发 Sync*）。
 * 故对它们兜底成「空文件夹成功」（kind='empty'，计数恒 0、恒无邮件，不泄露任何数据）。
 */
export const EWS_EMPTY_DISTINGUISHED_NAMES = new Set([
	'archive', 'calendar', 'contacts', 'conversationhistory', 'journal', 'junkemail',
	'notes', 'searchfolders', 'tasks', 'voicemail', 'nonipmroot', 'publicfoldersroot',
	'imcontactlist', 'quickcontacts', 'companycontacts', 'organizationalcontacts', 'directory',
	'syncissues', 'conflicts', 'localfailures', 'serverfailures',
	'recoverableitemsroot', 'recoverableitemsdeletions', 'recoverableitemsversions',
	'recoverableitemspurges', 'recoverableitemsdiscoveryholds',
	'archivemsgfolderroot', 'archivedeleteditems', 'archiveinbox',
	'archiverecoverableitemsroot', 'archiverecoverableitemsdeletions', 'archiverecoverableitemsversions',
	'archiverecoverableitemspurges', 'archiverecoverableitemsdiscoveryholds'
]);

// 账号文件夹前缀：该用户名下每个收件账号（account 表一行）一个自定义文件夹，
// FolderId = 'acct-<accountId>'（如 acct-3），DisplayName = 账号邮箱地址。
export const EWS_ACCOUNT_FOLDER_PREFIX = 'acct-';

/**
 * 'acct-<accountId>' → 正整数 accountId；其余（Distinguished 名 / 非数字 / 注入串）→ null。
 * token 来自客户端，只接受纯数字主键，绝不把字符串拼进查询。
 */
export function parseAccountFolder(token) {
	const text = String(token ?? '').trim().toLowerCase();
	if (!text.startsWith(EWS_ACCOUNT_FOLDER_PREFIX)) return null;
	const digits = text.slice(EWS_ACCOUNT_FOLDER_PREFIX.length);
	if (!/^\d+$/.test(digits)) return null;
	const value = Number(digits);
	return Number.isSafeInteger(value) && value > 0 ? value : null;
}

/** accountId → 账号文件夹 token（DisplayName 需查 account 表，由 handlers 填充，本层零依赖不查库） */
export function accountFolderId(accountId) {
	return `${EWS_ACCOUNT_FOLDER_PREFIX}${Number(accountId)}`;
}

/**
 * token → 文件夹定义：Distinguished（含别名）优先，其次账号文件夹 'acct-<id>'，
 * 最后是「未实现的标准 Distinguished 名」→ kind='empty' 空文件夹兜底
 * （token/DisplayName 原样回传请求里的 Id，客户端必须能对上自己请求的文件夹）。
 * 账号文件夹的 displayName 留空，由 handlers 用账号邮箱填充；归属（属于当前用户）也在 handlers 校验。
 * 既非 Distinguished 也非 acct- 前缀的非法 token 仍返回 null（调用方回 ErrorFolderNotFound）。
 */
export function ewsFolderDef(token) {
	const original = String(token ?? '').trim();
	const normalized = original.toLowerCase();
	const canonical = EWS_FOLDER_ALIASES[normalized] || normalized;
	const def = EWS_FOLDER_DEFS.find((item) => item.token === canonical);
	if (def) return def;
	const accountId = parseAccountFolder(canonical);
	if (accountId === null) {
		if (EWS_EMPTY_DISTINGUISHED_NAMES.has(canonical)) {
			return { token: original, kind: 'empty', displayName: original };
		}
		return null;
	}
	return { token: accountFolderId(accountId), kind: 'account', accountId, displayName: '' };
}
