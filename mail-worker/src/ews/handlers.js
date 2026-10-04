/**
 * EWS 操作编排（handler）：D1 查询 / COS 读取 / 发信走项目现有 service。
 *
 * 覆盖 Thunderbird 145+ 原生 Exchange 账号会发起的操作：
 *   GetFolder / FindFolder / SyncFolderHierarchy / SyncFolderItems / GetItem / GetAttachment /
 *   CreateItem / UpdateItem / DeleteItem / SendItem /
 *   ResolveNames / GetMailTips / GetServerTimeZones（TB 账号验证阶段会发，
 *   其中 ResolveNames 缺一条 Fault 就会被 TB 当成「身份验证出错」）
 * 其余操作统一回 ErrorNotImplemented Fault（TB 会自动降级，如轮询代替推送）。
 *
 * 约定：
 *   - 可见域：Distinguished 文件夹（收件箱/已发送/已删除）按用户聚合（userId 全量，信息不丢）；
 *     该用户名下每个收件账号（account 表一行）另有一个自定义文件夹：FolderId = acct-<accountId>、
 *     DisplayName = 账号邮箱，只含该账号的可见收件（type=0, is_del=0, trash=0）；
 *   - 所有按 Id 取数据的操作强制 where userId = 当前登录用户，防越权；账号文件夹额外校验
 *     account.user_id = 当前用户（他人账号按 ErrorFolderNotFound 处理，不泄露存在性）；
 *   - 以纯元数据为主，只有 GetItem(MimeContent) / GetAttachment / CreateItem 触碰 COS；
 *   - 邮件「最后修改时间」= COALESCE(NULLIF(update_time,''), create_time)（同为
 *     'YYYY-MM-DD HH:mm:ss' text，字典序即时间序），增量水位存 ews_sync_state；
 *   - XML 字符串生成全部在 protocol.js（纯函数，可 node 单测）。
 */

import { and, asc, count, desc, eq, getTableColumns, inArray, isNull, lt, lte, or, sql } from 'drizzle-orm';
import dayjs from 'dayjs';
import PostalMime from 'postal-mime';
import orm from '../entity/orm';
import email from '../entity/email';
import account from '../entity/account';
import { att } from '../entity/att';
import emailService from '../service/email-service';
import accountService from '../service/account-service';
import r2Service from '../service/r2-service';
import { attConst, emailConst, isDel } from '../const/entity-const';
import BizError from '../error/biz-error';
import { buildMimeBase64 } from './mime-build.js';
import {
	EWS_HTML_MAX_BYTES,
	EWS_MAX_MIME_ITEM_IDS,
	EWS_ROOT_CHILDREN,
	EWS_SYNC_PAGE,
	accountFolderId,
	ewsFolderDef,
	ewsMaxAttBytes,
	ewsMaxTotalAttBytes,
	ewsMimeSafeTotal
} from './const.js';
import {
	asArray,
	attr,
	children,
	escapeXml,
	firstChild,
	isTrueFlag,
	operationResponse,
	responseMessage,
	textOf
} from './xml.js';
import {
	attBudgetAllows,
	base64DecodedSize,
	base64EncodeBytes,
	base64ToBytes,
	buildFolderXml,
	buildItemXml,
	changeKeyOf,
	classifySyncRow,
	cleanBase64,
	createItemItemsXml,
	decodeSyncState,
	emptySyncState,
	encodeSyncState,
	findFolderRootXml,
	isInlineAttachment,
	isSentRow,
	mailTipsXml,
	mimeContentIdSet,
	parseAddressList,
	parseMailbox,
	parseMailboxList,
	parseMimeFrom,
	replaceInlineImagesWithPlaceholder,
	resolutionSetXml,
	resolveNameMatches,
	selectTombstoneDeletes,
	skippedAttachmentsHtml,
	skippedAttachmentsText,
	splitOutgoingAttachments,
	stripCidBrackets,
	timeZoneDefinitionsXml,
	toDateMs,
	truncateUtf8Bytes
} from './protocol.js';

/** EWS 业务错误：由 router 统一转成 SOAP Fault */
export class EwsFault extends Error {
	constructor(responseCode, message) {
		super(message);
		this.name = 'EwsFault';
		this.responseCode = responseCode;
	}
}

// ---------------------------------------------------------------- 基础工具 ----

function nowText() {
	return dayjs().format('YYYY-MM-DD HH:mm:ss');
}

function isMissingColumnError(error) {
	return /no such column/i.test(String(error?.message || error || ''));
}

function requireMigrated(error) {
	if (!isMissingColumnError(error)) throw error;
	throw new EwsFault('ErrorInternalServerError',
		'Database is not upgraded: run the project init endpoint to apply migration v4_4DB (email.update_time / ews_sync_state).');
}

/** 邮件「最后修改时间」表达式（update_time 未回填/为 NULL 时回落 create_time） */
function effTime() {
	return sql`COALESCE(NULLIF(update_time, ''), create_time)`;
}

function emailSelect() {
	return { ...getTableColumns(email), eff: sql`COALESCE(NULLIF(update_time, ''), create_time)`.as('eff') };
}

// ---------------------------------------------------------------- 文件夹 ----

const DISTINGUISHED_IDS = ['FolderId', 'DistinguishedFolderId'];

/**
 * 与登录邮箱同名的收件账号行（必须属于当前 user）：发件账号优先选它（CreateItem），
 * 账号文件夹排序也以它为首（EWS 账户 = 该地址的直觉）。
 * account.email 是 NOCASE 唯一索引，但列默认 BINARY 排序规则 → 需显式 COLLATE NOCASE 才大小写不敏感。
 * 无同名账号（或用户信息不完整）返回 null。
 */
function selectLoginEmailAccount(c, user) {
	const userId = Number(user?.userId);
	const address = String(user?.email ?? '').trim();
	if (!Number.isInteger(userId) || userId <= 0 || address === '') return Promise.resolve(null);
	return orm(c).select().from(account)
		.where(and(eq(account.userId, userId), sql`${account.email} COLLATE NOCASE = ${address}`))
		.get();
}

/** 同名账号的 accountId（number）；无同名账号 → null */
async function resolveUserAccount(c, user) {
	const row = await selectLoginEmailAccount(c, user);
	return row ? Number(row.accountId) : null;
}

/**
 * 按 From 地址在当前用户名下查收件账号（account.email NOCASE 等值，与同名账号查询同一口径）。
 * 查不到 = 该地址不属于当前用户（含他人账号 / 不存在的地址）→ 返回 null，调用方拒绝发信。
 */
function selectOwnedAccountByEmail(c, userId, address) {
	const id = Number(userId);
	const value = String(address ?? '').trim();
	if (!Number.isInteger(id) || id <= 0 || value === '') return Promise.resolve(null);
	return orm(c).select().from(account)
		.where(and(eq(account.userId, id), sql`${account.email} COLLATE NOCASE = ${value}`))
		.get();
}

/** 该用户名下的全部收件账号（账号文件夹的来源，一个账号一个文件夹）；account_id 升序保证顺序稳定 */
async function selectUserAccounts(c, userId) {
	return orm(c).select({ accountId: account.accountId, email: account.email })
		.from(account)
		.where(eq(account.userId, userId))
		.orderBy(asc(account.accountId))
		.all();
}

/**
 * 当前用户名下的账号（accountId → 邮箱）：账号文件夹的 DisplayName 与归属校验。
 * 他人账号 / 不存在的账号不在结果里 → 调用方按 ErrorFolderNotFound 处理（不泄露账号是否存在）。
 */
async function selectOwnedAccounts(c, userId, accountIds) {
	const result = new Map();
	const ids = [...new Set((accountIds || []).map(Number)
		.filter((id) => Number.isSafeInteger(id) && id > 0))];
	if (ids.length === 0) return result;
	for (const chunk of chunkList(ids)) {
		const rows = await orm(c).select({ accountId: account.accountId, email: account.email })
			.from(account)
			.where(and(eq(account.userId, userId), inArray(account.accountId, chunk)))
			.all();
		for (const row of rows) result.set(Number(row.accountId), String(row.email ?? ''));
	}
	return result;
}

/** 账号文件夹定义：FolderId = acct-<accountId>，DisplayName = 账号邮箱（查 account 表后填充） */
function accountFolderDef(accountId, address) {
	return {
		token: accountFolderId(accountId),
		kind: 'account',
		accountId: Number(accountId),
		displayName: String(address ?? '')
	};
}

/** 账号文件夹的收件账号条件；accountId 非法（非数字 / <=0）→ null（调用方回永不匹配条件，绝不放宽为全量） */
function accountFilter(accountId) {
	const value = Number(accountId);
	if (!Number.isFinite(value) || value <= 0) return null;
	return eq(email.accountId, value);
}

/**
 * 正常列表可见的邮件条件；trash 文件夹为垃圾桶语义（与 Web 端一致）。
 * accountId 仅账号文件夹（kind='account'）使用：只含该账号的可见收件；
 * Distinguished 文件夹不传（用户级聚合，见 handlers 头部约定）。
 */
function visibleFilter(kind, userId, accountId = null) {
	if (kind === 'account') {
		const scoped = accountFilter(accountId);
		if (scoped === null) return sql`1 = 0`;
		return and(
			eq(email.userId, userId),
			scoped,
			eq(email.type, emailConst.type.RECEIVE),
			eq(email.isDel, isDel.NORMAL),
			eq(email.trash, 0)
		);
	}
	if (kind === 'inbox') {
		return and(
			eq(email.userId, userId),
			eq(email.type, emailConst.type.RECEIVE),
			eq(email.isDel, isDel.NORMAL),
			eq(email.trash, 0)
		);
	}
	if (kind === 'sent') {
		return and(
			eq(email.userId, userId),
			eq(email.type, emailConst.type.SEND),
			eq(email.isDel, isDel.NORMAL),
			eq(email.trash, 0)
		);
	}
	if (kind === 'trash') {
		// 软删进垃圾桶（trash=1）；附件彻底删除会连带把邮件标 isDel=1（att-service.purgeAttRows）
		return and(eq(email.userId, userId), or(eq(email.trash, 1), eq(email.isDel, isDel.DELETE)));
	}
	// 空文件夹（drafts/outbox，以及未实现的 Distinguished 兜底兜出的空文件夹）：恒不可见，
	// 绝不放宽为全量（返回 null 会被 drizzle 忽略成无 where 条件 → 扫到全部用户的数据）
	if (kind === 'empty') return sql`1 = 0`;
	return null;
}

/**
 * 增量扫描范围（含垃圾桶里的行，用于产出 Delete 事件）。
 * 账号文件夹的范围 = 该账号的全部收件（含已进垃圾桶/已删的行），可见性由 classifySyncRow 判定。
 */
function scopeFilter(kind, userId, accountId = null) {
	if (kind === 'account') {
		const scoped = accountFilter(accountId);
		if (scoped === null) return sql`1 = 0`;
		return and(eq(email.userId, userId), scoped, eq(email.type, emailConst.type.RECEIVE));
	}
	if (kind === 'inbox') return and(eq(email.userId, userId), eq(email.type, emailConst.type.RECEIVE));
	if (kind === 'sent') return and(eq(email.userId, userId), eq(email.type, emailConst.type.SEND));
	if (kind === 'trash') return eq(email.userId, userId);
	// 空文件夹（含未实现的 Distinguished 兜底）：扫描域为空（同 visibleFilter，绝不退化成全量）
	if (kind === 'empty') return sql`1 = 0`;
	return null;
}

function isMailFolder(kind) {
	return kind === 'inbox' || kind === 'sent' || kind === 'trash' || kind === 'account';
}

/**
 * 初始全量的分页游标哨兵：fresh sync 必须先走「历史积压分页」把老邮件按 emailId 倒序
 * 分批发给客户端（否则客户端只会收到水位之后的增量，历史邮件全丢）。
 */
const FRESH_CURSOR = Number.MAX_SAFE_INTEGER;

/** 文件夹请求里的 Id（SyncFolderId / FolderIds 内的 DistinguishedFolderId 或 FolderId） */
function containerFolderToken(container) {
	if (!container || typeof container !== 'object') return '';
	const node = firstChild(container, 'FolderId') ?? firstChild(container, 'DistinguishedFolderId');
	return attr(node, 'Id') || '';
}

/**
 * 取容器里的全部文件夹 Id：children() 取同名元素的全部（文件夹 Id 可重复），
 * 单元素时 fast-xml-parser 不返回数组，故禁止用 firstChild。命名空间前缀已被解析器剥离。
 * 容器名由调用方指定：FolderIds（GetFolder）/ ParentFolderIds（FindFolder）。
 * 按容器内元素的出现顺序取（同一元素名的重复项本身就是数组，顺序不变）：响应顺序 = 请求顺序，
 * 客户端按序对齐请求项与 ResponseMessage（仅两种 Id 元素相互交错时会被解析器按名归组而重排）。
 */
function extractFolderTokens(payload, containerName = 'FolderIds') {
	const container = firstChild(payload, containerName);
	if (!container || typeof container !== 'object') return [];
	const tokens = [];
	for (const [name, value] of Object.entries(container)) {
		if (!DISTINGUISHED_IDS.includes(name)) continue;
		for (const node of asArray(value)) {
			const token = attr(node, 'Id');
			if (token) tokens.push(token);
		}
	}
	return tokens;
}

function extractItemIds(payload) {
	const container = firstChild(payload, 'ItemIds');
	const ids = [];
	for (const node of children(container, 'ItemId')) {
		const value = Number(attr(node, 'Id'));
		if (Number.isFinite(value) && value > 0 && !ids.includes(value)) ids.push(value);
	}
	return ids;
}

// D1 单条语句最多 100 个绑定参数（与 att-service 的 SQL_BIND_LIMIT 同规格）
const SQL_BIND_LIMIT = 90;
// 单次 GetItem/GetAttachment 的 Id 上限：防一次性重建大量 MimeContent 打爆 Worker 内存
const EWS_MAX_ITEM_IDS = 200;

function chunkList(list, size = SQL_BIND_LIMIT) {
	const chunks = [];
	for (let i = 0; i < list.length; i += size) chunks.push(list.slice(i, i + size));
	return chunks;
}

function assertBatchSize(ids, operation) {
	if (ids.length <= EWS_MAX_ITEM_IDS) return;
	throw new EwsFault('ErrorMaxBatchSizeExceeded',
		`Too many ids in one ${operation} call (${ids.length} > ${EWS_MAX_ITEM_IDS}).`);
}

async function folderCounts(c, userId, kind, accountId = null) {
	if (!isMailFolder(kind)) return { total: 0, unread: 0 };
	const row = await orm(c).select({
		total: count(),
		unread: sql`SUM(CASE WHEN ${email.unread} = ${emailConst.unread.UNREAD} THEN 1 ELSE 0 END)`
	}).from(email).where(visibleFilter(kind, userId, accountId)).get();
	return { total: Number(row?.total) || 0, unread: Number(row?.unread) || 0 };
}

// ------------------------------------------------------------ 附件读取 ----

/** 批量查询「是否有真实附件」（与 Web 端附件列表口径一致：type=0 且无 contentId） */
async function attachmentPresence(c, emailIds) {
	const result = new Map();
	if (emailIds.length === 0) return result;
	const unique = [...new Set(emailIds)];
	for (const chunk of chunkList(unique)) {
		const rows = await orm(c).select({ emailId: att.emailId, total: count() }).from(att)
			.where(and(
				inArray(att.emailId, chunk),
				eq(att.type, attConst.type.ATT),
				isNull(att.contentId)
			))
			.groupBy(att.emailId)
			.all();
		for (const row of rows) result.set(row.emailId, Number(row.total) > 0);
	}
	return result;
}

/** 按 Id 批量取邮件（强制 userId 归属；分片避免超过 D1 绑定参数上限） */
async function selectOwnedEmails(c, userId, ids) {
	const rows = [];
	for (const chunk of chunkList(ids)) {
		const part = await orm(c).select(emailSelect()).from(email)
			.where(and(eq(email.userId, userId), inArray(email.emailId, chunk)))
			.all();
		rows.push(...part);
	}
	return rows;
}

async function attachmentRows(c, emailId, userId) {
	return orm(c).select().from(att)
		.where(and(eq(att.emailId, emailId), eq(att.userId, userId)))
		.orderBy(asc(att.attId))
		.all();
}

/**
 * 本次响应「已重建附件字节」账本：跨本次响应内多封邮件累计。
 * 上限取 EWS_MAX_TOTAL_ATT_BYTES（env 可调小/调大）与 EWS_MIME_SAFE_TOTAL
 * （CPU 硬预算）的较小者：附件解码字节被压在安全预算内，base64 输出才有 ≤1.4× 预算的可能。
 * 超过 limit 后剩余附件走「跳过」路径（与单附件超限同一处理），避免一次响应重建过多附件打爆内存/CPU。
 */
function newAttBudget(c) {
	return {
		total: 0,
		limit: Math.min(ewsMaxTotalAttBytes(c.env), ewsMimeSafeTotal(c.env)),
		warned: false
	};
}

/**
 * 记录被跳过的内嵌图在正文里的引用形态：`cid:<contentId>`（成功替换后的形态）
 * 与 `{{domain}}<key>`（库内正文的原始形态），供循环后把 <img ...> 整段换成可见占位。
 * 普通附件（非内嵌图）被跳过时不记录引用，但会进统一占位清单（skippedItems）。
 */
function collectSkippedInlineRef(refs, attRow) {
	if (!isInlineAttachment(attRow)) return;
	const key = String(attRow.key ?? '');
	const contentId = stripCidBrackets(attRow.contentId) || stripCidBrackets(key);
	if (contentId !== '') refs.add(`cid:${contentId}`);
	if (key !== '') refs.add(`{{domain}}${key}`);
}

/** 附件在占位清单里的展示名：filename 缺失回落 key，再缺给固定文案 */
function attachmentDisplayName(attRow) {
	return String(attRow?.filename ?? '').trim() || String(attRow?.key ?? '').trim() || '未命名附件';
}

/**
 * 极简降级 MIME：只回一段 text/plain（主题/日期仍可见），用于重建异常或极端超限。
 * 绝不抛错：连极简 MIME 都构建失败时返回 ''（TB 侧只剩元数据，同样不会白屏）。
 */
function minimalMimeForRow(row) {
	try {
		const dateMs = toDateMs(row?.createTime);
		return buildMimeBase64({
			from: { email: row?.sendEmail, name: row?.name },
			to: rowRecipientsForMime(row),
			subject: row?.subject,
			dateMs: Number.isFinite(dateMs) ? dateMs : Date.now(),
			messageId: row?.messageId,
			text: '此邮件包含较大内容，无法在当前客户端加载，请使用网页版查看。'
				+ `\n邮件主题：${String(row?.subject ?? '')}`
				+ `\n邮件日期：${String(row?.createTime ?? '')}`
		});
	} catch (error) {
		console.warn(`[ews] minimal fallback MIME failed for email ${row?.emailId}: ${String(error?.message || error)}`);
		return '';
	}
}

/**
 * 用 COS 附件 + 库内正文重建完整 MIME（base64），供 EWS MimeContent。
 *
 * 防白屏降级阶梯（Free 计划 10ms CPU：base64 编码约 130KB/ms，任何一步都不能让输出失控）：
 *   ① 正文：text 保留；html > EWS_HTML_MAX_BYTES 截断 + 末尾提示用网页版；
 *   ② 内嵌图 / 普通附件统一护栏：单个 > EWS_MAX_ATT_BYTES 跳过；本次响应累计超账本跳过；
 *   ③ 所有被跳过项（内嵌图 + 普通附件）进统一占位清单，附在正文 HTML / text 末尾；
 *      正文为空（纯附件邮件）时清单本身就是正文——清单始终输出，绝不静默；
 *   ④ 构建后自查：解码后的原始 MIME 字节 ≤ EWS_MIME_SAFE_TOTAL × 1.4，超了先砍 html、再砍 text（附件已受账本约束）；
 *      两级降级都把占位清单保留为 text/html 正文，避免降级后连「附件被跳过」的提示都丢掉；
 *   ⑤ 整体 try/catch：任何异常 → 极简 text/plain 降级 MIME，绝不向上抛错（GetItem 永远 200/Success）。
 */
async function buildMimeForRow(c, row, maxAttBytes, budget) {
	try {
		return await buildMimeWithinSafeBudget(c, row, maxAttBytes, budget);
	} catch (error) {
		// 兜底阶梯：DB/COS/组装任何一步抛错都不上抛——上抛 = TB 白屏/收信中断
		console.warn(`[ews] MimeContent rebuild failed for email ${row?.emailId}; using minimal fallback MIME: ${String(error?.message || error)}`);
		return minimalMimeForRow(row);
	}
}

/** buildMimeForRow 的正常路径（异常由外层统一兜底） */
async function buildMimeWithinSafeBudget(c, row, maxAttBytes, budget) {
	const safeTotal = ewsMimeSafeTotal(c.env);
	const ledger = budget ?? { total: 0, limit: 0, warned: false };
	const rows = await attachmentRows(c, row.emailId, row.userId);
	let html = row.content || '';
	let text = row.text || '';
	const inlineImages = [];
	const attachments = [];
	// 被跳过的内嵌图引用：循环后统一把正文里的 <img> 换成文字占位（图片无声消失用户无从得知）
	const skippedInlineRefs = new Set();
	// 被跳过的项（内嵌图 + 普通附件）：统一进正文末尾的占位清单
	const skippedItems = [];

	for (const attRow of rows) {
		const inline = isInlineAttachment(attRow);
		// ① 单附件超限：不进 MIME（读 COS 前就跳过，不产生字节读取），进占位清单
		if ((Number(attRow.size) || 0) > maxAttBytes) {
			collectSkippedInlineRef(skippedInlineRefs, attRow);
			skippedItems.push({ filename: attachmentDisplayName(attRow), size: attRow.size });
			continue;
		}
		// ② 本次响应累计护栏：多封邮件累计超出账本后，剩余附件同样跳过（普通附件不再静默卷入重建）
		if (!attBudgetAllows(ledger, attRow.size)) {
			if (!ledger.warned) {
				ledger.warned = true;
				console.warn(`[ews] rebuilding MimeContent hit the total attachment budget (${ledger.limit} bytes): remaining attachments are skipped in this response.`);
			}
			collectSkippedInlineRef(skippedInlineRefs, attRow);
			skippedItems.push({ filename: attachmentDisplayName(attRow), size: attRow.size });
			continue;
		}
		const object = await r2Service.getObj(c, attRow.key);
		if (!object) continue;
		const data = new Uint8Array(await object.arrayBuffer());
		ledger.total += data.length;

		if (inline) {
			// 库内正文引用 {{domain}}attachments/<key>，mime-build 需要 cid:<contentId>
			const contentId = stripCidBrackets(attRow.contentId) || stripCidBrackets(attRow.key);
			html = html.split(`{{domain}}${attRow.key}`).join(`cid:${contentId}`);
			inlineImages.push({
				contentId,
				filename: attRow.filename,
				mimeType: attRow.mimeType,
				data
			});
		} else {
			attachments.push({ filename: attRow.filename, mimeType: attRow.mimeType, data });
		}
	}

	// 被跳过的内嵌图：正文里引用它的整段 <img ...> 替换为可见占位（提示大小阈值与网页版入口），
	// 成功重建的内嵌图此刻已是 cid: 形态、不受影响
	html = replaceInlineImagesWithPlaceholder(html, skippedInlineRefs, maxAttBytes);

	// ① 正文 HTML 超 EWS_HTML_MAX_BYTES → 截断 + 末尾提示（占位清单在截断之后追加，不会被截掉）
	const cut = truncateUtf8Bytes(html, EWS_HTML_MAX_BYTES);
	if (cut.truncated) html = `${cut.text}（内容过长已截断，请使用网页版查看完整内容）`;

	// ③ 被跳过项统一清单：HTML 正文末尾一份、text/plain 末尾一份。
	//    清单始终输出：正文为空（纯附件邮件）时清单本身就是正文，否则用户既看不到附件也看不到任何提示。
	const manifestHtml = skippedAttachmentsHtml(skippedItems);
	const manifestText = skippedAttachmentsText(skippedItems);
	if (manifestHtml !== '') html = html !== '' ? html + manifestHtml : manifestHtml;
	if (manifestText !== '') text = text !== '' ? text + '\n' + manifestText : manifestText;

	const dateMs = toDateMs(row.createTime);
	const input = {
		from: { email: row.sendEmail, name: row.name },
		to: rowRecipientsForMime(row),
		// cc/bcc 列是 JSON 字符串（[{address,name}]），必须解析成数组再交给 mime-build
		cc: parseAddressList(row.cc),
		bcc: parseAddressList(row.bcc),
		subject: row.subject,
		dateMs: Number.isFinite(dateMs) ? dateMs : Date.now(),
		messageId: row.messageId,
		inReplyTo: row.inReplyTo,
		references: row.relation,
		text,
		html,
		inlineImages,
		attachments
	};

	// ④ 构建后自查：MimeContent 解码后的原始 MIME 字节 ≤ EWS_MIME_SAFE_TOTAL × 1.4。
	//    口径说明：附件/正文在 MIME 内层已 base64 过一次（×4/3），EWS 的 MimeContent 再对整封
	//    base64 一次；1.4× 覆盖内层膨胀 + boundary/头，外层编码量正比于此、由 ④ 兜底。
	//    超了继续降级：先砍正文 html（只留占位清单 + text），仍超再砍 text（清单极小，始终保留为正文；
	//    附件已受账本约束，理论上到不了再砍清单这步）
	const safeRawBytes = Math.floor(safeTotal * 1.4);
	let mime = buildMimeBase64(input);
	if (base64DecodedSize(mime) > safeRawBytes) {
		console.warn(`[ews] MimeContent raw size exceeds the safe budget (email ${row.emailId}), dropping html body.`);
		// 砍原 html 正文，但占位清单不能丢：它是被跳过附件在客户端的唯一提示，且只有 <p> 一小段
		input.html = manifestHtml;
		if (input.text === '' && manifestText !== '') input.text = manifestText;
		mime = buildMimeBase64(input);
	}
	if (base64DecodedSize(mime) > safeRawBytes) {
		console.warn(`[ews] MimeContent raw size still exceeds the safe budget after dropping html (email ${row.emailId}), dropping text body.`);
		input.text = '';
		// 有清单时视为非空正文，保留为 text/html 单体（mime-build 对 text/html 皆空会输出空 text/plain，清单会被丢）
		input.html = manifestHtml;
		mime = buildMimeBase64(input);
	}
	if (base64DecodedSize(mime) > safeRawBytes) {
		// 附件账本 ≤ EWS_MIME_SAFE_TOTAL 时数学上不应到达：真到了就整封走极简降级，绝不输出超大响应
		console.warn(`[ews] MimeContent raw size exceeds the safe budget even without bodies (email ${row.emailId}); minimal fallback.`);
		return minimalMimeForRow(row);
	}
	return mime;
}

/** MimeContent 侧的收件人：recipient（JSON）优先，缺失回落 toEmail */
function rowRecipientsForMime(row) {
	let list = [];
	try {
		const parsed = JSON.parse(row.recipient || '[]');
		if (Array.isArray(parsed)) {
			list = parsed
				.map((item) => ({ email: item?.address ?? item?.email, name: item?.name }))
				.filter((item) => item.email);
		}
	} catch (e) {
		list = [];
	}
	if (list.length === 0 && row.toEmail) list.push({ email: row.toEmail, name: row.toName });
	return list;
}

// ------------------------------------------------------------ 同步状态 ----

/** 读取 D1 里的水位（仅作「客户端 SyncState 不可解析时」的续传回退） */
async function readStoredSyncState(c, userId, folder) {
	try {
		const row = await c.env.db.prepare('SELECT sync_state FROM ews_sync_state WHERE user_id = ? AND folder = ?')
			.bind(userId, folder).first();
		if (!row?.sync_state) return null;
		return decodeSyncState(row.sync_state);
	} catch (e) {
		return null;
	}
}

async function storeSyncState(c, userId, folder, state) {
	try {
		await c.env.db.prepare(
			`INSERT INTO ews_sync_state (user_id, folder, sync_state, update_time)
			 VALUES (?, ?, ?, ?)
			 ON CONFLICT(user_id, folder) DO UPDATE SET sync_state = excluded.sync_state, update_time = excluded.update_time`
		).bind(userId, folder, encodeSyncState(state), Date.now()).run();
	} catch (e) {
		// 表未建（未执行迁移）不影响同步本身：SyncState 由客户端回传
	}
}

/** 当前可见邮件的最大「最后修改时间」= 初始全量水位快照 */
async function snapshotWatermark(c, userId, kind, accountId = null) {
	try {
		const row = await orm(c).select({ wm: sql`MAX(${effTime()})` }).from(email)
			.where(visibleFilter(kind, userId, accountId)).get();
		if (row?.wm === null || row?.wm === undefined) return '';
		return String(row.wm);
	} catch (error) {
		requireMigrated(error);
	}
}

/**
 * 物理删除 tombstone（邮件行已不存在：附件彻底删除 / 自动清理等服务器主动物理删）。
 * 表由 v4_4DB 建；表不存在（未迁移）时不产出 Delete 事件，绝不影响其余同步。
 */
async function readTombstones(c, userId, watermark) {
	try {
		const result = await c.env.db.prepare(
			`SELECT email_id, type, trash FROM ews_tombstone
			 WHERE user_id = ? AND del_time > ?
			 ORDER BY del_time ASC, email_id ASC`
		).bind(userId, watermark).all();
		return Array.isArray(result?.results) ? result.results : [];
	} catch (error) {
		if (/no such table/i.test(String(error?.message || error))) return [];
		throw error;
	}
}

// ---------------------------------------------------------------- GetFolder ----

async function handleGetFolder(c, payload, user) {
	const userId = user.userId;
	const tokens = extractFolderTokens(payload);
	if (tokens.length === 0) {
		throw new EwsFault('ErrorInvalidRequest', 'GetFolder requires FolderIds.');
	}

	// TB 一次 GETFOLDER 点名一串 DistinguishedFolderId（msgfolderroot 第一个）并按序 zip 请求项与
	// ResponseMessages：数量必须 = 请求数、顺序必须 = 请求顺序，root 必须第一条且成功
	// → 逐个 token 产出一条 ResponseMessage（每条只含自己那个文件夹），绝不合并成一条。
	const defs = tokens.map((token) => ewsFolderDef(token));
	// 账号文件夹：批量取当前用户名下的账号行（DisplayName = 账号邮箱）
	// 查不到 = 不属于当前用户（或已不存在）→ ErrorFolderNotFound，不泄露账号是否存在
	const ownedAccounts = await selectOwnedAccounts(c, userId, defs.map((def) => def?.accountId));

	const messages = [];
	for (let i = 0; i < tokens.length; i++) {
		const token = tokens[i];
		const def = defs[i];
		if (!def || (def.kind === 'account' && !ownedAccounts.has(def.accountId))) {
			messages.push(responseMessage('GetFolder', {
				responseClass: 'Error',
				responseCode: 'ErrorFolderNotFound',
				messageText: `Folder not found: ${token}`
			}));
			continue;
		}
		let xmlDef = def;
		let changeKey = '1';
		if (def.kind === 'account') {
			xmlDef = accountFolderDef(def.accountId, ownedAccounts.get(def.accountId));
			changeKey = String(def.accountId);
		} else if (def.kind === 'root') {
			// root 的 ChildFolderCount 含账号文件夹（与 SyncFolderHierarchy 的 Create 集合自洽）
			const accounts = await selectUserAccounts(c, userId);
			xmlDef = { ...def, extraChildCount: accounts.length };
		}
		messages.push(responseMessage('GetFolder', {
			body: `<m:Folders>${buildFolderXml(xmlDef,
				await folderCounts(c, userId, def.kind, def.accountId), changeKey)}</m:Folders>`
		}));
	}

	const xml = operationResponse('GetFolder', messages.join(''));
	// 诊断（TB「收取邮件」只发 GetFolder、后续 Sync* 静默缺席时用）：完整输出（该请求频率低，日志量可控），
	// 需要看到响应中后段（每个 FolderId 的 ChildFolderCount/DisplayName）才能判断 TB 为何不再继续
	console.log('EWS GetFolder resp:', xml);
	return xml;
}

// ---------------------------------------------------------------- FindFolder ----

/**
 * root（msgfolderroot / ipm_subtree 别名同为 'root'）的子文件夹：5 个 Distinguished（inbox/sentitems/
 * deleteditems/drafts/outbox）+ 当前用户名下每个账号文件夹（acct-<id>，DisplayName = 账号邮箱）。
 * 与 SyncFolderHierarchy 的 Create 集合口径一致；他人账号天然不在 selectUserAccounts 结果里（跳过）。
 */
async function rootChildFolders(c, userId) {
	const folders = [];
	for (const childToken of EWS_ROOT_CHILDREN) {
		const def = ewsFolderDef(childToken);
		folders.push(buildFolderXml(def, await folderCounts(c, userId, def.kind)));
	}
	for (const row of await selectUserAccounts(c, userId)) {
		const def = accountFolderDef(row.accountId, row.email);
		folders.push(buildFolderXml(def, await folderCounts(c, userId, 'account', def.accountId),
			String(def.accountId)));
	}
	return folders;
}

/**
 * FindFolder：枚举父文件夹的子文件夹（TB 拉文件夹树的另一条路径，与 SyncFolderHierarchy 并列）。
 * 请求形如 <m:FindFolder Traversal="Shallow"><m:ParentFolderIds><t:DistinguishedFolderId Id="msgfolderroot"/>…
 *   - 每个 ParentFolderId 一条 ResponseMessage（顺序与请求一致，客户端按序对齐）；
 *   - root/msgfolderroot → 全部子文件夹；其余父（Distinguished / 账号文件夹）→ 空列表（浅遍历，
 *     Traversal 忽略：本服务的层级只有两层）；
 *   - 账号文件夹父需归属校验，他人账号 → 与不存在的文件夹同一错误（不泄露账号是否存在）；
 *   - 未知 token → ResponseClass=Error + ErrorFolderNotFound（绝不兜底成空列表）。
 * FolderShape/BaseShape 忽略：恒回完整字段（IdOnly 的客户端只读 FolderId，多余字段无害）。
 */
async function handleFindFolder(c, payload, user) {
	const userId = user.userId;
	const tokens = extractFolderTokens(payload, 'ParentFolderIds');
	if (tokens.length === 0) {
		throw new EwsFault('ErrorInvalidRequest', 'FindFolder requires ParentFolderIds.');
	}

	// 账号文件夹：批量取当前用户名下的账号行一次（DisplayName = 账号邮箱 + 归属校验共用）
	const defs = tokens.map((token) => ewsFolderDef(token));
	const ownedAccounts = await selectOwnedAccounts(c, userId,
		defs.map((def) => def?.accountId));

	const messages = [];
	for (let i = 0; i < tokens.length; i++) {
		const token = tokens[i];
		const def = defs[i];
		if (!def || (def.kind === 'account' && !ownedAccounts.has(def.accountId))) {
			messages.push(responseMessage('FindFolder', {
				responseClass: 'Error',
				responseCode: 'ErrorFolderNotFound',
				messageText: `Folder not found: ${token}`
			}));
			continue;
		}
		// 浅遍历：只有 root 有子文件夹；Distinguished / 账号文件夹都是叶子（回空列表，不是错误）
		const folders = def.kind === 'root' ? await rootChildFolders(c, userId) : [];
		messages.push(responseMessage('FindFolder', { body: findFolderRootXml(folders) }));
	}

	return operationResponse('FindFolder', messages.join(''));
}

// ------------------------------------------------- SyncFolderHierarchy --------

async function handleSyncFolderHierarchy(c, payload, user) {
	const userId = user.userId;
	const token = textOf(firstChild(payload, 'SyncState')).trim();

	// 文件夹集合是静态的（Inbox/Sent/Deleted/Drafts/Outbox + 每个收件账号一个 acct-<id>）：
	// 已有 SyncState 直接回空变更（账号列表变化不做增量：TB 重建账户时重新全量取）
	// 三件套恒存在（TB 硬校验）：SyncState（非空）+ IncludesLastFolderInRange + Changes（可为空）
	if (token !== '' && decodeSyncState(token)) {
		return operationResponse('SyncFolderHierarchy', responseMessage('SyncFolderHierarchy', {
			body: `<m:SyncState>${escapeXml(token)}</m:SyncState>` +
				'<m:IncludesLastFolderInRange>true</m:IncludesLastFolderInRange>' +
				'<m:Changes></m:Changes>'
		}));
	}

	// 该用户名下每个收件账号 → 一个自定义文件夹（DisplayName = 账号邮箱）
	// 同名账号（EWS 账户本身的地址）排最前，符合「账户先看到自己」的直觉
	const preferredAccountId = await resolveUserAccount(c, user);
	const accounts = await selectUserAccounts(c, userId);
	const preferredIndex = accounts.findIndex((row) => Number(row.accountId) === preferredAccountId);
	if (preferredIndex > 0) accounts.unshift(accounts.splice(preferredIndex, 1)[0]);

	const changes = [];
	for (const childToken of EWS_ROOT_CHILDREN) {
		let def = ewsFolderDef(childToken);
		// root 的 ChildFolderCount 要含账号文件夹：同一响应里 Create 了它们，计数必须自洽
		if (def.kind === 'root') def = { ...def, extraChildCount: accounts.length };
		changes.push(`<t:Create>${buildFolderXml(def, await folderCounts(c, userId, def.kind))}</t:Create>`);
	}
	for (const row of accounts) {
		const def = accountFolderDef(row.accountId, row.email);
		changes.push(`<t:Create>${buildFolderXml(def, await folderCounts(c, userId, def.kind, def.accountId), String(def.accountId))}</t:Create>`);
	}

	return operationResponse('SyncFolderHierarchy', responseMessage('SyncFolderHierarchy', {
		body: `<m:SyncState>${escapeXml(encodeSyncState(emptySyncState()))}</m:SyncState>` +
			'<m:IncludesLastFolderInRange>true</m:IncludesLastFolderInRange>' +
			`<m:Changes>${changes.join('')}</m:Changes>`
	}));
}

// --------------------------------------------------- SyncFolderItems ---------

async function buildChangesXml(c, tag, rows, options) {
	if (rows.length === 0) return '';
	const presence = await attachmentPresence(c, rows.map((row) => row.emailId));
	// MimeContent 只重建前 EWS_MAX_MIME_ITEM_IDS 封（其余只回元数据），且多封共用一份附件字节账本
	const mimeIds = options.mimeIds ?? new Set();
	const items = [];
	for (const row of rows) {
		const mimeContent = options.includeMimeContent && mimeIds.has(row.emailId)
			? await buildMimeForRow(c, row, options.maxAttBytes, options.attBudget)
			: '';
		items.push(`<t:${tag}>${buildItemXml(row, {
			changeKey: changeKeyOf(row),
			hasAttachments: presence.get(row.emailId) === true,
			mimeContent,
			parentFolderId: options.folderToken
		})}</t:${tag}>`);
	}
	return items.join('');
}

async function handleSyncFolderItems(c, payload, user) {
	const userId = user.userId;
	const folderToken = containerFolderToken(firstChild(payload, 'SyncFolderId'));
	const def = ewsFolderDef(folderToken);
	if (!def) {
		throw new EwsFault('ErrorFolderNotFound', `Folder not found: ${folderToken}`);
	}
	// 账号文件夹：先校验该账号属于当前用户（他人账号 → 与不存在的文件夹同一错误；过滤条件本身也强制 userId）
	if (def.kind === 'account' && !(await selectOwnedAccounts(c, userId, [def.accountId])).has(def.accountId)) {
		throw new EwsFault('ErrorFolderNotFound', `Folder not found: ${folderToken}`);
	}

	const requested = Number(textOf(firstChild(payload, 'MaxChangesReturned')));
	const pageSize = Math.max(1, Math.min(EWS_SYNC_PAGE,
		Number.isFinite(requested) && requested > 0 ? Math.floor(requested) : EWS_SYNC_PAGE));
	const itemShape = firstChild(payload, 'ItemShape');
	const includeMimeContent = isTrueFlag(firstChild(itemShape, 'IncludeMimeContent'));
	const maxAttBytes = ewsMaxAttBytes(c.env);

	// 根/草稿/发件箱：不承载邮件，回空变更
	// 三件套恒存在（TB 硬校验）：SyncState（非空）+ IncludesLastItemInRange + Changes（可为空）
	if (!isMailFolder(def.kind)) {
		return operationResponse('SyncFolderItems', responseMessage('SyncFolderItems', {
			body: `<m:SyncState>${escapeXml(encodeSyncState(emptySyncState()))}</m:SyncState>` +
				'<m:IncludesLastItemInRange>true</m:IncludesLastItemInRange>' +
				'<m:Changes></m:Changes>'
		}));
	}

	// 邮件范围：Distinguished 文件夹 = 用户级聚合（全部收件账号）；账号文件夹（acct-<id>）= 该账号口径
	// （可见域/水位快照/增量扫描共用同一过滤，本请求内所有查询复用）
	const accountId = def.kind === 'account' ? def.accountId : null;

	const token = textOf(firstChild(payload, 'SyncState')).trim();
	let state = decodeSyncState(token);
	if (!state && token !== '') {
		// 客户端确实同步过但 SyncState 不可解析：按 D1 水位续传，避免整箱重发
		state = await readStoredSyncState(c, userId, def.token);
	}
	if (!state) {
		// 初始全量：以当前可见邮件的最大 update_time 为水位快照，再按 emailId 倒序分页回补历史
		state = { ...emptySyncState(), wm: await snapshotWatermark(c, userId, def.kind, accountId), cur: FRESH_CURSOR };
	}

	const creates = [];
	const updates = [];
	const deletes = [];
	let tombstoneDeletes = [];
	let wm = state.wm;
	let wid = state.wid;
	let cur = state.cur;
	let more = false;
	// 本轮进入增量扫描时的水位：tombstone 与邮件共用同一「eff 水位」语义（del_time > wm）
	const sweepWm = wm;
	// 历史积压分页进行中：此时客户端尚未拿到全量，Delete 事件留到积压翻页结束后再产出
	let backfilling = false;

	try {
		// ① 历史积压分页：最后修改时间 <= 水位快照 且 emailId < 游标
		if (cur !== null) {
			const rows = await orm(c).select(emailSelect()).from(email)
				.where(and(
					visibleFilter(def.kind, userId, accountId),
					lte(effTime(), wm),
					lt(email.emailId, cur)
				))
				.orderBy(desc(email.emailId))
				.limit(pageSize)
				.all();

			creates.push(...rows);
			// 首批（倒序）的首行即该水位下的最大 emailId：积压发完后用它把增量下界收紧，
			// 避免 eff == wm 的老邮件在增量阶段被重复上报
			if (rows.length > 0) wid = Math.max(wid, rows[0].emailId);
			if (rows.length >= pageSize) {
				cur = rows[rows.length - 1].emailId;
				more = true;
				backfilling = true;
			} else {
				cur = null;
			}
		}

		// ② 增量：最后修改时间 > 水位（含进入垃圾桶的行 → Delete 事件）
		if (!more) {
			const budget = Math.max(1, pageSize - creates.length);
			const rows = await orm(c).select(emailSelect()).from(email)
				.where(and(
					scopeFilter(def.kind, userId, accountId),
					sql`(${effTime()} > ${wm} OR (${effTime()} = ${wm} AND ${email.emailId} > ${wid}))`
				))
				.orderBy(asc(effTime()), asc(email.emailId))
				.limit(budget)
				.all();

			for (const row of rows) {
				const change = classifySyncRow(def.kind, row, wm);
				if (change === 'delete') deletes.push(row);
				else if (change === 'update') updates.push(row);
				else if (change === 'create') creates.push(row);
			}

			if (rows.length > 0) {
				const last = rows[rows.length - 1];
				wm = String(last.eff ?? wm);
				wid = last.emailId;
			}
			if (rows.length >= budget) more = true;
		}

		// ③ 物理删除 tombstone：邮件行已不存在，增量扫描看不到 → 按 del_time > 本轮进入时的水位补 Delete 事件。
		//    与同轮已产出的 ItemId 去重；积压翻页中不产出（客户端尚未拿到全量，Delete 无意义且会跨轮重复）。
		//    账号文件夹跳过：ews_tombstone 只记 type/trash 不记 account_id，无法归属到 acct-<id>
		//    （同名邮件在 inbox 侧仍会收到 Delete；账号文件夹内的物理删除残留由客户端重新全量同步消化）
		if (!backfilling && def.kind !== 'account') {
			const tombstones = await readTombstones(c, userId, sweepWm);
			const knownIds = new Set([...creates, ...updates, ...deletes].map((row) => Number(row.emailId)));
			tombstoneDeletes = selectTombstoneDeletes(def.token, tombstones, knownIds);
		}
	} catch (error) {
		requireMigrated(error);
	}

	const nextState = { v: 1, wm, wid, cur };
	await storeSyncState(c, userId, def.token, nextState);

	// MimeContent 只重建前 EWS_MAX_MIME_ITEM_IDS 封（Create/Update 合并计数），
	// 且所有邮件共用一份本次响应的附件字节账本
	const attBudget = newAttBudget(c);
	const mimeIds = includeMimeContent
		? mimeContentIdSet([...creates, ...updates].map((row) => row.emailId), EWS_MAX_MIME_ITEM_IDS)
		: new Set();
	const changesXml = [
		await buildChangesXml(c, 'Create', creates, { includeMimeContent, maxAttBytes, attBudget, mimeIds, folderToken: def.token }),
		await buildChangesXml(c, 'Update', updates, { includeMimeContent, maxAttBytes, attBudget, mimeIds, folderToken: def.token }),
		deletes.map((row) => `<t:Delete><t:ItemId Id="${escapeXml(row.emailId)}"/></t:Delete>`).join(''),
		tombstoneDeletes.map((emailId) => `<t:Delete><t:ItemId Id="${escapeXml(String(emailId))}"/></t:Delete>`).join('')
	].join('');

	// Changes 恒存在（无变更时也输出空元素：TB 反序列化要求该节点在场）；
	// IncludesLastItemInRange 语义：more=true（还有下一页）→ false，否则 true
	const body = `<m:SyncState>${escapeXml(encodeSyncState(nextState))}</m:SyncState>` +
		`<m:IncludesLastItemInRange>${more ? 'false' : 'true'}</m:IncludesLastItemInRange>` +
		`<m:Changes>${changesXml}</m:Changes>`;

	return operationResponse('SyncFolderItems', responseMessage('SyncFolderItems', { body }));
}

// ---------------------------------------------------------------- GetItem -----

async function handleGetItem(c, payload, user) {
	const userId = user.userId;
	const ids = extractItemIds(payload);
	if (ids.length === 0) {
		throw new EwsFault('ErrorInvalidRequest', 'GetItem requires ItemIds.');
	}

	const itemShape = firstChild(payload, 'ItemShape');
	const includeMimeContent = isTrueFlag(firstChild(itemShape, 'IncludeMimeContent'));
	const bodyType = (attr(firstChild(itemShape, 'BodyType'), 'BodyType') || textOf(firstChild(itemShape, 'BodyType'))).toUpperCase();
	const baseShape = textOf(firstChild(itemShape, 'BaseShape')).trim();
	const wantBody = !includeMimeContent && (bodyType !== '' || baseShape === 'Default' || baseShape === 'AllProperties');
	const maxAttBytes = ewsMaxAttBytes(c.env);

	assertBatchSize(ids, 'GetItem');
	const rows = await selectOwnedEmails(c, userId, ids);

	if (rows.length === 0) {
		return operationResponse('GetItem', responseMessage('GetItem', {
			responseClass: 'Error',
			responseCode: 'ErrorItemNotFound',
			messageText: 'Item not found.'
		}));
	}

	// MimeContent（重邮件重建）单独 clamp 到前 EWS_MAX_MIME_ITEM_IDS 个 Id：其余 Id 仍回元数据；
	// 全部 MimeContent 共用一份附件字节账本（ewsMaxTotalAttBytes）
	const mimeIds = includeMimeContent ? mimeContentIdSet(ids, EWS_MAX_MIME_ITEM_IDS) : new Set();
	const attBudget = newAttBudget(c);
	const presence = await attachmentPresence(c, rows.map((row) => row.emailId));
	const items = [];
	for (const row of rows) {
		const mimeContent = includeMimeContent && mimeIds.has(row.emailId)
			? await buildMimeForRow(c, row, maxAttBytes, attBudget)
			: '';
		const body = wantBody ? { html: row.content || '', text: row.text || '' } : null;
		items.push(buildItemXml(row, {
			changeKey: changeKeyOf(row),
			hasAttachments: presence.get(row.emailId) === true,
			mimeContent,
			body,
			parentFolderId: isSentRow(row) ? 'sentitems' : 'inbox'
		}));
	}

	return operationResponse('GetItem', responseMessage('GetItem', {
		body: `<m:Items>${items.join('')}</m:Items>`
	}));
}

// ----------------------------------------------------------- GetAttachment ---

async function handleGetAttachment(c, payload, user) {
	const userId = user.userId;
	const container = firstChild(payload, 'AttachmentIds');
	const attachmentIds = [];
	for (const node of children(container, 'AttachmentId')) {
		const value = Number(attr(node, 'Id'));
		if (Number.isFinite(value) && value > 0) attachmentIds.push(value);
	}
	if (attachmentIds.length === 0) {
		throw new EwsFault('ErrorInvalidRequest', 'GetAttachment requires AttachmentIds.');
	}
	assertBatchSize(attachmentIds, 'GetAttachment');

	const maxAttBytes = ewsMaxAttBytes(c.env);
	const attachments = [];

	// 归属校验：附件必须属于当前登录用户
	for (const attachmentId of attachmentIds) {
		const row = await orm(c).select().from(att)
			.where(and(eq(att.attId, attachmentId), eq(att.userId, userId)))
			.get();
		if (!row) {
			throw new EwsFault('ErrorItemNotFound', `Attachment not found: ${attachmentId}`);
		}
		if ((Number(row.size) || 0) > maxAttBytes) {
			throw new EwsFault('ErrorInvalidRequest',
				`Attachment is too large for EWS (${row.size} bytes > ${maxAttBytes} bytes). Please download it from the CloudMail web client.`);
		}

		const object = await r2Service.getObj(c, row.key);
		if (!object) {
			throw new EwsFault('ErrorItemNotFound', `Attachment content is not available: ${attachmentId}`);
		}
		const bytes = new Uint8Array(await object.arrayBuffer());
		const contentId = stripCidBrackets(row.contentId);

		attachments.push('<t:FileAttachment>' +
			`<t:AttachmentId Id="${escapeXml(String(row.attId))}"/>` +
			`<t:Name>${escapeXml(row.filename ?? 'file')}</t:Name>` +
			`<t:ContentType>${escapeXml(row.mimeType ?? 'application/octet-stream')}</t:ContentType>` +
			(contentId === '' ? '' : `<t:ContentId>${escapeXml(contentId)}</t:ContentId>`) +
			`<t:Content>${base64EncodeBytes(bytes)}</t:Content>` +
			`<t:Size>${bytes.length}</t:Size>` +
			'</t:FileAttachment>');
	}

	return operationResponse('GetAttachment', responseMessage('GetAttachment', {
		body: `<m:Attachments>${attachments.join('')}</m:Attachments>`
	}));
}

// -------------------------------------------------------------- CreateItem ---

/** MimeContent 兜底解析（客户端只发 MIME、不给结构化字段时） */
async function parseMimeContent(mimeContent) {
	try {
		const bytes = base64ToBytes(mimeContent);
		if (bytes.length === 0) return null;
		const parsed = await PostalMime.parse(bytes);
		const toAddress = (item) => ({ address: item?.address ?? '', name: item?.name ?? '' });
		return {
			subject: parsed.subject ?? '',
			text: parsed.text ?? '',
			html: parsed.html ?? '',
			from: parsed.from ? toAddress(parsed.from) : null,
			to: asArray(parsed.to).map(toAddress).filter((item) => item.address),
			cc: asArray(parsed.cc).map(toAddress).filter((item) => item.address),
			bcc: asArray(parsed.bcc).map(toAddress).filter((item) => item.address),
			attachments: asArray(parsed.attachments).map((item) => ({
				filename: item.filename ?? 'file',
				mimeType: item.mimeType ?? item.contentType ?? 'application/octet-stream',
				contentId: item.contentId ?? '',
				disposition: item.disposition ?? '',
				bytes: item.content instanceof ArrayBuffer ? new Uint8Array(item.content) : new Uint8Array(item.content ?? 0)
			}))
		};
	} catch (e) {
		return null;
	}
}

async function handleCreateItem(c, payload, user) {
	const disposition = attr(payload, 'MessageDisposition') || 'SendAndSaveCopy';
	if (disposition === 'SaveOnly') {
		throw new EwsFault('ErrorInvalidRequest',
			'Drafts are not supported by the CloudMail EWS bridge. Please send the message instead of saving it.');
	}

	const messageNodes = children(firstChild(payload, 'Items'), 'Message');
	if (messageNodes.length === 0) {
		throw new EwsFault('ErrorInvalidRequest', 'CreateItem requires a Message item.');
	}
	if (messageNodes.length > 1) {
		throw new EwsFault('ErrorInvalidRequest', 'CreateItem supports a single Message per call.');
	}
	const message = messageNodes[0];
	if (!message || typeof message !== 'object') {
		throw new EwsFault('ErrorInvalidRequest', 'CreateItem requires a Message item.');
	}
	if (children(firstChild(message, 'Attachments'), 'ItemAttachment').length > 0) {
		throw new EwsFault('ErrorInvalidRequest', 'Item attachments (embedded messages) are not supported by the CloudMail EWS bridge.');
	}

	const maxAttBytes = ewsMaxAttBytes(c.env);
	const maxTotalAttBytes = ewsMaxTotalAttBytes(c.env);

	const bodyNode = firstChild(message, 'Body');
	const bodyText = textOf(bodyNode);
	const isHtmlBody = (attr(bodyNode, 'BodyType') || 'HTML').toUpperCase() !== 'TEXT';
	let html = isHtmlBody ? bodyText : '';
	let text = isHtmlBody ? '' : bodyText;
	let subject = textOf(firstChild(message, 'Subject')).trim();
	let from = parseMailbox(firstChild(message, 'From')) ?? parseMailbox(firstChild(message, 'Sender'));
	let to = parseMailboxList(firstChild(message, 'ToRecipients'));
	let cc = parseMailboxList(firstChild(message, 'CcRecipients'));
	let bcc = parseMailboxList(firstChild(message, 'BccRecipients'));

	// 结构化附件：{ name, mimeType, content(base64), contentId, isInline }
	const outgoing = [];
	for (const node of children(firstChild(message, 'Attachments'), 'FileAttachment')) {
		const name = textOf(firstChild(node, 'Name')).trim() || 'file';
		const mimeType = textOf(firstChild(node, 'ContentType')).trim() || 'application/octet-stream';
		const contentId = stripCidBrackets(textOf(firstChild(node, 'ContentId')));
		const content = cleanBase64(textOf(firstChild(node, 'Content')));
		if (content === '') continue;
		outgoing.push({ name, mimeType, content, contentId, isInline: isTrueFlag(firstChild(node, 'IsInline')) });
	}

	// 结构化字段为空时按 MIME 解析（TB 也可能直接发 MimeContent）
	const mimeContent = cleanBase64(textOf(firstChild(message, 'MimeContent')));
	if (to.length === 0 && cc.length === 0 && bcc.length === 0 && html === '' && text === '' && mimeContent !== '') {
		const parsed = await parseMimeContent(mimeContent);
		if (!parsed) {
			throw new EwsFault('ErrorInvalidRequest', 'Unable to parse MimeContent.');
		}
		subject = subject || parsed.subject;
		html = html || parsed.html || '';
		text = text || parsed.text || '';
		to = parsed.to;
		cc = parsed.cc;
		bcc = parsed.bcc;
		from = from ?? parsed.from;
		for (const item of parsed.attachments) {
			outgoing.push({
				name: item.filename,
				mimeType: item.mimeType,
				content: base64EncodeBytes(item.bytes),
				contentId: stripCidBrackets(item.contentId),
				isInline: String(item.disposition).toLowerCase() === 'inline' && item.contentId !== ''
			});
		}
	}

	// From 地址（发件账号路由依据）：结构化 t:From/t:Sender 优先；上面 PostalMime 分支未覆盖时
	// （结构化字段部分存在、From 只在 MimeContent 里）再从 MIME 头取（TB 发信 From 常在 MimeContent 里）。
	if (String(from?.address ?? '').trim() === '' && mimeContent !== '') {
		const mimeFrom = parseMimeFrom(mimeContent);
		if (mimeFrom !== '') from = { address: mimeFrom, name: '' };
	}

	// 附件大小护栏（解码后字节）：单文件超限 / 总量超限都提示改用 Web 端
	let totalAttBytes = 0;
	for (const item of outgoing) {
		const size = base64DecodedSize(item.content);
		if (size > maxAttBytes) {
			throw new EwsFault('ErrorInvalidRequest',
				`Attachment "${item.name}" is too large for EWS (${size} bytes > ${maxAttBytes} bytes). Please send it from the CloudMail web client.`);
		}
		totalAttBytes += size;
	}
	if (totalAttBytes > maxTotalAttBytes) {
		throw new EwsFault('ErrorInvalidRequest',
			`Attachments total size is too large for EWS (${totalAttBytes} bytes > ${maxTotalAttBytes} bytes). Please send them from the CloudMail web client.`);
	}

	// cid: 引用还原成 data: URL（后续 email-service/att-service 会再转成 cid 附件入库）
	const { html: outgoingHtml, attachments } = splitOutgoingAttachments(html, outgoing);
	html = outgoingHtml;

	const receiveEmail = [];
	for (const item of [...to, ...cc, ...bcc]) {
		if (!receiveEmail.includes(item.address)) receiveEmail.push(item.address);
	}
	if (receiveEmail.length === 0) {
		throw new EwsFault('ErrorInvalidRequest', 'CreateItem requires at least one recipient (To/Cc/Bcc).');
	}

	// 发件账号路由：From 地址非空 → 必须是当前用户名下的账号（NOCASE 等值），
	// 命中则用该账号（含其邮箱 → email-service 按域名取 resendTokens[domain]）发信；
	// 不属于当前用户 → 拒绝（禁止冒用他人身份 / 用未配置地址发信）。
	// From 缺失/为空 → 保持原行为：与登录邮箱同名的收件账号，其次登录邮箱账号。
	const fromAddress = String(from?.address ?? '').trim();
	let accountRow = null;
	if (fromAddress !== '') {
		accountRow = await selectOwnedAccountByEmail(c, user.userId, fromAddress);
		if (!accountRow) {
			throw new EwsFault('ErrorInvalidRequest',
				`发件地址不属于当前账户，无法以该地址发信: ${fromAddress}`);
		}
	} else {
		accountRow = await selectLoginEmailAccount(c, user);
		if (!accountRow) {
			accountRow = await accountService.selectByEmailIncludeDel(c, user.email);
			if (!accountRow || accountRow.userId !== user.userId) {
				throw new EwsFault('ErrorInvalidRequest', `No sender account available for ${user.email}.`);
			}
		}
	}

	let emailRow = null;
	try {
		const result = await emailService.send(c, {
			accountId: accountRow.accountId,
			name: from?.name || accountRow.name || '',
			sendType: 'send',
			receiveEmail,
			subject,
			text,
			content: html,
			attachments
		}, user.userId);
		emailRow = Array.isArray(result) ? result[0] : result;
	} catch (error) {
		// 发信失败（限额/黑名单/未配置发信服务等）：把业务原因放进 faultstring 供客户端展示
		if (error instanceof BizError || error?.name === 'BizError') {
			throw new EwsFault('ErrorInvalidRequest', error.message);
		}
		throw error;
	}

	// TB 从 m:Items 里的 ItemId 取新建邮件 Id（缺失 → MissingIdInResponse）
	const itemId = Number(emailRow?.emailId) || 0;
	return operationResponse('CreateItem', responseMessage('CreateItem', {
		body: createItemItemsXml(itemId, emailRow?.createTime ?? '')
	}));
}

// -------------------------------------------------------------- UpdateItem ---

/**
 * 已读标记：项目 unread 语义 0=未读 / 1=已读；同时 touch update_time 让增量同步能发出 Update 事件。
 * stamp 由调用方传入（响应里的 ChangeKey 必须与实际写入的 update_time 一致，不能各自取 nowText）。
 */
async function updateReadFlag(c, userId, emailId, unread, stamp = nowText()) {
	try {
		await c.env.db.prepare('UPDATE email SET unread = ?, update_time = ? WHERE email_id = ? AND user_id = ?')
			.bind(unread, stamp, emailId, userId).run();
	} catch (error) {
		if (!isMissingColumnError(error)) throw error;
		await c.env.db.prepare('UPDATE email SET unread = ? WHERE email_id = ? AND user_id = ?')
			.bind(unread, emailId, userId).run();
	}
}

async function handleUpdateItem(c, payload, user) {
	const userId = user.userId;
	const itemChanges = children(firstChild(payload, 'ItemChanges'), 'ItemChange');
	if (itemChanges.length === 0) {
		throw new EwsFault('ErrorInvalidRequest', 'UpdateItem requires ItemChanges.');
	}

	const messages = [];
	for (const change of itemChanges) {
		const itemId = Number(attr(firstChild(change, 'ItemId'), 'Id'));

		let unread = null;
		for (const update of children(firstChild(change, 'Updates'), 'SetItemField')) {
			const fieldUri = attr(firstChild(update, 'FieldURI'), 'FieldURI') || '';
			if (fieldUri !== 'message:IsRead') continue;
			const node = firstChild(firstChild(update, 'Message'), 'IsRead');
			if (node === undefined || node === null) continue;
			unread = isTrueFlag(node) ? emailConst.unread.READ : emailConst.unread.UNREAD;
		}

		if (!Number.isFinite(itemId) || itemId <= 0) {
			messages.push(responseMessage('UpdateItem', {
				responseClass: 'Error', responseCode: 'ErrorInvalidRequest', messageText: 'Invalid ItemId.'
			}));
			continue;
		}

		// 归属校验：防越权改他人邮件
		const row = await orm(c).select({
			emailId: email.emailId,
			createTime: email.createTime,
			eff: sql`COALESCE(NULLIF(update_time, ''), create_time)`.as('eff')
		}).from(email)
			.where(and(eq(email.userId, userId), eq(email.emailId, itemId)))
			.get();
		if (!row) {
			messages.push(responseMessage('UpdateItem', {
				responseClass: 'Error', responseCode: 'ErrorItemNotFound', messageText: `Item not found: ${itemId}`
			}));
			continue;
		}

		// 成功响应带更新后的 ItemId（TB 从 m:Items 里读回写结果；ChangeKey = 新的「最后修改时间」）
		let changeKey = changeKeyOf(row);
		if (unread !== null) {
			const stamp = nowText();
			await updateReadFlag(c, userId, itemId, unread, stamp);
			changeKey = stamp;
		}

		messages.push(responseMessage('UpdateItem', {
			body: '<m:Items><t:Message>' +
				`<t:ItemId Id="${escapeXml(String(itemId))}" ChangeKey="${escapeXml(changeKey)}"/>` +
				'</t:Message></m:Items>'
		}));
	}

	return operationResponse('UpdateItem', messages.join(''));
}

// -------------------------------------------------------------- DeleteItem ---

async function handleDeleteItem(c, payload, user) {
	const ids = extractItemIds(payload);
	if (ids.length === 0) {
		throw new EwsFault('ErrorInvalidRequest', 'DeleteItem requires ItemIds.');
	}

	// 分片查询 + 分批删除：批量删除可能超过 D1 绑定参数上限
	const ownedIds = new Set();
	for (const chunk of chunkList(ids)) {
		const rows = await orm(c).select({ emailId: email.emailId }).from(email)
			.where(and(eq(email.userId, user.userId), inArray(email.emailId, chunk)))
			.all();
		for (const row of rows) ownedIds.add(Number(row.emailId));
	}

	// HardDelete 也按软删除处理（安全）：与 Web 端 DELETE /email/delete 完全同一路径（含 syncDelete 设置）
	const deletable = ids.filter((id) => ownedIds.has(id));
	for (const chunk of chunkList(deletable)) {
		await emailService.delete(c, { emailIds: chunk.join(',') }, user.userId);
	}

	// TB 校验 ResponseMessage 数量 = 请求 ItemId 数量（顺序一致）：每个 ItemId 一条；
	// 未找到的 Id 回 ErrorItemNotFound（TB 容忍该错误，不当整体失败）
	return operationResponse('DeleteItem', ids.map((id) => (ownedIds.has(id)
		? responseMessage('DeleteItem', {})
		: responseMessage('DeleteItem', {
			responseClass: 'Error',
			responseCode: 'ErrorItemNotFound',
			messageText: `Item not found: ${id}`
		}))).join(''));
}

// ---------------------------------------------------------------- SendItem ---

async function handleSendItem() {
	// CloudMail 没有 outbox 语义：邮件在 CreateItem(SendOnly/SendAndSaveCopy) 时已发出
	throw new EwsFault('ErrorItemNotFound', 'SendItem is not supported: messages are sent by CreateItem.');
}

// ------------------------------------------------------------ ResolveNames ---

/** 目录项显示名：优先 user.name（库内一般没有），否则邮箱本地部分 */
function resolutionDisplayName(user) {
	const name = String(user?.name ?? '').trim();
	if (name !== '') return name;
	const email = String(user?.email ?? '').trim();
	const at = email.lastIndexOf('@');
	return at > 0 ? email.slice(0, at) : email;
}

/**
 * ResolveNames：TB 账号验证阶段用它解析/校验地址（验证失败会显示「身份验证出错」）。
 * 与当前认证用户的邮箱/名做不区分大小写匹配 → Success；无匹配回
 * ErrorNameResolutionNoResults（标准 ResponseMessage，不抛 Fault）。
 * ReturnFullContactData / SearchScope 忽略（不做目录检索，只回当前用户）。
 */
async function handleResolveNames(c, payload, user) {
	const entry = textOf(firstChild(payload, 'UnresolvedEntry')).trim();
	if (entry === '') {
		throw new EwsFault('ErrorInvalidRequest', 'ResolveNames requires UnresolvedEntry.');
	}

	const address = String(user?.email ?? '').trim();
	const matched = address !== '' && resolveNameMatches(entry, address, user?.name);
	if (!matched) {
		return operationResponse('ResolveNames', responseMessage('ResolveNames', {
			responseClass: 'Error',
			responseCode: 'ErrorNameResolutionNoResults',
			messageText: `No results were found for "${entry}".`
		}));
	}

	return operationResponse('ResolveNames', responseMessage('ResolveNames', {
		body: resolutionSetXml([{ name: resolutionDisplayName(user), address }])
	}));
}

// -------------------------------------------------------------- GetMailTips --

/** GetMailTips：每个收件人一个 Success/NoError 的 MailTips ResponseMessage（无特殊提示字段） */
async function handleGetMailTips(c, payload) {
	const recipients = parseMailboxList(firstChild(payload, 'Recipients'));
	const messages = recipients.map((item) => responseMessage('MailTips', { body: mailTipsXml([item]) }));
	return operationResponse('GetMailTips',
		messages.length > 0 ? messages.join('') : responseMessage('MailTips', {}));
}

// --------------------------------------------------------- GetServerTimeZones -

/** GetServerTimeZones：只回标准 UTC 时区定义（时区数据缺失时部分客户端拒绝完成向导） */
async function handleGetServerTimeZones() {
	return operationResponse('GetServerTimeZones', responseMessage('GetServerTimeZones', {
		body: timeZoneDefinitionsXml()
	}));
}

// ---------------------------------------------------------------- 分发 -------

const HANDLERS = {
	GetFolder: handleGetFolder,
	FindFolder: handleFindFolder,
	SyncFolderHierarchy: handleSyncFolderHierarchy,
	SyncFolderItems: handleSyncFolderItems,
	GetItem: handleGetItem,
	GetAttachment: handleGetAttachment,
	CreateItem: handleCreateItem,
	UpdateItem: handleUpdateItem,
	DeleteItem: handleDeleteItem,
	SendItem: handleSendItem,
	ResolveNames: handleResolveNames,
	GetMailTips: handleGetMailTips,
	GetServerTimeZones: handleGetServerTimeZones
};

export async function dispatch(c, parsed, user) {
	// 诊断日志：tail wrangler 日志可确认 TB 各阶段（含账号验证）实际发送的 EWS 操作
	console.log('EWS operation:', parsed.operation);
	// 只认 HANDLERS 自身属性：operation 名来自请求 XML，toString/constructor/valueOf 等
	// 原型链成员不能当操作名命中（否则会被当成 handler 调用，返回非 XML 的垃圾响应）
	const handler = Object.hasOwn(HANDLERS, parsed.operation) ? HANDLERS[parsed.operation] : null;
	if (!handler) {
		throw new EwsFault('ErrorNotImplemented',
			`Operation ${parsed.operation} is not implemented by the CloudMail EWS bridge.`);
	}
	return handler(c, parsed.payload, user);
}
