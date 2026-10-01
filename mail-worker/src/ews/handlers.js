/**
 * EWS 操作编排（handler）：D1 查询 / COS 读取 / 发信走项目现有 service。
 *
 * 覆盖 Thunderbird 145+ 原生 Exchange 账号会发起的操作：
 *   GetFolder / SyncFolderHierarchy / SyncFolderItems / GetItem / GetAttachment /
 *   CreateItem / UpdateItem / DeleteItem / SendItem
 * 其余操作统一回 ErrorNotImplemented Fault（TB 会自动降级，如轮询代替推送）。
 *
 * 约定：
 *   - 所有按 Id 取数据的操作强制 where userId = 当前登录用户，防越权；
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
import { att } from '../entity/att';
import emailService from '../service/email-service';
import accountService from '../service/account-service';
import r2Service from '../service/r2-service';
import { attConst, emailConst, isDel } from '../const/entity-const';
import BizError from '../error/biz-error';
import { buildMimeBase64 } from './mime-build.js';
import {
	EWS_ROOT_CHILDREN,
	EWS_SYNC_PAGE,
	ewsFolderDef,
	ewsMaxAttBytes,
	ewsMaxTotalAttBytes
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
	base64DecodedSize,
	base64EncodeBytes,
	base64ToBytes,
	buildFolderXml,
	buildItemXml,
	changeKeyOf,
	classifySyncRow,
	cleanBase64,
	decodeSyncState,
	emptySyncState,
	encodeSyncState,
	isInlineAttachment,
	isSentRow,
	parseAddressList,
	parseMailbox,
	parseMailboxList,
	splitOutgoingAttachments,
	stripCidBrackets,
	toDateMs
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

/** 正常列表可见的邮件条件；trash 文件夹为垃圾桶语义（与 Web 端一致） */
function visibleFilter(kind, userId) {
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
	return null;
}

/** 增量扫描范围（含垃圾桶里的行，用于产出 Delete 事件） */
function scopeFilter(kind, userId) {
	if (kind === 'inbox') return and(eq(email.userId, userId), eq(email.type, emailConst.type.RECEIVE));
	if (kind === 'sent') return and(eq(email.userId, userId), eq(email.type, emailConst.type.SEND));
	if (kind === 'trash') return eq(email.userId, userId);
	return null;
}

function isMailFolder(kind) {
	return kind === 'inbox' || kind === 'sent' || kind === 'trash';
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

function extractFolderTokens(payload) {
	const container = firstChild(payload, 'FolderIds');
	const tokens = [];
	for (const name of DISTINGUISHED_IDS) {
		for (const node of children(container, name)) {
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

async function folderCounts(c, userId, kind) {
	if (!isMailFolder(kind)) return { total: 0, unread: 0 };
	const row = await orm(c).select({
		total: count(),
		unread: sql`SUM(CASE WHEN ${email.unread} = ${emailConst.unread.UNREAD} THEN 1 ELSE 0 END)`
	}).from(email).where(visibleFilter(kind, userId)).get();
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

/** 用 COS 附件 + 库内正文重建完整 MIME（base64），供 EWS MimeContent */
async function buildMimeForRow(c, row, maxAttBytes) {
	const rows = await attachmentRows(c, row.emailId, row.userId);
	let html = row.content || '';
	const inlineImages = [];
	const attachments = [];

	for (const attRow of rows) {
		// 超限附件不进 MIME（TB 侧表现为该附件缺失，正文与其它附件仍可见）
		if ((Number(attRow.size) || 0) > maxAttBytes) continue;
		const object = await r2Service.getObj(c, attRow.key);
		if (!object) continue;
		const data = new Uint8Array(await object.arrayBuffer());

		if (isInlineAttachment(attRow)) {
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

	const dateMs = toDateMs(row.createTime);
	return buildMimeBase64({
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
		text: row.text,
		html,
		inlineImages,
		attachments
	});
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
async function snapshotWatermark(c, userId, kind) {
	try {
		const row = await orm(c).select({ wm: sql`MAX(${effTime()})` }).from(email)
			.where(visibleFilter(kind, userId)).get();
		if (row?.wm === null || row?.wm === undefined) return '';
		return String(row.wm);
	} catch (error) {
		requireMigrated(error);
	}
}

// ---------------------------------------------------------------- GetFolder ----

async function handleGetFolder(c, payload, user) {
	const userId = user.userId;
	const tokens = extractFolderTokens(payload);
	if (tokens.length === 0) {
		throw new EwsFault('ErrorInvalidRequest', 'GetFolder requires FolderIds.');
	}

	const known = [];
	const unknown = [];
	for (const token of tokens) {
		const def = ewsFolderDef(token);
		if (def) known.push(def);
		else unknown.push(token);
	}

	const messages = [];
	if (known.length > 0) {
		const folders = [];
		for (const def of known) {
			folders.push(buildFolderXml(def, await folderCounts(c, userId, def.kind)));
		}
		messages.push(responseMessage('GetFolder', { body: `<m:Folders>${folders.join('')}</m:Folders>` }));
	}
	for (const token of unknown) {
		messages.push(responseMessage('GetFolder', {
			responseClass: 'Error',
			responseCode: 'ErrorFolderNotFound',
			messageText: `Folder not found: ${token}`
		}));
	}

	return operationResponse('GetFolder', messages.join(''));
}

// ------------------------------------------------- SyncFolderHierarchy --------

async function handleSyncFolderHierarchy(c, payload, user) {
	const userId = user.userId;
	const token = textOf(firstChild(payload, 'SyncState')).trim();

	// 文件夹集合是静态的（Inbox/Sent/Deleted/Drafts/Outbox）：已有 SyncState 直接回空变更
	if (token !== '' && decodeSyncState(token)) {
		return operationResponse('SyncFolderHierarchy', responseMessage('SyncFolderHierarchy', {
			body: `<m:SyncState>${escapeXml(token)}</m:SyncState>` +
				'<m:IncludesLastFolderInRange>true</m:IncludesLastFolderInRange>'
		}));
	}

	const changes = [];
	for (const childToken of EWS_ROOT_CHILDREN) {
		const def = ewsFolderDef(childToken);
		changes.push(`<t:Create>${buildFolderXml(def, await folderCounts(c, userId, def.kind))}</t:Create>`);
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
	const items = [];
	for (const row of rows) {
		const mimeContent = options.includeMimeContent
			? await buildMimeForRow(c, row, options.maxAttBytes)
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

	const requested = Number(textOf(firstChild(payload, 'MaxChangesReturned')));
	const pageSize = Math.max(1, Math.min(EWS_SYNC_PAGE,
		Number.isFinite(requested) && requested > 0 ? Math.floor(requested) : EWS_SYNC_PAGE));
	const itemShape = firstChild(payload, 'ItemShape');
	const includeMimeContent = isTrueFlag(firstChild(itemShape, 'IncludeMimeContent'));
	const maxAttBytes = ewsMaxAttBytes(c.env);

	// 根/草稿/发件箱：不承载邮件，回空变更
	if (!isMailFolder(def.kind)) {
		return operationResponse('SyncFolderItems', responseMessage('SyncFolderItems', {
			body: `<m:SyncState>${escapeXml(encodeSyncState(emptySyncState()))}</m:SyncState>` +
				'<m:IncludesLastItemInRange>true</m:IncludesLastItemInRange>'
		}));
	}

	const token = textOf(firstChild(payload, 'SyncState')).trim();
	let state = decodeSyncState(token);
	if (!state && token !== '') {
		// 客户端确实同步过但 SyncState 不可解析：按 D1 水位续传，避免整箱重发
		state = await readStoredSyncState(c, userId, def.token);
	}
	if (!state) {
		// 初始全量：以当前可见邮件的最大 update_time 为水位快照，再按 emailId 倒序分页回补历史
		state = { ...emptySyncState(), wm: await snapshotWatermark(c, userId, def.kind), cur: FRESH_CURSOR };
	}

	const creates = [];
	const updates = [];
	const deletes = [];
	let wm = state.wm;
	let wid = state.wid;
	let cur = state.cur;
	let more = false;

	try {
		// ① 历史积压分页：最后修改时间 <= 水位快照 且 emailId < 游标
		if (cur !== null) {
			const rows = await orm(c).select(emailSelect()).from(email)
				.where(and(
					visibleFilter(def.kind, userId),
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
			} else {
				cur = null;
			}
		}

		// ② 增量：最后修改时间 > 水位（含进入垃圾桶的行 → Delete 事件）
		if (!more) {
			const budget = Math.max(1, pageSize - creates.length);
			const rows = await orm(c).select(emailSelect()).from(email)
				.where(and(
					scopeFilter(def.kind, userId),
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
	} catch (error) {
		requireMigrated(error);
	}

	const nextState = { v: 1, wm, wid, cur };
	await storeSyncState(c, userId, def.token, nextState);

	const changesXml = [
		await buildChangesXml(c, 'Create', creates, { includeMimeContent, maxAttBytes, folderToken: def.token }),
		await buildChangesXml(c, 'Update', updates, { includeMimeContent, maxAttBytes, folderToken: def.token }),
		deletes.map((row) => `<t:Delete><t:ItemId Id="${escapeXml(row.emailId)}"/></t:Delete>`).join('')
	].join('');

	const body = `<m:SyncState>${escapeXml(encodeSyncState(nextState))}</m:SyncState>` +
		`<m:IncludesLastItemInRange>${more ? 'false' : 'true'}</m:IncludesLastItemInRange>` +
		(changesXml === '' ? '' : `<m:Changes>${changesXml}</m:Changes>`);

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

	const presence = await attachmentPresence(c, rows.map((row) => row.emailId));
	const items = [];
	for (const row of rows) {
		const mimeContent = includeMimeContent ? await buildMimeForRow(c, row, maxAttBytes) : '';
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

	// 发件账号：优先 From（必须是本人账号），否则用登录邮箱对应的主账号
	let accountRow = from?.address ? await accountService.selectByEmailIncludeDel(c, from.address) : null;
	if (!accountRow || accountRow.userId !== user.userId) {
		accountRow = await accountService.selectByEmailIncludeDel(c, user.email);
	}
	if (!accountRow || accountRow.userId !== user.userId) {
		throw new EwsFault('ErrorInvalidRequest', `No sender account available for ${user.email}.`);
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

	const itemId = Number(emailRow?.emailId) || 0;
	return operationResponse('CreateItem', responseMessage('CreateItem', {
		body: `<m:Items><t:Message><t:ItemId Id="${escapeXml(String(itemId))}" ChangeKey="${escapeXml(String(emailRow?.createTime ?? ''))}"/></t:Message></m:Items>`
	}));
}

// -------------------------------------------------------------- UpdateItem ---

/** 已读标记：项目 unread 语义 0=未读 / 1=已读；同时 touch update_time 让增量同步能发出 Update 事件 */
async function updateReadFlag(c, userId, emailId, unread) {
	try {
		await c.env.db.prepare('UPDATE email SET unread = ?, update_time = ? WHERE email_id = ? AND user_id = ?')
			.bind(unread, nowText(), emailId, userId).run();
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
		const row = await orm(c).select({ emailId: email.emailId }).from(email)
			.where(and(eq(email.userId, userId), eq(email.emailId, itemId)))
			.get();
		if (!row) {
			messages.push(responseMessage('UpdateItem', {
				responseClass: 'Error', responseCode: 'ErrorItemNotFound', messageText: `Item not found: ${itemId}`
			}));
			continue;
		}

		if (unread !== null) {
			await updateReadFlag(c, userId, itemId, unread);
		}

		messages.push(responseMessage('UpdateItem', {}));
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
	const ownedIds = [];
	for (const chunk of chunkList(ids)) {
		const owned = await orm(c).select({ emailId: email.emailId }).from(email)
			.where(and(eq(email.userId, user.userId), inArray(email.emailId, chunk)))
			.all();
		ownedIds.push(...owned.map((row) => row.emailId));
	}
	if (ownedIds.length === 0) {
		return operationResponse('DeleteItem', responseMessage('DeleteItem', {
			responseClass: 'Error', responseCode: 'ErrorItemNotFound', messageText: 'Item not found.'
		}));
	}

	// HardDelete 也按软删除处理（安全）：与 Web 端 DELETE /email/delete 完全同一路径（含 syncDelete 设置）
	for (const chunk of chunkList(ownedIds)) {
		await emailService.delete(c, { emailIds: chunk.join(',') }, user.userId);
	}
	return operationResponse('DeleteItem', responseMessage('DeleteItem', {}));
}

// ---------------------------------------------------------------- SendItem ---

async function handleSendItem() {
	// CloudMail 没有 outbox 语义：邮件在 CreateItem(SendOnly/SendAndSaveCopy) 时已发出
	throw new EwsFault('ErrorItemNotFound', 'SendItem is not supported: messages are sent by CreateItem.');
}

// ---------------------------------------------------------------- 分发 -------

const HANDLERS = {
	GetFolder: handleGetFolder,
	SyncFolderHierarchy: handleSyncFolderHierarchy,
	SyncFolderItems: handleSyncFolderItems,
	GetItem: handleGetItem,
	GetAttachment: handleGetAttachment,
	CreateItem: handleCreateItem,
	UpdateItem: handleUpdateItem,
	DeleteItem: handleDeleteItem,
	SendItem: handleSendItem
};

export async function dispatch(c, parsed, user) {
	const handler = HANDLERS[parsed.operation];
	if (!handler) {
		throw new EwsFault('ErrorNotImplemented',
			`Operation ${parsed.operation} is not implemented by the CloudMail EWS bridge.`);
	}
	return handler(c, parsed.payload, user);
}
