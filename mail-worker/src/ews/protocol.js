/**
 * EWS 协议层（纯函数）：邮件项 / 文件夹 XML、同步状态编解码、附件解析与 base64 工具。
 *
 * 与 handlers.js（编排 D1/COS/service）的分工：本模块零项目依赖（只 import ./const.js、./xml.js），
 * 因此可以被 node 直接 import 做断言（scripts/test-ews-smoke.mjs），也是 TB 实际解析的那层字符串。
 *
 * 注意：这里出现的少量数字常量（1/0）与 ../const/entity-const 的语义一一对应，
 * 为保持零项目依赖而内联，注释处标注了来源。
 */

import { EWS_MAX_MIME_ITEM_IDS, EWS_ROOT_CHILDREN } from './const.js';
import { children, escapeXml, firstChild, textOf } from './xml.js';

// ../const/entity-const：emailConst.unread（0=未读，1=已读）
const UNREAD = 0;
const READ = 1;
// ../const/entity-const：attConst.type（0=普通附件，1=内嵌图）
const ATT_TYPE_EMBED = 1;
// ../const/entity-const：isDel（1=已删除）
const IS_DEL_DELETE = 1;
// ../const/entity-const：emailConst.type（0=收件，1=发件）
const TYPE_SEND = 1;

// ---------------------------------------------------------------- 通用 ----

/** 'YYYY-MM-DD HH:mm:ss'（UTC）→ EWS 的 xs:dateTime */
export function toIso(text) {
	const value = String(text ?? '').trim();
	if (value === '') return '';
	return value.replace(' ', 'T') + 'Z';
}

export function toDateMs(text) {
	const value = String(text ?? '').trim();
	if (value === '') return NaN;
	const ms = Date.parse(value.replace(' ', 'T') + 'Z');
	return Number.isFinite(ms) ? ms : NaN;
}

export function parseJsonArray(text) {
	if (!text) return [];
	try {
		const parsed = JSON.parse(text);
		return Array.isArray(parsed) ? parsed : [];
	} catch (e) {
		return [];
	}
}

export function stripCidBrackets(value) {
	return String(value ?? '').trim().replace(/^</, '').replace(/>$/, '');
}

export function cleanBase64(text) {
	return String(text ?? '').replace(/\s+/g, '');
}

export function base64ToBytes(text) {
	const clean = cleanBase64(text);
	const binary = clean === '' ? '' : atob(clean);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return bytes;
}

export function base64EncodeBytes(bytes) {
	let binary = '';
	for (let i = 0; i < bytes.length; i += 0x8000) {
		binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
	}
	return btoa(binary);
}

/** base64（可含空白）解码后的字节数，用于发信前的附件大小护栏 */
export function base64DecodedSize(text) {
	const clean = cleanBase64(text);
	if (clean === '') return 0;
	let padding = 0;
	if (clean.endsWith('==')) padding = 2;
	else if (clean.endsWith('=')) padding = 1;
	return Math.max(0, Math.floor((clean.length * 3) / 4) - padding);
}

export function changeKeyOf(row) {
	return String(row?.eff ?? row?.createTime ?? '');
}

// ------------------------------------------------------------ 同步状态 ----

/** SyncState 对客户端是不透明字符串：base64(JSON{v,wm,wid,cur})，v 为版本 */
export function encodeSyncState(state) {
	try {
		return btoa(JSON.stringify(state));
	} catch (e) {
		return '';
	}
}

/** 解不出来的 SyncState 一律当「无状态」（初始全量），避免把非法水位当增量用 */
export function decodeSyncState(token) {
	if (!token) return null;
	try {
		const parsed = JSON.parse(atob(String(token).trim()));
		if (!parsed || typeof parsed !== 'object' || parsed.v !== 1) return null;
		if (typeof parsed.wm !== 'string') return null;
		return {
			v: 1,
			wm: parsed.wm,
			wid: Number.isFinite(Number(parsed.wid)) ? Number(parsed.wid) : 0,
			cur: parsed.cur === null || parsed.cur === undefined || !Number.isFinite(Number(parsed.cur))
				? null
				: Number(parsed.cur)
		};
	} catch (e) {
		return null;
	}
}

export function emptySyncState() {
	return { v: 1, wm: '', wid: 0, cur: null };
}

// ---------------------------------------------------------------- 文件夹 ----

/**
 * def.kind === 'root' 时 def.extraChildCount 表示「账号文件夹」的个数
 * （账号文件夹也是 root 的子文件夹，ChildFolderCount 必须与同响应的 Create 自洽）。
 */
export function buildFolderXml(def, counts = { total: 0, unread: 0 }, changeKey = '1') {
	const parts = [`<t:FolderId Id="${escapeXml(def.token)}" ChangeKey="${escapeXml(changeKey)}"/>`];
	if (def.kind !== 'root') parts.push('<t:ParentFolderId Id="root" ChangeKey="1"/>');
	// 文件夹类必须是 IPF.*（InterPersonal Folder）：IPM.Note 是条目类，TB 按文件夹类识别用途，
	// 非法值会让整棵文件夹树被丢弃（不进 SyncFolderHierarchy）。
	parts.push('<t:FolderClass>IPF.Note</t:FolderClass>');
	parts.push(`<t:DisplayName>${escapeXml(def.displayName)}</t:DisplayName>`);
	parts.push(`<t:TotalCount>${Number(counts.total) || 0}</t:TotalCount>`);
	const childCount = def.kind === 'root'
		? EWS_ROOT_CHILDREN.length + (Number(def.extraChildCount) || 0)
		: 0;
	parts.push(`<t:ChildFolderCount>${childCount}</t:ChildFolderCount>`);
	parts.push(`<t:UnreadCount>${Number(counts.unread) || 0}</t:UnreadCount>`);
	return `<t:Folder>${parts.join('')}</t:Folder>`;
}

/**
 * FindFolder 成功响应体：m:RootFolder（子文件夹集合）。
 * 空子列表也必须输出 <t:Folders></t:Folders>（TB 与其它客户端都依赖该节点存在）；
 * IncludesLastItemInRange 恒 true（本实现不分页，一次给全）。
 */
export function findFolderRootXml(folders = []) {
	const items = (folders || []).filter(Boolean);
	return `<m:RootFolder TotalItemsInView="${items.length}" IncludesLastItemInRange="true">` +
		`<t:Folders>${items.join('')}</t:Folders>` +
		'</m:RootFolder>';
}

// ------------------------------------------------------------ ResolveNames --

/**
 * ResolveNames 的目录匹配（大小写不敏感）：UnresolvedEntry 命中当前登录用户的
 * 显示名、邮箱全称、邮箱本地部分/域，或用户邮箱包含该串 → true。
 * TB 账号验证阶段会发它解析/校验地址；无匹配时 handler 回 ErrorNameResolutionNoResults
 * （标准 ResponseMessage，绝不抛 Fault —— TB 把 Fault 当作认证失败）。
 */
export function resolveNameMatches(entry, address, name = '') {
	const needle = String(entry ?? '').trim().toLowerCase();
	if (needle === '') return false;
	const display = String(name ?? '').trim().toLowerCase();
	if (display !== '' && needle === display) return true;

	const emailAddress = String(address ?? '').trim().toLowerCase();
	if (emailAddress === '') return false;
	if (needle === emailAddress) return true;

	// 「Name <local@domain>」这类完整地址串，或只给本地部分/域
	const at = emailAddress.lastIndexOf('@');
	const local = at === -1 ? emailAddress : emailAddress.slice(0, at);
	const domain = at === -1 ? '' : emailAddress.slice(at + 1);
	if (local !== '' && needle.includes(local)) return true;
	if (domain !== '' && needle.includes(domain)) return true;
	return emailAddress.includes(needle);
}

/** 单个 t:Resolution（目录项：当前登录用户的邮箱） */
export function resolutionXml(name, address) {
	const emailAddress = String(address ?? '').trim();
	if (emailAddress === '') return '';
	return '<t:Resolution><t:Mailbox>' +
		`<t:Name>${escapeXml(name ?? '')}</t:Name>` +
		`<t:EmailAddress>${escapeXml(emailAddress)}</t:EmailAddress>` +
		'<t:RoutingType>SMTP</t:RoutingType>' +
		'<t:MailboxType>Mailbox</t:MailboxType>' +
		'</t:Mailbox></t:Resolution>';
}

/** ResolveNames 成功响应体：m:ResolutionSet（messages ns，与 Exchange 的 messages.xsd 一致） */
export function resolutionSetXml(resolutions = []) {
	const items = (resolutions || [])
		.map((item) => resolutionXml(item?.name, item?.address))
		.filter(Boolean);
	if (items.length === 0) return '';
	return `<m:ResolutionSet IndexedPagingOffset="1" TotalItemsInView="${items.length}" IncludesLastItemInRange="true">` +
		`${items.join('')}</m:ResolutionSet>`;
}

// ------------------------------------------------ 服务器时区 / MailTips -------

/**
 * GetServerTimeZones 的最小合法响应体：只回标准 UTC TimeZoneDefinition。
 * 时区数据缺失时部分客户端会拒绝完成账号向导，因此这里不能回 Fault。
 */
export function timeZoneDefinitionsXml() {
	return '<m:TimeZoneDefinitions>' +
		'<t:TimeZoneDefinition Id="UTC" Name="UTC">' +
		'<t:Periods><t:Period Bias="PT0M" Name="UTC" Id="UTC"/></t:Periods>' +
		'<t:TransitionsGroups><t:TransitionsGroup Id="0">' +
		'<t:Transition><t:To Kind="Period">UTC</t:To></t:Transition>' +
		'</t:TransitionsGroup></t:TransitionsGroups>' +
		'</t:TimeZoneDefinition>' +
		'</m:TimeZoneDefinitions>';
}

/** GetMailTips 的响应体：每个收件人一个 t:MailTips（无特殊 tips，仅回显地址） */
export function mailTipsXml(recipients = []) {
	const items = (recipients || [])
		.map((item) => String(item?.address ?? item?.email ?? '').trim())
		.filter((address) => address !== '')
		.map((address) => '<t:MailTips><t:RecipientAddress>' +
			`<t:EmailAddress>${escapeXml(address)}</t:EmailAddress>` +
			'</t:RecipientAddress></t:MailTips>');
	if (items.length === 0) return '';
	return `<m:MailTips>${items.join('')}</m:MailTips>`;
}

// ---------------------------------------------------------------- 邮件项 ----

export function mailboxXml(address, name) {
	const emailAddress = String(address ?? '').trim();
	if (emailAddress === '') return '';
	const nameXml = String(name ?? '').trim() === '' ? '' : `<t:Name>${escapeXml(name)}</t:Name>`;
	return `<t:Mailbox>${nameXml}<t:EmailAddress>${escapeXml(emailAddress)}</t:EmailAddress></t:Mailbox>`;
}

export function recipientsXml(tag, list) {
	const items = (list || [])
		.map((item) => mailboxXml(item?.address ?? item?.email, item?.name))
		.filter(Boolean);
	if (items.length === 0) return '';
	return `<t:${tag}>${items.join('')}</t:${tag}>`;
}

/** 邮件行的 cc/bcc 列（JSON 字符串 [{address,name}]）→ mime-build 的地址数组 */
export function parseAddressList(raw) {
	return parseJsonArray(raw)
		.map((item) => ({ email: item?.address ?? item?.email, name: item?.name }))
		.filter((item) => item.email);
}

/** 收件人：优先原始 recipient（收件保留原 To 列表），缺失时回落 toEmail */
export function rowRecipients(row) {
	const list = parseJsonArray(row?.recipient)
		.map((item) => ({ address: item?.address ?? item?.email, name: item?.name }))
		.filter((item) => item.address);
	if (list.length === 0 && row?.toEmail) list.push({ address: row.toEmail, name: row.toName });
	return list;
}

export function isInlineAttachment(row) {
	if (row?.type === ATT_TYPE_EMBED) return true;
	return typeof row?.contentId === 'string' && row.contentId.trim() !== '';
}

/**
 * 单封邮件 → t:Message（TB 依赖的字段集）。
 * options.mimeContent：base64 原文（仅客户端显式请求 MimeContent 时传），base64 字符无需转义。
 */
export function buildItemXml(row, options = {}) {
	const {
		changeKey = '',
		hasAttachments = false,
		mimeContent = '',
		body = null,
		parentFolderId = ''
	} = options;

	const parts = [];
	// mime-build 的 base64 输出为 76 列 CRLF 折行（MIME 传输需要），但 t:MimeContent 是
	// 单值文本元素：去掉折行换成连续 base64（TB/ews-rs 反序列化对空白更保守，连续更稳）
	if (mimeContent !== '') parts.push(`<t:MimeContent CharacterSet="UTF-8">${cleanBase64(mimeContent)}</t:MimeContent>`);
	parts.push(`<t:ItemId Id="${escapeXml(row.emailId)}" ChangeKey="${escapeXml(changeKey)}"/>`);
	if (parentFolderId !== '') parts.push(`<t:ParentFolderId Id="${escapeXml(parentFolderId)}" ChangeKey="1"/>`);
	parts.push('<t:ItemClass>IPM.Note</t:ItemClass>');
	parts.push(`<t:Subject>${escapeXml(row.subject ?? '')}</t:Subject>`);
	if (body?.html) parts.push(`<t:Body BodyType="HTML">${escapeXml(body.html)}</t:Body>`);
	else if (body?.text) parts.push(`<t:Body BodyType="Text">${escapeXml(body.text)}</t:Body>`);
	parts.push(`<t:DateTimeReceived>${escapeXml(toIso(row.createTime))}</t:DateTimeReceived>`);
	parts.push(`<t:DateTimeSent>${escapeXml(toIso(row.createTime))}</t:DateTimeSent>`);
	parts.push('<t:IsDraft>false</t:IsDraft>');
	parts.push('<t:IsFromMe>false</t:IsFromMe>');
	const from = mailboxXml(row.sendEmail, row.name);
	if (from !== '') parts.push(`<t:From>${from}</t:From><t:Sender>${from}</t:Sender>`);
	const to = recipientsXml('ToRecipients', rowRecipients(row));
	if (to !== '') parts.push(to);
	const cc = recipientsXml('CcRecipients', parseJsonArray(row.cc));
	if (cc !== '') parts.push(cc);
	const bcc = recipientsXml('BccRecipients', parseJsonArray(row.bcc));
	if (bcc !== '') parts.push(bcc);
	parts.push(`<t:IsRead>${Number(row.unread) === READ ? 'true' : 'false'}</t:IsRead>`);
	parts.push(`<t:HasAttachments>${hasAttachments ? 'true' : 'false'}</t:HasAttachments>`);
	parts.push('<t:Importance>Normal</t:Importance>');
	return `<t:Message>${parts.join('')}</t:Message>`;
}

export function isSentRow(row) {
	return Number(row?.type) === TYPE_SEND;
}

export function isDeletedRow(row) {
	return row?.trash === 1 || row?.isDel === IS_DEL_DELETE;
}

export function isUnreadRow(row) {
	return Number(row?.unread) === UNREAD;
}

/** 邮件是否「在」该文件夹里（正常列表可见 = 未删除且不在垃圾桶；垃圾桶文件夹相反） */
export function isVisibleInFolder(kind, row) {
	// 账号文件夹（acct-<id>）的内容 = 该账号的可见收件，口径与收件箱一致（账号维度由 SQL 过滤）
	if (kind === 'inbox' || kind === 'account') {
		return Number(row?.type) === 0 && row?.isDel !== IS_DEL_DELETE && row?.trash !== 1;
	}
	if (kind === 'sent') {
		return Number(row?.type) === TYPE_SEND && row?.isDel !== IS_DEL_DELETE && row?.trash !== 1;
	}
	if (kind === 'trash') {
		return row?.trash === 1 || row?.isDel === IS_DEL_DELETE;
	}
	return false;
}

/**
 * 增量行 → 变更类型：
 *   'create' 新增（客户没见过的邮件）/ 'update' 已读等变更 / 'delete' 移出该文件夹
 *   null     客户端从未收到过、且当前不在该文件夹里（无需发变更，避免让客户端更新不存在的项）
 * 判据：create_time <= 水位（watermark）⇒ 客户端在初始全量阶段已收到过这封邮件。
 */
export function classifySyncRow(kind, row, watermark) {
	const known = String(row?.createTime ?? '') <= watermark;
	if (!isVisibleInFolder(kind, row)) return known ? 'delete' : null;
	return known ? 'update' : 'create';
}

// ------------------------------------------------ 资源护栏（纯函数） --------

/**
 * MimeContent 单次响应的 Id 白名单：只允许前 limit 个 Id 真正重建 MimeContent，
 * 其余 Id 仍回元数据（客户端可按需再取），避免一次响应重建过多重邮件。
 * 返回 Set 便于 O(1) 判定。
 */
export function mimeContentIdSet(ids, limit = EWS_MAX_MIME_ITEM_IDS) {
	const value = Number(limit);
	const max = Number.isFinite(value) && value > 0 ? Math.floor(value) : EWS_MAX_MIME_ITEM_IDS;
	const set = new Set();
	for (const id of ids || []) {
		if (set.size >= max) break;
		const emailId = Number(id);
		if (Number.isFinite(emailId) && emailId > 0) set.add(emailId);
	}
	return set;
}

/**
 * 本次响应「已重建附件字节」账本护栏：budget = { total, limit }（跨多封邮件累计）。
 * 返回 false 表示本附件会使累计超出 limit → 调用方走既有「跳过该附件」路径。
 * size <= 0 视为大小未知（老数据 size 未回填）：放行，下载后由调用方按实际字节累加。
 */
export function attBudgetAllows(budget, size) {
	const limit = Number(budget?.limit);
	const total = Number(budget?.total);
	if (!Number.isFinite(limit) || limit <= 0) return true;
	if (!Number.isFinite(total)) return true;
	const value = Number(size) || 0;
	if (value <= 0) return true;
	return total + value <= limit;
}

/**
 * 被跳过的内嵌图（超 EWS_MAX_ATT_BYTES 或超本次响应附件账本）在 MimeContent 里不能无声消失：
 * 正文里引用它的上下文替换成可见文字占位（大小阈值动态取当前生效配置，向上取整到 0.1MB）。
 */
export function oversizeInlinePlaceholderHtml(maxAttBytes) {
	const bytes = Number(maxAttBytes);
	const mb = Number.isFinite(bytes) && bytes > 0
		? Math.max(0.1, Math.round((bytes / (1024 * 1024)) * 10) / 10)
		: 1;
	return '<p style="border:1px dashed #999;padding:8px;color:#666;">' +
		`[图片过大（>${mb}MB），此客户端无法加载，请使用网页版查看]</p>`;
}

/**
 * 把 html 中引用「被跳过的内嵌图」的整个 <img ...> 标签替换成占位提示。
 * refs：被跳过内嵌图的引用形态集合（`cid:<contentId>` 与库内正文的 `{{domain}}<key>` 两种）。
 * 标签可能带任意属性（class/width/data-*…）→ 宽匹配整个 img 标签，仅对 src 命中的动手，其余原样保留。
 */
export function replaceInlineImagesWithPlaceholder(html, refs, maxAttBytes) {
	const source = typeof html === 'string' ? html : '';
	if (source === '' || !refs || refs.size === 0) return source;
	const placeholder = oversizeInlinePlaceholderHtml(maxAttBytes);
	return source.replace(/<img\b[^>]*>/gi, (tag) => {
		const match = tag.match(/\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/i);
		const src = (match?.[1] ?? match?.[2] ?? match?.[3] ?? '').trim();
		return src !== '' && refs.has(src) ? placeholder : tag;
	});
}

/**
 * 物理删除 tombstone（ews_tombstone 行）→ 该邮件物理删除前所属的文件夹 token：
 * trash=1 → deleteditems；否则按 type（0=收件 → inbox，1=发件 → sentitems）。
 * 与 handlers.js 的 visibleFilter/scopeFilter 口径一致。
 */
export function tombstoneFolderToken(row) {
	if (Number(row?.trash) === 1) return 'deleteditems';
	return Number(row?.type) === TYPE_SEND ? 'sentitems' : 'inbox';
}

/**
 * 物理删除事件 → 本次请求文件夹要产出的 Delete ItemId 列表（纯函数）：
 *   - 只产出「物理删除前属于本文件夹」的行（其它文件夹的 Delete 由各自的 SyncFolderItems 负责）；
 *   - 与同轮已知 ItemId 集合（Create/Update/Delete 已产出的 Id）去重，同一 Id 一轮只出现一次；
 *   - tombstone 内自身重复（同 emailId）也去重。
 * @param {string} folderToken 本次请求的文件夹 token（inbox/sentitems/deleteditems）
 * @param {Array<{email_id?: number, emailId?: number, type?: number, trash?: number}>} tombstones
 * @param {Set<number>|null} knownIds
 * @returns {number[]}
 */
export function selectTombstoneDeletes(folderToken, tombstones, knownIds = null) {
	const seen = new Set();
	const out = [];
	for (const row of tombstones || []) {
		const emailId = Number(row?.email_id ?? row?.emailId);
		if (!Number.isFinite(emailId) || emailId <= 0) continue;
		if (tombstoneFolderToken(row) !== folderToken) continue;
		if (knownIds && knownIds.has(emailId)) continue;
		if (seen.has(emailId)) continue;
		seen.add(emailId);
		out.push(emailId);
	}
	return out;
}

// ---------------------------------------------------------- CreateItem 侧 ----

/**
 * CreateItem 成功响应体：`<m:Items><t:Message><t:ItemId Id="…"/></t:Message></m:Items>`。
 * TB（ews-rs）只在 Items 里取新建邮件的 ItemId，元素缺失会报 MissingIdInResponse；
 * ChangeKey 为空时仍输出空属性（与 Exchange 一致，属性可空、元素不可缺）。
 */
export function createItemItemsXml(itemId, changeKey = '') {
	return '<m:Items><t:Message>' +
		`<t:ItemId Id="${escapeXml(String(itemId ?? ''))}" ChangeKey="${escapeXml(String(changeKey ?? ''))}"/>` +
		'</t:Message></m:Items>';
}

export function parseMailbox(node) {
	if (!node || typeof node !== 'object') return null;
	const mailbox = firstChild(node, 'Mailbox') ?? node;
	const address = textOf(firstChild(mailbox, 'EmailAddress')).trim();
	if (address === '') return null;
	return { address, name: textOf(firstChild(mailbox, 'Name')).trim() };
}

export function parseMailboxList(container) {
	const list = [];
	for (const node of children(container, 'Mailbox')) {
		const address = textOf(firstChild(node, 'EmailAddress')).trim();
		if (address === '') continue;
		list.push({ address, name: textOf(firstChild(node, 'Name')).trim() });
	}
	return list;
}

/**
 * TB 发信时正文里的内嵌图引用是 cid:<contentId>，而项目发信链路（attService.toImageUrlHtml）
 * 只识别 data:image / 站内 URL —— 这里先把内嵌附件还原成 data: URL 内联进正文。
 * 正文里没引用的（或未标 IsInline 的）内嵌附件退化为普通附件，避免丢件。
 */
export function splitOutgoingAttachments(html, outgoing) {
	const source = typeof html === 'string' ? html : '';
	const attachments = [];
	const demoted = [];
	let result = source;

	for (const item of outgoing || []) {
		const dataUrl = `data:${item.mimeType};base64,${item.content}`;
		const referencedByCid = item.contentId !== '' && result.includes(`cid:${item.contentId}`);
		// 少数客户端用文件名当 cid
		const referencedByName = result.includes(`cid:${item.name}`);

		// IsInline 但类型不是 image/* 或 video/*（如 text/calendar、application/pdf）：
		// 发信链路只把 data: 图片/视频内联（att-service.toImageUrlHtml），替换成 data: URL 只会
		// 变成正文里的坏内容甚至丢件 → 强制按普通附件发出（不做 cid: → data: 替换）
		const demotedInline = item.isInline === true && !/^(image|video)\//i.test(String(item.mimeType ?? ''));
		if (demotedInline) demoted.push(item.name);

		if (!demotedInline && (item.isInline || referencedByCid || referencedByName)) {
			let replaced = result;
			if (item.contentId !== '') replaced = replaced.split(`cid:${item.contentId}`).join(dataUrl);
			if (replaced === result) replaced = replaced.split(`cid:${item.name}`).join(dataUrl);
			if (replaced !== result) {
				result = replaced;
				continue;
			}
		}

		attachments.push({
			// 原始 base64（不带 data: 前缀）：att-service.saveSendAtt 直接 atob(content)，
			// 与 Web 端上传的附件形态一致（mail-vue 用 FileReader 后 split(',')[1]）
			content: item.content,
			filename: item.name,
			size: base64DecodedSize(item.content),
			type: item.mimeType,
			mimeType: item.mimeType,
			contentType: item.mimeType
		});
	}

	if (demoted.length > 0) {
		console.info(`[ews] IsInline attachments with non image/video type are sent as regular attachments: ${demoted.join(', ')}`);
	}

	return { html: result, attachments };
}
