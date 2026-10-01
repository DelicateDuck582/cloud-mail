/**
 * EWS 协议层（纯函数）：邮件项 / 文件夹 XML、同步状态编解码、附件解析与 base64 工具。
 *
 * 与 handlers.js（编排 D1/COS/service）的分工：本模块零项目依赖（只 import ./const.js、./xml.js），
 * 因此可以被 node 直接 import 做断言（scripts/test-ews-smoke.mjs），也是 TB 实际解析的那层字符串。
 *
 * 注意：这里出现的少量数字常量（1/0）与 ../const/entity-const 的语义一一对应，
 * 为保持零项目依赖而内联，注释处标注了来源。
 */

import { EWS_ROOT_CHILDREN } from './const.js';
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

export function buildFolderXml(def, counts = { total: 0, unread: 0 }, changeKey = '1') {
	const parts = [`<t:FolderId Id="${escapeXml(def.token)}" ChangeKey="${escapeXml(changeKey)}"/>`];
	if (def.kind !== 'root') parts.push('<t:ParentFolderId Id="root" ChangeKey="1"/>');
	parts.push('<t:FolderClass>IPM.Note</t:FolderClass>');
	parts.push(`<t:DisplayName>${escapeXml(def.displayName)}</t:DisplayName>`);
	parts.push(`<t:TotalCount>${Number(counts.total) || 0}</t:TotalCount>`);
	parts.push(`<t:ChildFolderCount>${def.kind === 'root' ? EWS_ROOT_CHILDREN.length : 0}</t:ChildFolderCount>`);
	parts.push(`<t:UnreadCount>${Number(counts.unread) || 0}</t:UnreadCount>`);
	return `<t:Folder>${parts.join('')}</t:Folder>`;
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
	if (mimeContent !== '') parts.push(`<t:MimeContent CharacterSet="UTF-8">${mimeContent}</t:MimeContent>`);
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
	if (kind === 'inbox') {
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

// ---------------------------------------------------------- CreateItem 侧 ----

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
	let result = source;

	for (const item of outgoing || []) {
		const dataUrl = `data:${item.mimeType};base64,${item.content}`;
		const referencedByCid = item.contentId !== '' && result.includes(`cid:${item.contentId}`);
		// 少数客户端用文件名当 cid
		const referencedByName = result.includes(`cid:${item.name}`);

		if (item.isInline || referencedByCid || referencedByName) {
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

	return { html: result, attachments };
}
