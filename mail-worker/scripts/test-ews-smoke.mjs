/**
 * EWS 桥接层冒烟测试 —— 纯 node，无需 wrangler/Cloudflare 运行时：
 *
 *   cd mail-worker && node --no-warnings scripts/test-ews-smoke.mjs
 *
 * 覆盖 TB 真实会发出的 SOAP 请求解析、响应模板结构与转义（含 XML 良构校验）、
 * SyncState 编解码、base64 工具、CreateItem 的 cid→data: 内嵌图还原、MimeContent 集成、
 * 请求体大小护栏、MimeContent/附件字节护栏、物理删除 tombstone 的 Delete 事件映射、
 * 以及 dispatch 对原型链操作名（toString）返回标准 Fault。
 *
 * 只依赖 fast-xml-parser（package.json dependencies）：
 *   - xml.js / protocol.js / const.js / request-guard.js 无项目依赖，可直接 file URL import；
 *   - handlers.js 依赖 hono/drizzle 等，只在「17. dispatch 原型链」一例里动态 import：
 *     项目内大量 import 省略了 .js 扩展名（wrangler 打包能解析、node 不能），该用例用
 *     node:module 的 resolve hook（data: URL 内联注册）补一次 .js 后缀再 import，
 *     从而对真实的 dispatch 做断言。
 */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { register } from 'node:module';
import { XMLParser, XMLValidator } from 'fast-xml-parser';

import {
	EWS_AUTH_CACHE_TTL,
	EWS_AUTH_FAIL_DELAY_MS,
	EWS_MAX_MIME_ITEM_IDS,
	EWS_SYNC_PAGE,
	ewsFolderDef,
	ewsMaxAttBytes,
	EWS_DEFAULT_MAX_ATT_BYTES
} from '../src/ews/const.js';
import {
	attr,
	asArray,
	children,
	escapeXml,
	firstChild,
	isTrueFlag,
	operationResponse,
	parseSoapRequest,
	responseMessage,
	soapEnvelope,
	soapFault,
	textOf
} from '../src/ews/xml.js';
import {
	attBudgetAllows,
	base64DecodedSize,
	base64EncodeBytes,
	base64ToBytes,
	buildFolderXml,
	buildItemXml,
	changeKeyOf,
	classifySyncRow,
	decodeSyncState,
	emptySyncState,
	encodeSyncState,
	isDeletedRow,
	isInlineAttachment,
	isUnreadRow,
	isVisibleInFolder,
	mimeContentIdSet,
	parseAddressList,
	parseMailboxList,
	rowRecipients,
	selectTombstoneDeletes,
	splitOutgoingAttachments,
	stripCidBrackets,
	toIso,
	tombstoneFolderToken
} from '../src/ews/protocol.js';
import { parseContentLength, precheckContentLength, readLimitedText } from '../src/ews/request-guard.js';
import { buildMimeBase64 } from '../src/ews/mime-build.js';

const cases = [];
function testCase(name, fn) {
	cases.push({ name, fn });
}

const parseBack = new XMLParser({
	removeNSPrefix: true,
	ignoreAttributes: false,
	attributeNamePrefix: '@_',
	parseTagValue: false,
	parseAttributeValue: false,
	trimValues: true
});

/** 生成的所有响应都必须是良构 XML（否则 TB 直接报解析错误） */
function assertWellFormed(xml) {
	const result = XMLValidator.validate(xml);
	assert.equal(result, true, `XML must be well formed: ${typeof result === 'object' ? result.err?.msg : ''}`);
	assert.ok(xml.startsWith('<?xml version="1.0" encoding="utf-8"?>'), 'XML declaration present');
}

function envelopeFor(operation, body) {
	return soapEnvelope(operationResponse(operation, body));
}

/**
 * handlers.js / router.js 的传递依赖里大量 import 省略 .js 扩展名（wrangler 打包能解析、node 不能），
 * 注册一次 resolve hook 补后缀，让 node 也能 import 真实模块做断言。
 */
let resolveHookReady = false;
function ensureNodeResolveHook() {
	if (resolveHookReady) return;
	const hook = `export async function resolve(specifier, context, next) {
  if (specifier.startsWith('node:') || specifier.startsWith('file:') || specifier.startsWith('data:')) return next(specifier, context);
  try { return await next(specifier, context); }
  catch (e) { try { return await next(specifier + '.js', context); } catch (e2) { throw e; } }
}`;
	register('data:text/javascript,' + encodeURIComponent(hook));
	resolveHookReady = true;
}

// ------------------------------------------------------- 1. 请求解析（TB 原样）

const SYNC_REQUEST_EMPTY_STATE = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013" />
  </soap:Header>
  <soap:Body>
    <m:SyncFolderItems>
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:IncludeMimeContent>false</t:IncludeMimeContent>
      </m:ItemShape>
      <m:SyncFolderId>
        <t:DistinguishedFolderId Id="inbox" />
      </m:SyncFolderId>
      <m:SyncState />
      <m:MaxChangesReturned>512</m:MaxChangesReturned>
      <m:SyncScope>NormalItems</m:SyncScope>
    </m:SyncFolderItems>
  </soap:Body>
</soap:Envelope>`;

const SYNC_REQUEST_STATEFUL = `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
            xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <s:Body>
    <m:SyncFolderItems>
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:IncludeMimeContent>true</t:IncludeMimeContent>
      </m:ItemShape>
      <m:SyncFolderId>
        <t:FolderId Id="sentitems" ChangeKey="1" />
      </m:SyncFolderId>
      <m:SyncState>eyJ2IjoxLCJ3bSI6IjIwMjYtMTAtMDEgMTA6MDA6MDAiLCJ3aWQiOjEyLCJjdXIiOm51bGx9</m:SyncState>
      <m:MaxChangesReturned>25</m:MaxChangesReturned>
    </m:SyncFolderItems>
  </s:Body>
</s:Envelope>`;

const GETFOLDER_REQUEST = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
  <soap:Body>
    <m:GetFolder>
      <m:FolderShape>
        <t:BaseShape>AllProperties</t:BaseShape>
      </m:FolderShape>
      <m:FolderIds>
        <t:DistinguishedFolderId Id="inbox" />
        <t:DistinguishedFolderId Id="deleteditems" />
        <t:FolderId Id="custom-folder" />
      </m:FolderIds>
    </m:GetFolder>
  </soap:Body>
</soap:Envelope>`;

testCase('1. SyncFolderItems 请求解析（空 SyncState + m:/t:/soap: 前缀）', () => {
	const parsed = parseSoapRequest(SYNC_REQUEST_EMPTY_STATE);
	assert.equal(parsed.error, undefined, 'no parse error');
	assert.equal(parsed.operation, 'SyncFolderItems');

	const payload = parsed.payload;
	const syncFolderId = firstChild(payload, 'SyncFolderId');
	assert.equal(attr(firstChild(syncFolderId, 'DistinguishedFolderId'), 'Id'), 'inbox', 'folderId parsed');
	assert.equal(textOf(firstChild(payload, 'SyncState')), '', 'empty SyncState stays an empty string');
	assert.equal(textOf(firstChild(payload, 'MaxChangesReturned')), '512', 'maxChangesReturned parsed as string');
	assert.equal(isTrueFlag(firstChild(firstChild(payload, 'ItemShape'), 'IncludeMimeContent')), false);
	assert.equal(textOf(firstChild(firstChild(payload, 'ItemShape'), 'BaseShape')), 'IdOnly');
	assert.equal(ewsFolderDef(attr(firstChild(syncFolderId, 'DistinguishedFolderId'), 'Id')).token, 'inbox');
});

testCase('2. SyncFolderItems 请求解析（非空 SyncState + IncludeMimeContent + FolderId）', () => {
	const parsed = parseSoapRequest(SYNC_REQUEST_STATEFUL);
	assert.equal(parsed.operation, 'SyncFolderItems');

	const payload = parsed.payload;
	assert.equal(attr(firstChild(firstChild(payload, 'SyncFolderId'), 'FolderId'), 'Id'), 'sentitems');
	const state = decodeSyncState(textOf(firstChild(payload, 'SyncState')));
	assert.ok(state, 'SyncState decodes');
	assert.equal(state.wm, '2026-10-01 10:00:00');
	assert.equal(state.wid, 12);
	assert.equal(state.cur, null);
	assert.equal(isTrueFlag(firstChild(firstChild(payload, 'ItemShape'), 'IncludeMimeContent')), true);
	assert.equal(Number(textOf(firstChild(payload, 'MaxChangesReturned'))), 25);
});

testCase('3. GetFolder 请求解析（多个 FolderIds + 命名空间前缀不固定）', () => {
	const parsed = parseSoapRequest(GETFOLDER_REQUEST);
	assert.equal(parsed.operation, 'GetFolder');

	const folderIds = firstChild(parsed.payload, 'FolderIds');
	const tokens = children(folderIds, 'DistinguishedFolderId').map((node) => attr(node, 'Id'));
	assert.deepEqual(tokens, ['inbox', 'deleteditems'], '多个 FolderIds 全部解析');
	assert.equal(attr(firstChild(folderIds, 'FolderId'), 'Id'), 'custom-folder');
	assert.equal(ewsFolderDef('msgfolderroot').token, 'root', 'msgfolderroot 归一到 root');
	assert.equal(ewsFolderDef('INBOX').token, 'inbox', '大小写不敏感');
	assert.equal(ewsFolderDef('nonexistent'), null, '未知文件夹 → null（handler 回 ErrorFolderNotFound）');
});

testCase('4. 非法/异常请求：DOCTYPE、空体、非 SOAP、空 Body', () => {
	assert.equal(parseSoapRequest('').error, 'EmptyRequest');
	assert.equal(parseSoapRequest('not xml at all').error, 'NotSoapEnvelope', '非 XML 文本按「不是 SOAP 信封」处理');
	assert.equal(
		parseSoapRequest('<soap:Envelope xmlns:soap="x"><soap:Body><m:A xmlns:m="m"').error,
		'MalformedXml',
		'截断的 XML → MalformedXml'
	);
	assert.equal(parseSoapRequest('<root><a>1</a></root>').error, 'NotSoapEnvelope');
	assert.equal(
		parseSoapRequest('<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>').error,
		'EmptySoapBody'
	);
	assert.equal(
		parseSoapRequest('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="x"><soap:Body><m:A xmlns:m="m"/></soap:Body></soap:Envelope>').error,
		'DoctypeNotAllowed'
	);
});

// --------------------------------------------------- 5. GetFolder 响应模板结构

testCase('5. GetFolder 响应：命名空间、结构、转义、良构', () => {
	const defs = [
		{ token: 'inbox', kind: 'inbox', displayName: 'Inbox' },
		{ token: 'deleteditems', kind: 'trash', displayName: 'Deleted Items' },
		{ token: 'root', kind: 'root', displayName: 'CloudMail' },
		{ token: 'weird', kind: 'inbox', displayName: '<A&B> "quoted" \'apos\'' }
	];
	const folders = defs.map((def, index) => buildFolderXml(def, { total: index * 10, unread: index }, '1'));

	const xml = envelopeFor('GetFolder',
		responseMessage('GetFolder', { body: `<m:Folders>${folders.join('')}</m:Folders>` }));
	assertWellFormed(xml);

	// 命名空间：信封 + 操作元素都声明（TB 依赖 messages/types 两个 ns）
	assert.ok(xml.includes('xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'), 'soap ns');
	assert.ok(xml.includes('xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"'), 'types ns');
	assert.ok(xml.includes('xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"'), 'messages ns');
	assert.ok(xml.includes('<t:ServerVersionInfo'), 'ServerVersionInfo header');

	// 结构（重新解析后按元素取值）
	const doc = parseBack.parse(xml);
	const message = doc.Envelope.Body.GetFolderResponse.ResponseMessages.GetFolderResponseMessage;
	assert.equal(message['@_ResponseClass'], 'Success');
	assert.equal(message.ResponseCode, 'NoError');

	const foldersOut = asArray(message.Folders.Folder);
	assert.equal(foldersOut.length, 4);
	const [inbox, deleted, root, weird] = foldersOut;
	assert.equal(inbox.FolderId['@_Id'], 'inbox');
	assert.equal(inbox.DisplayName, 'Inbox');
	assert.equal(inbox.TotalCount, '0');
	assert.equal(inbox.UnreadCount, '0');
	assert.equal(inbox.ChildFolderCount, '0');
	assert.equal(deleted.FolderId['@_Id'], 'deleteditems');
	assert.equal(deleted.TotalCount, '10');
	assert.equal(deleted.UnreadCount, '1');
	assert.equal(root.ChildFolderCount, '5', 'root 的子文件夹数 = 5');
	assert.ok(!('ParentFolderId' in root), 'root 没有 ParentFolderId');
	assert.equal(weird.DisplayName, '<A&B> "quoted" \'apos\'', '显示名原样往返（转义/反转义闭环）');
	assert.ok(xml.includes('&lt;A&amp;B&gt; &quot;quoted&quot; &apos;apos&apos;'), '特殊字符被转义');
	assert.ok(!xml.includes('<A&B>'), '原始危险字符串不出现在 XML 中');
});

// ----------------------------------------------------------- 6. 邮件项 XML ----

const MAIL_ROW = {
	emailId: 42,
	sendEmail: 'sender@example.com',
	name: '张伟 & Co <evil>',
	subject: 'Quarterly <Report> & "notes" \u0007',
	recipient: JSON.stringify([{ address: 'me@example.com', name: '李四' }]),
	toEmail: 'me@example.com',
	toName: '李四',
	cc: JSON.stringify([{ address: 'cc@example.com', name: '' }]),
	bcc: '[]',
	unread: 1,
	type: 0,
	createTime: '2026-10-01 08:30:00',
	text: 'plain text',
	content: '<p>hi</p>'
};

testCase('6. 邮件项 XML：字段、转义、IsRead/ChangeKey、良构', () => {
	const item = buildItemXml(MAIL_ROW, {
		changeKey: changeKeyOf({ eff: '2026-10-01 09:00:00' }),
		hasAttachments: true,
		parentFolderId: 'inbox'
	});
	const xml = envelopeFor('GetItem', responseMessage('GetItem', { body: `<m:Items>${item}</m:Items>` }));
	assertWellFormed(xml);

	const doc = parseBack.parse(xml);
	const message = doc.Envelope.Body.GetItemResponse.ResponseMessages.GetItemResponseMessage;
	assert.equal(message['@_ResponseClass'], 'Success');
	const out = asArray(message.Items.Message)[0];
	assert.equal(out.ItemId['@_Id'], '42');
	assert.equal(out.ItemId['@_ChangeKey'], '2026-10-01 09:00:00');
	assert.equal(out.ParentFolderId['@_Id'], 'inbox');
	assert.equal(out.ItemClass, 'IPM.Note');
	assert.equal(out.Subject, 'Quarterly <Report> & "notes"', '主题往返（\\u0007 控制字符被剥掉，空白被 XML 解析器 trim）');
	assert.equal(out.DateTimeReceived, '2026-10-01T08:30:00Z');
	assert.equal(out.DateTimeSent, '2026-10-01T08:30:00Z');
	assert.equal(out.IsRead, 'true', 'unread=1 即已读');
	assert.equal(out.HasAttachments, 'true');
	assert.equal(out.Importance, 'Normal');
	assert.equal(out.From.Mailbox.EmailAddress, 'sender@example.com');
	assert.equal(out.From.Mailbox.Name, '张伟 & Co <evil>', '发件人显示名往返');
	assert.deepEqual(asArray(out.ToRecipients.Mailbox).map((m) => m.EmailAddress), ['me@example.com']);
	assert.deepEqual(asArray(out.CcRecipients.Mailbox).map((m) => m.EmailAddress), ['cc@example.com']);
	assert.ok(!('BccRecipients' in out), '空 Bcc 不输出元素');
	assert.ok(!('<Report>' in out), '转义后的主题不会破坏结构');
});

testCase('7. 邮件项 XML：MimeContent / 未读 / 无收件人回落 toEmail', () => {
	const mimeContent = buildMimeBase64({
		from: { email: 'a@example.com', name: 'A' },
		to: [{ email: 'b@example.com' }],
		subject: 'sub',
		dateMs: Date.UTC(2026, 9, 1, 12, 0, 0),
		text: 'hello'
	});
	const row = { ...MAIL_ROW, unread: 0, recipient: null, cc: '[]', toEmail: 'fallback@example.com', toName: '' };
	const item = buildItemXml(row, { changeKey: 'x', mimeContent });
	const xml = envelopeFor('GetItem', responseMessage('GetItem', { body: `<m:Items>${item}</m:Items>` }));
	assertWellFormed(xml);

	const out = asArray(parseBack.parse(xml).Envelope.Body.GetItemResponse.ResponseMessages.GetItemResponseMessage.Items.Message)[0];
	assert.equal(out.IsRead, 'false', 'unread=0 即未读');
	assert.equal(out.HasAttachments, 'false');
	assert.equal(out.ToRecipients.Mailbox.EmailAddress, 'fallback@example.com', 'recipient 为空时回落 toEmail');
	assert.equal(out.MimeContent['@_CharacterSet'], 'UTF-8', 'MimeContent 带 CharacterSet 属性');
	assert.ok(textOf(out.MimeContent).length > 100, 'MimeContent 内联 base64');
	const decodedMime = Buffer.from(textOf(out.MimeContent).replace(/\s+/g, ''), 'base64').toString('utf8');
	assert.ok(decodedMime.startsWith('MIME-Version: 1.0'), 'MimeContent 解码回 MIME 原文');
	assert.ok(decodeMimeBodies(decodedMime).includes('hello'), 'MIME 正文（内层 base64）可见');
});

/** MIME 正文是 base64，明文引用（cid:）只能在内层解码后校验 */
function decodeMimeBodies(raw) {
	const blobs = [];
	let current = [];
	for (const line of raw.split('\r\n')) {
		if (/^[A-Za-z0-9+/]{4,}={0,2}$/.test(line)) current.push(line);
		else if (current.length > 0) {
			blobs.push(current.join(''));
			current = [];
		}
	}
	if (current.length > 0) blobs.push(current.join(''));
	return blobs.map((blob) => Buffer.from(blob, 'base64').toString('utf8')).join('\n');
}

// -------------------------------------------------------- 8. SyncState 编解码 --

testCase('8. SyncState 编解码：往返、垃圾输入、版本不符', () => {
	const state = { v: 1, wm: '2026-10-01 10:00:00', wid: 1234, cur: 88 };
	const token = encodeSyncState(state);
	assert.equal(typeof token, 'string');
	assert.equal(token.includes('<'), false);
	assert.deepEqual(decodeSyncState(token), state);
	assert.deepEqual(decodeSyncState(encodeSyncState(emptySyncState())), { v: 1, wm: '', wid: 0, cur: null });
	assert.equal(decodeSyncState(''), null);
	assert.equal(decodeSyncState('not base64 !!!'), null);
	assert.equal(decodeSyncState(btoa(JSON.stringify({ v: 2, wm: '' }))), null, '版本不符视为无状态（重全量）');
	assert.equal(decodeSyncState(btoa(JSON.stringify({ v: 1 }))), null, '缺 wm 视为无状态');
});

// ------------------------------------------------------------ 9. base64 工具 --

testCase('9. base64 工具：与 Buffer 对齐、往返一致', () => {
	assert.equal(base64DecodedSize(''), 0);
	assert.equal(base64DecodedSize('Zg=='), 1);
	assert.equal(base64DecodedSize('Zm8='), 2);
	assert.equal(base64DecodedSize('Zm9v'), 3);
	assert.equal(base64DecodedSize(' Z m 9 v\n'), 3, '空白被忽略');

	const bytes = Uint8Array.from([0, 1, 2, 250, 255, 128, 64]);
	const encoded = base64EncodeBytes(bytes);
	assert.equal(encoded, Buffer.from(bytes).toString('base64'));
	assert.deepEqual(base64ToBytes(encoded), bytes);
	assert.deepEqual(base64ToBytes(''), new Uint8Array(0));
	assert.equal(base64DecodedSize(encoded), bytes.length);
});

// -------------------------------------------------------------- 10. Fault -----

testCase('10. SOAP Fault：结构、转义、良构', () => {
	const xml = soapFault('ErrorInvalidRequest', 'Attachment "a<&>b.txt" is too large & unsupported.');
	assertWellFormed(xml);
	assert.ok(xml.includes('<faultcode>soap:Client</faultcode>'));
	assert.ok(xml.includes('&lt;&amp;&gt;'), 'faultstring 中的尖括号/&被转义');
	assert.ok(!xml.includes('"a<&>b.txt"'));
	const doc = parseBack.parse(xml);
	const fault = doc.Envelope.Body.Fault;
	assert.equal(fault.faultcode, 'soap:Client');
	assert.equal(fault.detail.ResponseCode, 'ErrorInvalidRequest');
	assert.equal(fault.detail.MessageXml.Value['@_Name'], 'ResponseCode');
});

// ------------------------------------------- 11. CreateItem：cid → data: ------

testCase('11. CreateItem 附件拆分：内嵌图还原为 data:、未引用回落为附件', () => {
	const png = base64EncodeBytes(Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3]));
	const outgoing = [
		{ name: 'logo.png', mimeType: 'image/png', content: png, contentId: 'logo@cloud', isInline: true },
		{ name: 'orphan.png', mimeType: 'image/png', content: png, contentId: 'orphan@cloud', isInline: true },
		{ name: 'ref-by-name.png', mimeType: 'image/png', content: png, contentId: '', isInline: false },
		{ name: 'doc.pdf', mimeType: 'application/pdf', content: png, contentId: '', isInline: false }
	];
	const html = '<p>hi</p><img src="cid:logo@cloud"><img src="cid:ref-by-name.png">';

	const result = splitOutgoingAttachments(html, outgoing);
	assert.ok(result.html.includes(`src="data:image/png;base64,${png}"`), 'cid: 引用被替换成 data: URL');
	assert.ok(!result.html.includes('cid:logo@cloud'), '原 cid 引用不残留');
	assert.equal((result.html.match(/data:image\/png;base64/g) || []).length, 2, '两处内嵌图都被替换');
	assert.deepEqual(result.attachments.map((a) => a.filename), ['orphan.png', 'doc.pdf'], '未引用的内嵌图降级为普通附件');
	assert.equal(result.attachments[0].size, Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3]).length);
	// 附件 content 必须是原始 base64（att-service.saveSendAtt 直接 atob，带 data: 前缀会抛 InvalidCharacterError）
	assert.ok(result.attachments.every((a) => !a.content.startsWith('data:')), '附件为原始 base64，不是 data: URL');
	assert.deepEqual(
		Array.from(Buffer.from(result.attachments[1].content, 'base64')),
		Array.from(Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3])),
		'附件字节可被 atob 解码回去（与 Web 端上传形态一致）'
	);
	assert.ok(result.attachments.every((a) => a.type === a.mimeType && a.contentType === a.mimeType), 'type/mimeType 兼容 email-service 各分支');
});

// ------------------------------------------------ 12. MimeContent 集成 --------

testCase('12. MimeContent：{{domain}}attachments/<key> → cid 引用后重建 MIME', () => {
	const pngBytes = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 9, 9]);
	const key = 'attachments/abc123.png';
	// buildMimeForRow 的替换规则（handlers.js）：{{domain}}<key> → cid:<contentId>
	const storedHtml = `<p>图：</p><img src="{{domain}}${key}">`;
	const html = storedHtml.split(`{{domain}}${key}`).join('cid:inline-1@cloud');

	const mime = buildMimeBase64({
		from: { email: 'a@example.com', name: 'A' },
		to: [{ email: 'me@example.com' }],
		subject: 'with inline',
		dateMs: Date.UTC(2026, 9, 1, 12, 0, 0),
		html,
		inlineImages: [{ contentId: 'inline-1@cloud', filename: 'p.png', mimeType: 'image/png', data: pngBytes }]
	});

	const raw = Buffer.from(mime.replace(/\s+/g, ''), 'base64').toString('utf8');
	assert.ok(raw.includes('Content-ID: <inline-1@cloud>'), '内嵌图带 Content-ID');
	assert.ok(raw.includes('Content-Type: multipart/related'), '有内嵌图时用 multipart/related');
	assert.ok(decodeMimeBodies(raw).includes('cid:inline-1@cloud'), 'MIME 正文（内层 base64）引用 cid');
	assert.ok(!decodeMimeBodies(raw).includes('{{domain}}'), '库内占位符不出现在 MIME 中');

	const item = buildItemXml(MAIL_ROW, { changeKey: 'k', mimeContent: mime });
	const xml = envelopeFor('GetItem', responseMessage('GetItem', { body: `<m:Items>${item}</m:Items>` }));
	assertWellFormed(xml);
	const back = asArray(parseBack.parse(xml).Envelope.Body.GetItemResponse.ResponseMessages.GetItemResponseMessage.Items.Message)[0];
	assert.equal(textOf(back.MimeContent).replace(/\s+/g, ''), mime.replace(/\s+/g, ''), 'base64 往返一致（仅换行被 XML 规范化）');
});

// ------------------------------------------------------ 13. 常量与判定函数 ---

testCase('13. 常量与判定函数', () => {
	assert.equal(EWS_SYNC_PAGE, 50, '分页上限 50（Free 计划 CPU 约束）');
	assert.equal(EWS_DEFAULT_MAX_ATT_BYTES, 1024 * 1024, '附件默认上限 1MB');
	assert.equal(ewsMaxAttBytes({}), EWS_DEFAULT_MAX_ATT_BYTES);
	assert.equal(ewsMaxAttBytes({ EWS_MAX_ATT_BYTES: '5242880' }), 5242880);
	assert.equal(ewsMaxAttBytes({ EWS_MAX_ATT_BYTES: 'abc' }), EWS_DEFAULT_MAX_ATT_BYTES);
	assert.equal(ewsMaxAttBytes({ EWS_MAX_ATT_BYTES: '0' }), EWS_DEFAULT_MAX_ATT_BYTES);

	assert.equal(isInlineAttachment({ type: 1, contentId: null }), true, 'type=1 即内嵌图');
	assert.equal(isInlineAttachment({ type: 0, contentId: 'cid@x' }), true, 'contentId 非空即内嵌图（收信侧）');
	assert.equal(isInlineAttachment({ type: 0, contentId: null }), false);
	assert.equal(isInlineAttachment({ type: 0, contentId: '  ' }), false);

	assert.equal(stripCidBrackets('<abc@x>'), 'abc@x');
	assert.equal(stripCidBrackets('abc@x'), 'abc@x');
	assert.equal(toIso('2026-10-01 08:30:00'), '2026-10-01T08:30:00Z');
	assert.equal(toIso(''), '');
	assert.equal(changeKeyOf({ eff: 'a', createTime: 'b' }), 'a');

	const list = parseMailboxList(parseBack.parse('<t:ToRecipients xmlns:t="t"><t:Mailbox><t:Name>N</t:Name><t:EmailAddress>a@b.c</t:EmailAddress></t:Mailbox><t:Mailbox><t:EmailAddress>d@e.f</t:EmailAddress></t:Mailbox><t:Mailbox><t:Name>skip</t:Name></t:Mailbox></t:ToRecipients>').ToRecipients);
	assert.deepEqual(list, [{ address: 'a@b.c', name: 'N' }, { address: 'd@e.f', name: '' }], '无地址的 Mailbox 被丢弃');

	assert.deepEqual(rowRecipients({ recipient: '[{"address":"x@y.z","name":"X"}]' }), [{ address: 'x@y.z', name: 'X' }]);
	assert.deepEqual(rowRecipients({ recipient: 'not json', toEmail: 't@t.t', toName: 'T' }), [{ address: 't@t.t', name: 'T' }]);
	// cc/bcc 列是 JSON 字符串，必须解析成数组（否则会变成 "Cc: <[]>" 这种非法头）
	assert.deepEqual(parseAddressList('[{"address":"cc@x.y","name":"CC"}]'), [{ email: 'cc@x.y', name: 'CC' }]);
	assert.deepEqual(parseAddressList('[]'), []);
	assert.deepEqual(parseAddressList(null), []);

	assert.equal(escapeXml('a<b>&"\'c\u0007'), 'a&lt;b&gt;&amp;&quot;&apos;c');
});

// ---------------------------------------------------------- 14. 不支持操作 ----

testCase('14. 未实现操作：ErrorNotImplemented 风格的 Fault（含操作名）', () => {
	const xml = soapFault('ErrorNotImplemented', 'Operation FindItem is not implemented by the CloudMail EWS bridge.');
	assertWellFormed(xml);
	assert.ok(xml.includes('ErrorNotImplemented'));
	assert.ok(xml.includes('FindItem'));
});

// ---------------------------------------------------------- 15. 变更分类 -----

testCase('15. SyncFolderItems 增量分类：Create / Update / Delete / 忽略', () => {
	const wm = '2026-10-01 10:00:00';
	const oldMail = { type: 0, isDel: 0, trash: 0, createTime: '2026-09-30 08:00:00' };
	const newMail = { type: 0, isDel: 0, trash: 0, createTime: '2026-10-01 11:00:00' };

	// inbox：老邮件被 touch（已读等）→ Update；水位之后新增 → Create
	assert.equal(classifySyncRow('inbox', oldMail, wm), 'update');
	assert.equal(classifySyncRow('inbox', newMail, wm), 'create');

	// inbox：邮件进垃圾桶（update_time 被 touch）→ Delete；客户端从未见过的新邮件进垃圾桶 → 忽略
	assert.equal(classifySyncRow('inbox', { ...oldMail, trash: 1 }, wm), 'delete');
	assert.equal(classifySyncRow('inbox', { ...newMail, trash: 1 }, wm), null);

	// 收件/发件隔离由 SQL 的 type 条件保证（handlers.js 的 scopeFilter）；
	// 分类函数本身只看「这封邮件是否在当前文件夹里」
	assert.equal(classifySyncRow('inbox', { ...oldMail, type: 1 }, wm), 'delete', '发件邮件不属于收件箱文件夹');
	assert.equal(classifySyncRow('sent', { ...oldMail, type: 1 }, wm), 'update');
	assert.equal(classifySyncRow('sent', oldMail, wm), 'delete', '收件邮件不属于发件箱文件夹');

	// 垃圾桶文件夹：trash=1 可见；恢复（trash=0）→ Delete
	assert.equal(classifySyncRow('trash', { ...oldMail, trash: 1 }, wm), 'update');
	assert.equal(classifySyncRow('trash', { ...newMail, trash: 1 }, wm), 'create');
	assert.equal(classifySyncRow('trash', oldMail, wm), 'delete');

	// 附件彻底删除（isDel=1）在垃圾桶里仍可见，在正常列表里是 Delete
	assert.equal(classifySyncRow('trash', { ...oldMail, isDel: 1 }, wm), 'update');
	assert.equal(classifySyncRow('inbox', { ...oldMail, isDel: 1 }, wm), 'delete');

	// 水位为空串（空文件夹初始同步）：任何已存在行都算 Create
	assert.equal(classifySyncRow('inbox', oldMail, ''), 'create');

	assert.equal(isVisibleInFolder('inbox', oldMail), true);
	assert.equal(isVisibleInFolder('inbox', { ...oldMail, trash: 1 }), false);
	assert.equal(isDeletedRow({ trash: 1 }), true);
	assert.equal(isDeletedRow({ trash: 0, isDel: 0 }), false);
	assert.equal(isUnreadRow({ unread: 0 }), true, '项目语义：0=未读');
	assert.equal(isUnreadRow({ unread: 1 }), false);
});

// ------------------------------------------------ 16. 请求体大小护栏 ---------

testCase('16. 请求体大小护栏：Content-Length 预检 + 流式累计字节（超限中止读取）', async () => {
	const LIMIT = 1024;

	// Content-Length 解析：只有纯十进制才是「可信」
	assert.equal(parseContentLength('2048'), 2048);
	assert.equal(parseContentLength(' 2048 '), 2048, '空白被忽略');
	assert.equal(parseContentLength(null), null);
	assert.equal(parseContentLength(undefined), null);
	assert.equal(parseContentLength(''), null);
	assert.equal(parseContentLength('abc'), null);
	assert.equal(parseContentLength('-1'), null);
	assert.equal(parseContentLength('1024, 1024'), null, '多值 Content-Length 视为不可信');

	assert.equal(precheckContentLength(String(LIMIT + 1), LIMIT).state, 'too-large', '超过上限 → 直接 413（不读体）');
	assert.equal(precheckContentLength(String(LIMIT), LIMIT).state, 'ok', '恰好等于上限：放行');
	assert.equal(precheckContentLength(null, LIMIT).state, 'unknown', '缺失 Content-Length → 必须流式计数');
	assert.equal(precheckContentLength('abc', LIMIT).state, 'unknown', '不可信 Content-Length → 同样走流式计数');

	// 无 Content-Length（chunked）：逐块累计字节，超限立即中止（第 3 个 chunk 不会被读取）
	let chunksRead = 0;
	const oversize = new ReadableStream({
		pull(controller) {
			chunksRead++;
			if (chunksRead > 3) {
				controller.close();
				return;
			}
			controller.enqueue(new Uint8Array(700).fill(0x41));
		}
	});
	const tooBig = await readLimitedText(oversize, LIMIT);
	assert.equal(tooBig.tooLarge, true);
	assert.equal(tooBig.bytes, 1400, '累计 700 + 700 即超限');
	assert.equal(chunksRead, 2, '超限后不再读下一个 chunk（内存占用有界）');

	// 未超限：完整读回（含多字节字符按字节计数）
	const ok = await readLimitedText(new Blob(['<soap:Envelope/>']).stream(), LIMIT);
	assert.equal(ok.text, '<soap:Envelope/>');
	const wide = await readLimitedText(new Blob(['中'.repeat(400)]).stream(), LIMIT);
	assert.equal(wide.tooLarge, true, '按字节数（400 个 3 字节字符 = 1200 > 1024）而非字符数判定');
	assert.equal(wide.bytes, 1200);
	assert.deepEqual(await readLimitedText(null, LIMIT), { text: '' }, '无 body 视为空文本');
});

// ------------------------------------------- 17. dispatch 原型链操作名 ------

testCase('17. dispatch：原型链操作名（toString）返回标准 Fault，而非非 XML 文本', async () => {
	ensureNodeResolveHook();

	const parsed = parseSoapRequest('<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><toString/></soap:Body></soap:Envelope>');
	assert.equal(parsed.error, undefined, '请求本身是合法 SOAP');
	assert.equal(parsed.operation, 'toString', 'Body 首个元素名即操作名（原样保留，不折大小写）');

	const { dispatch, EwsFault } = await import('../src/ews/handlers.js');

	// 修复前：HANDLERS['toString'] 命中 Object.prototype.toString → 返回 '[object Object]'（非 XML）
	await assert.rejects(() => dispatch({}, parsed, {}), (error) => {
		assert.ok(error instanceof EwsFault, '必须是 EwsFault（router 会转成 SOAP Fault）');
		assert.equal(error.responseCode, 'ErrorNotImplemented');
		const xml = soapFault(error.responseCode, error.message);
		assertWellFormed(xml);
		assert.ok(xml.includes('<faultstring'), 'faultstring 存在');
		assert.ok(xml.includes('ErrorNotImplemented'), 'Fault 带 ResponseCode');
		return true;
	});

	// 正常操作名仍然命中真实 handler（GetFolder 缺 FolderIds → handler 内校验抛 Fault）
	await assert.rejects(() => dispatch({}, { operation: 'GetFolder', payload: {} }, { userId: 1 }), (error) => {
		assert.ok(error instanceof EwsFault);
		assert.equal(error.responseCode, 'ErrorInvalidRequest', '真实 handler 被调用（不是原型链成员）');
		return true;
	});
});

// --------------------------------- 18. MimeContent / 附件字节护栏（纯函数） ---

testCase('18. MimeContent 护栏：Id clamp ≤20 + 本次响应附件字节账本', () => {
	assert.equal(EWS_MAX_MIME_ITEM_IDS, 20);

	const ids = Array.from({ length: 25 }, (_, index) => index + 1);
	const set = mimeContentIdSet(ids);
	assert.equal(set.size, 20, '单次只重建 20 封 MimeContent');
	assert.ok(set.has(20));
	assert.equal(set.has(21), false, '第 21 个 Id 起只回元数据');
	assert.equal(mimeContentIdSet(ids, 3).size, 3, '显式 limit 生效');
	assert.equal(mimeContentIdSet([0, -1, 'x', Number.NaN, 5]).size, 1, '非法 Id 不入白名单');
	assert.equal(mimeContentIdSet(ids, 0).size, 20, '非法 limit 回落到默认值');

	const LIMIT = 2 * 1024 * 1024;
	const budget = { total: 0, limit: LIMIT };
	assert.equal(attBudgetAllows(budget, 1024 * 1024), true, '未到上限：放行');
	budget.total += 1024 * 1024;
	assert.equal(attBudgetAllows(budget, 1024 * 1024), true, '恰好用满：放行');
	budget.total += 1024 * 1024;
	assert.equal(attBudgetAllows(budget, 1), false, '累计到上限后剩余附件走跳过路径');
	assert.equal(attBudgetAllows(budget, 0), true, 'size 未知（<=0）先放行，下载后按实际字节累加');
	assert.equal(attBudgetAllows(budget, -5), true, '负数同样视为未知大小');
	assert.equal(attBudgetAllows({ total: 0, limit: 0 }, 1024 ** 3), true, 'limit 非法 → 不设限');
});

// ------------------------------- 19. 物理删除 tombstone → Delete 事件 -------

testCase('19. tombstone：文件夹映射 + 同轮去重 + Delete 事件 XML 良构', () => {
	assert.equal(tombstoneFolderToken({ type: 0, trash: 0 }), 'inbox');
	assert.equal(tombstoneFolderToken({ type: 1, trash: 0 }), 'sentitems');
	assert.equal(tombstoneFolderToken({ type: 0, trash: 1 }), 'deleteditems', '进过垃圾桶的 → 垃圾桶文件夹');
	assert.equal(tombstoneFolderToken({ type: 1, trash: 1 }), 'deleteditems');

	const rows = [
		{ email_id: 11, type: 0, trash: 0 },
		{ email_id: 12, type: 1, trash: 0 },
		{ email_id: 13, type: 0, trash: 1 },
		{ email_id: 11, type: 0, trash: 0 },
		{ email_id: 14, type: 0, trash: 0 }
	];
	assert.deepEqual(selectTombstoneDeletes('inbox', rows, new Set()), [11, 14], '只产出本文件夹 + tombstone 自身去重');
	assert.deepEqual(selectTombstoneDeletes('sentitems', rows, new Set()), [12]);
	assert.deepEqual(selectTombstoneDeletes('deleteditems', rows, new Set()), [13]);
	assert.deepEqual(selectTombstoneDeletes('inbox', rows, new Set([14, 11])), [], '与同轮已产出的 ItemId 去重');
	assert.deepEqual(selectTombstoneDeletes('inbox', [{ email_id: 0 }, { email_id: 'x' }], new Set()), [], '非法 Id 丢弃');
	assert.deepEqual(selectTombstoneDeletes('inbox', null, null), [], '无 tombstone / 无已知集合也不炸');

	// handlers.js 的 Delete 事件产出形态（同轮 Delete 与 tombstone Delete 同一模板）
	const xml = envelopeFor('SyncFolderItems', responseMessage('SyncFolderItems', {
		body: `<m:SyncState>${escapeXml(encodeSyncState(emptySyncState()))}</m:SyncState>` +
			'<m:IncludesLastItemInRange>true</m:IncludesLastItemInRange>' +
			'<m:Changes><t:Delete><t:ItemId Id="11"/></t:Delete><t:Delete><t:ItemId Id="14"/></t:Delete></m:Changes>'
	}));
	assertWellFormed(xml);
	const back = parseBack.parse(xml).Envelope.Body.SyncFolderItemsResponse.ResponseMessages.SyncFolderItemsResponseMessage;
	assert.deepEqual(asArray(back.Changes.Delete).map((node) => node.ItemId['@_Id']), ['11', '14'], 'Delete 事件带 ItemId');
});

// --------------------------- 20. IsInline 非 image/video 附件降级 ----------

testCase('20. CreateItem：IsInline 的非 image/video 附件强制按普通附件发出', () => {
	const content = base64EncodeBytes(Uint8Array.from([1, 2, 3, 4]));
	const outgoing = [
		{ name: 'invite.ics', mimeType: 'text/calendar', content, contentId: 'cal@cloud', isInline: true },
		{ name: 'logo.png', mimeType: 'image/png', content, contentId: 'logo@cloud', isInline: true },
		{ name: 'clip.mp4', mimeType: 'video/mp4', content, contentId: 'clip@cloud', isInline: true }
	];
	const html = '<img src="cid:logo@cloud"><video src="cid:clip@cloud"><span>cid:cal@cloud</span>';
	const result = splitOutgoingAttachments(html, outgoing);

	assert.ok(result.html.includes('cid:cal@cloud'), '非 image/video 的 IsInline 项不做 cid: → data: 替换');
	assert.ok(!result.html.includes('data:text/calendar'), '不产生 data:text/calendar');
	assert.deepEqual(result.attachments.map((a) => a.filename), ['invite.ics'], '降级为普通附件（附件本体不丢）');
	assert.equal((result.html.match(/data:image\/png/g) || []).length, 1, '图片内联保持原行为');
	assert.equal((result.html.match(/data:video\/mp4/g) || []).length, 1, 'video 内联为 IsInline 的合法类型');
});

// ---------------------------------------- 21. 认证护栏常量（TTL / 延迟） ----

testCase('21. 常量：认证缓存 TTL 5 分钟 + 凭据错误延迟 1 秒', () => {
	assert.equal(EWS_AUTH_CACHE_TTL, 300, '认证缓存 5 分钟（原 15 分钟）');
	assert.equal(EWS_AUTH_FAIL_DELAY_MS, 1000, '与 login-service 失败延迟一致');
});

// --------------------------- 22. router 级：请求体超限在读体前 413 ---------

testCase('22. router 级：Content-Length 超限的 POST 在读体前 413（chunked 超限则流式中止）', async () => {
	ensureNodeResolveHook();
	const { default: ewsApp } = await import('../src/ews/router.js');

	const email = 'tb-user@example.com';
	const password = 'secret-password';
	const jwtSecret = 'unit-test-jwt-secret';
	// 认证缓存键 = ews-auth:sha256(jwt_secret:email:password)（auth.js 加盐后的键）
	const cacheKey = 'ews-auth:' + createHash('sha256').update(`${jwtSecret}:${email}:${password}`).digest('hex');
	const store = new Map([[cacheKey, JSON.stringify({ userId: 7, email, status: 0, isDel: 0 })]]);
	const env = {
		jwt_secret: jwtSecret,
		kv: {
			get: async (key) => (store.has(key) ? JSON.parse(store.get(key)) : null),
			put: async () => {},
			delete: async () => {}
		}
	};
	const auth = 'Basic ' + Buffer.from(`${email}:${password}`).toString('base64');

	// ① Content-Length 超限：直接 413，且 body 从未被读取
	let pulls = 0;
	const body = new ReadableStream({
		pull(controller) {
			pulls++;
			controller.enqueue(new TextEncoder().encode('<soap:Envelope/>'));
		}
	});
	const res = await ewsApp.fetch(new Request('https://mail.example.com/EWS/Exchange.asmx', {
		method: 'POST',
		headers: {
			Authorization: auth,
			'Content-Length': String(41 * 1024 * 1024),
			'Content-Type': 'text/xml; charset=utf-8'
		},
		body,
		duplex: 'half'
	}), env, {});
	assert.equal(res.status, 413, '超过 40MB → HTTP 413');
	// 注意：undici 对 duplex:'half' 的流式 body 会预取 1 个 chunk（与 router 无关），
	// 这里断言「router 没有把 body 读完」；faultstring 里出现 too large 也证明走的是预检分支而非读体分支
	assert.ok(pulls <= 1, `router 不从请求体读数据（pulls=${pulls}）`);
	assert.equal(res.headers.get('content-type'), 'text/xml; charset=utf-8');
	const fault = await res.text();
	assertWellFormed(fault);
	assert.ok(fault.includes('ErrorInvalidRequest'), '413 body 是标准 SOAP Fault');
	assert.ok(fault.includes('too large'), '按 Content-Length 预检拒绝（不是读体失败分支）');

	// ② 无 Content-Length（chunked）且实际超限：流式累计字节，超限即中止并 413
	const chunk = new Uint8Array(1024 * 1024);
	let sent = 0;
	let cancelled = false;
	const chunked = new ReadableStream({
		pull(controller) {
			// 声明 100MB 可用，实际读方应在 40MB 处停止（内存有界）
			if (sent >= 100) {
				controller.close();
				return;
			}
			sent++;
			controller.enqueue(chunk);
		},
		cancel() {
			cancelled = true;
		}
	});
	const res2 = await ewsApp.fetch(new Request('https://mail.example.com/EWS/Exchange.asmx', {
		method: 'POST',
		headers: { Authorization: auth, 'Content-Type': 'text/xml; charset=utf-8' },
		body: chunked,
		duplex: 'half'
	}), env, {});
	assert.equal(res2.headers.get('content-length'), null, '前置条件：本请求没有 Content-Length');
	assert.equal(res2.status, 413, '流式累计超限 → 413');
	assert.equal(cancelled, true, '超限后主动取消读取（不再拉剩余数据）');
	assert.ok(sent <= 42, `最多多读一个 chunk（实际读取 ${sent}MB / 共 100MB）`);

	// ③ 正常大小的请求体仍走原路径（缺 Authorization 的握手探测 → 401，不读体不报 413）
	const res3 = await ewsApp.fetch(new Request('https://mail.example.com/EWS/Exchange.asmx', {
		method: 'POST',
		headers: { 'Content-Type': 'text/xml; charset=utf-8' },
		body: '<soap:Envelope/>'
	}), env, {});
	assert.equal(res3.status, 401);
});

// ------------------------------- 23. 认证：加盐缓存键 + 失败延迟 1 秒 ---------

testCase('23. 认证：缓存键按 jwt_secret 加盐（旧键不再命中）+ 凭据错误延迟 1 秒', async () => {
	ensureNodeResolveHook();
	const { authenticate } = await import('../src/ews/auth.js');

	const email = 'tb-user@example.com';
	const password = 'secret-password';
	const jwtSecret = 'unit-test-jwt-secret';
	const entry = JSON.stringify({ userId: 7, email, status: 0, isDel: 0 });
	const saltedKey = 'ews-auth:' + createHash('sha256').update(`${jwtSecret}:${email}:${password}`).digest('hex');
	const legacyKey = 'ews-auth:' + createHash('sha256').update(`${email.toLowerCase()}:${password}`).digest('hex');

	// 最小 D1 桩：drizzle 的 d1 driver 走 prepare().bind().raw()/.get()
	function stubD1() {
		const stmt = {
			bind() {
				return stmt;
			},
			async get() {
				return null;
			},
			async all() {
				return { results: [] };
			},
			async run() {
				return {};
			},
			async raw() {
				return [];
			}
		};
		return { prepare: () => stmt, batch: async () => [] };
	}

	function makeContext(store, salt) {
		return {
			req: {
				header: (name) => (String(name).toLowerCase() === 'authorization'
					? 'Basic ' + Buffer.from(`${email}:${password}`).toString('base64')
					: undefined)
			},
			env: {
				jwt_secret: salt,
				kv: {
					get: async (key) => (store.has(key) ? JSON.parse(store.get(key)) : null),
					put: async () => {},
					delete: async () => {}
				},
				db: stubD1()
			},
			set() {},
			get() {}
		};
	}

	// ① 加盐键命中：认证成功（不查库）
	const okUser = await authenticate(makeContext(new Map([[saltedKey, entry]]), jwtSecret));
	assert.equal(okUser.userId, 7, '按 sha256(jwt_secret:email:password) 命中缓存');

	// ② 只有旧（未加盐）键有缓存：不再命中 → 凭据错误 → 延迟约 1 秒
	const t0 = Date.now();
	const bad = await authenticate(makeContext(new Map([[legacyKey, entry]]), jwtSecret));
	const elapsed = Date.now() - t0;
	assert.equal(bad, null, '旧的未加盐缓存键不再被使用（加盐后旧键失效）');
	assert.ok(elapsed >= 950, `凭据错误响应延迟约 1 秒（实测 ${elapsed}ms）`);

	// ③ jwt_secret 缺失：退化为不加盐旧键（仅告警，保证不因配置缺失而全线 401）
	const fallback = await authenticate(makeContext(new Map([[legacyKey, entry]]), undefined));
	assert.equal(fallback.userId, 7, 'jwt_secret 未配置时退化回旧键');
});

// ------------- 24. SyncFolderItems：tombstone 读侧产出 Delete（含容错） ------

testCase('24. SyncFolderItems：物理删除 tombstone → Delete 事件（水位/文件夹匹配/表缺失容错）', async () => {
	ensureNodeResolveHook();
	const { default: ewsApp } = await import('../src/ews/router.js');

	const email = 'tb-user@example.com';
	const password = 'secret-password';
	const jwtSecret = 'unit-test-jwt-secret';
	const cacheKey = 'ews-auth:' + createHash('sha256').update(`${jwtSecret}:${email}:${password}`).digest('hex');
	const kvStore = new Map([[cacheKey, JSON.stringify({ userId: 7, email, status: 0, isDel: 0 })]]);

	// D1 桩：邮件查询（drizzle 走 .bind().raw()）返回空集；ews_tombstone 查询返回给定行；其余（ews_sync_state）忽略
	function stubD1(tombstoneRows, { missingTable = false } = {}) {
		const queries = [];
		const stmt = {
			sql: '',
			params: [],
			bind(...params) {
				stmt.params = params;
				return stmt;
			},
			async get() {
				return null;
			},
			async all() {
				if (/ews_tombstone/.test(stmt.sql)) return { results: tombstoneRows };
				return { results: [] };
			},
			async run() {
				return {};
			},
			async raw() {
				return [];
			}
		};
		return {
			queries,
			prepare(sql) {
				if (missingTable && /ews_tombstone/.test(sql)) throw new Error('no such table: ews_tombstone');
				queries.push(sql);
				stmt.sql = sql;
				stmt.params = [];
				return stmt;
			},
			batch: async () => []
		};
	}

	const SYNC_STATE = encodeSyncState({ v: 1, wm: '2026-10-01 10:00:00', wid: 0, cur: null });
	const syncRequest = (folder) => `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:SyncFolderItems>
      <m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape>
      <m:SyncFolderId><t:DistinguishedFolderId Id="${folder}" /></m:SyncFolderId>
      <m:SyncState>${SYNC_STATE}</m:SyncState>
      <m:MaxChangesReturned>512</m:MaxChangesReturned>
    </m:SyncFolderItems>
  </soap:Body>
</soap:Envelope>`;

	async function sync(folder, tombstoneRows, options) {
		const db = stubD1(tombstoneRows, options);
		const env = {
			jwt_secret: jwtSecret,
			kv: { get: async (key) => (kvStore.has(key) ? JSON.parse(kvStore.get(key)) : null), put: async () => {}, delete: async () => {} },
			db
		};
		const res = await ewsApp.fetch(new Request('https://mail.example.com/EWS/Exchange.asmx', {
			method: 'POST',
			headers: {
				Authorization: 'Basic ' + Buffer.from(`${email}:${password}`).toString('base64'),
				'Content-Type': 'text/xml; charset=utf-8'
			},
			body: syncRequest(folder)
		}), env, {});
		const xml = await res.text();
		// 成功响应是裸的 <m:SyncFolderItemsResponse>（router 只对 Fault 走 soapEnvelope），这里只校验良构
		assert.equal(XMLValidator.validate(xml), true, 'SyncFolderItems 响应必须良构');
		assert.ok(!xml.includes('<soap:Fault>'), '不应出现 Fault');
		return { xml, queries: db.queries };
	}

	// 删除前类型：11=收件（inbox）、12=发件（sentitems）、13=垃圾桶里的收件、14=已进垃圾桶的发件
	const tombstones = [
		{ email_id: 11, type: 0, trash: 0 },
		{ email_id: 12, type: 1, trash: 0 },
		{ email_id: 13, type: 0, trash: 1 },
		{ email_id: 14, type: 1, trash: 1 }
	];

	const inbox = await sync('inbox', tombstones);
	assert.ok(inbox.xml.includes('<t:Delete><t:ItemId Id="11"/></t:Delete>'), 'inbox 的物理删除 → Delete 11');
	assert.ok(!inbox.xml.includes('Id="12"'), '发件邮件的 Delete 不进 inbox');
	assert.ok(!inbox.xml.includes('Id="13"') && !inbox.xml.includes('Id="14"'), '垃圾桶里的 Delete 不进 inbox');
	// tombstone 查询的绑定参数：user_id + 本轮水位（del_time > wm）
	const tombstoneQuery = inbox.queries.find((sql) => /ews_tombstone/.test(sql));
	assert.ok(tombstoneQuery, '确实查询了 ews_tombstone');
	assert.ok(/del_time > \?/.test(tombstoneQuery), '按 del_time > 水位过滤');
	assert.ok(inbox.queries.some((sql) => /ews_sync_state/.test(sql)), '同步水位仍会落库');

	const sent = await sync('sentitems', tombstones);
	assert.ok(sent.xml.includes('<t:Delete><t:ItemId Id="12"/></t:Delete>'), 'sentitems 的物理删除 → Delete 12');
	assert.ok(!sent.xml.includes('Id="11"'), '收件邮件的 Delete 不进 sentitems');

	const trash = await sync('deleteditems', tombstones);
	assert.ok(trash.xml.includes('<t:Delete><t:ItemId Id="13"/></t:Delete>'), '垃圾桶文件夹按 trash=1 匹配');
	assert.ok(trash.xml.includes('<t:Delete><t:ItemId Id="14"/></t:Delete>'));

	// ews_tombstone 未建（未迁移）：容错，不产出 Delete、也不 Fault
	const missing = await sync('inbox', tombstones, { missingTable: true });
	assert.ok(!missing.xml.includes('<t:Delete>'), '表缺失时静默跳过（不影响其余同步）');
	assert.ok(missing.xml.includes('SyncFolderItemsResponse'), '仍是正常的 SyncFolderItems 响应');
});

// ------------------------------------------------------------------ runner ---

let failed = 0;
for (const { name, fn } of cases) {
	try {
		await fn();
		console.log(`PASS ${name}`);
	} catch (error) {
		failed++;
		console.error(`FAIL ${name}`);
		console.error(`     ${error && error.message}`);
	}
}
console.log(failed === 0 ? `\nALL ${cases.length} CASES PASSED` : `\n${failed}/${cases.length} CASES FAILED`);
process.exitCode = failed === 0 ? 0 : 1;
