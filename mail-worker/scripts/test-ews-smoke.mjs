/**
 * EWS 桥接层冒烟测试 —— 纯 node，无需 wrangler/Cloudflare 运行时：
 *
 *   cd mail-worker && node --no-warnings scripts/test-ews-smoke.mjs
 *
 * 覆盖 TB 真实会发出的 SOAP 请求解析、响应模板结构与转义（含 XML 良构校验）、
 * SyncState 编解码、base64 工具、CreateItem 的 cid→data: 内嵌图还原、MimeContent 集成。
 *
 * 只依赖 fast-xml-parser（package.json dependencies）：
 *   - xml.js / protocol.js / const.js 无项目依赖，可直接 file URL import；
 *   - handlers.js / router.js 依赖 hono/drizzle 等，本脚本不 import（由 wrangler 打包验证）。
 */

import assert from 'node:assert/strict';
import { XMLParser, XMLValidator } from 'fast-xml-parser';

import {
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
	parseAddressList,
	parseMailboxList,
	rowRecipients,
	splitOutgoingAttachments,
	stripCidBrackets,
	toIso
} from '../src/ews/protocol.js';
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

// ------------------------------------------------------------------ runner ---

let failed = 0;
for (const { name, fn } of cases) {
	try {
		fn();
		console.log(`PASS ${name}`);
	} catch (error) {
		failed++;
		console.error(`FAIL ${name}`);
		console.error(`     ${error && error.message}`);
	}
}
console.log(failed === 0 ? `\nALL ${cases.length} CASES PASSED` : `\n${failed}/${cases.length} CASES FAILED`);
process.exitCode = failed === 0 ? 0 : 1;
