/**
 * EWS 桥接层冒烟测试 —— 纯 node，无需 wrangler/Cloudflare 运行时：
 *
 *   cd mail-worker && node --no-warnings scripts/test-ews-smoke.mjs
 *
 * 覆盖 TB 真实会发出的 SOAP 请求解析、响应模板结构与转义（含 XML 良构校验）、
 * 所有成功响应必须是完整 SOAP 信封（<?xml ?> + soap:Envelope/soap:Body，Fault 不双重包裹）、
 * SyncState 编解码、base64 工具、CreateItem 的 cid→data: 内嵌图还原、MimeContent 集成、
 * 请求体大小护栏、MimeContent/附件字节护栏、物理删除 tombstone 的 Delete 事件映射、
 * 可见域（Distinguished 文件夹按用户聚合；账号文件夹 acct-<id> 只含该账号的可见收件，
 * 含归属校验与非法 token 拒绝）、
 * 超限内嵌图的正文可见占位（跳过 part + 阈值动态显示，GetAttachment 超限文案指向网页版）、
 * 防白屏降级阶梯（多图/普通附件跳过进统一占位清单、纯附件无正文时清单即正文（html/text 皆空也始终输出）、HTML 截断、解码后 ≤1.4×预算、构建异常 → 极简 MIME 兜底）、
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
import { DatabaseSync } from 'node:sqlite';
import { XMLParser, XMLValidator } from 'fast-xml-parser';

import {
	EWS_AUTH_CACHE_TTL,
	EWS_AUTH_FAIL_DELAY_MS,
	EWS_HTML_MAX_BYTES,
	EWS_MAX_MIME_ITEM_IDS,
	EWS_MIME_SAFE_TOTAL,
	EWS_SEND_MAX_BYTES,
	EWS_SYNC_PAGE,
	accountFolderId,
	ewsFolderDef,
	ewsMaxAttBytes,
	EWS_DEFAULT_MAX_ATT_BYTES,
	ewsMaxTotalAttBytes,
	ewsMimeSafeTotal,
	ewsSendMaxBytes,
	parseAccountFolder
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
	createItemItemsXml,
	decodeSyncState,
	emptySyncState,
	encodeSyncState,
	humanFileSize,
	isDeletedRow,
	isInlineAttachment,
	isUnreadRow,
	isVisibleInFolder,
	mimeContentIdSet,
	oversizeInlinePlaceholderHtml,
	parseAddressList,
	parseMailboxList,
	parseMimeFrom,
	replaceInlineImagesWithPlaceholder,
	resolveNameMatches,
	rowRecipients,
	selectTombstoneDeletes,
	skippedAttachmentsHtml,
	skippedAttachmentsText,
	splitOutgoingAttachments,
	stripCidBrackets,
	toIso,
	tombstoneFolderToken,
	truncateUtf8Bytes
} from '../src/ews/protocol.js';
import { parseContentLength, precheckContentLength, readLimitedText } from '../src/ews/request-guard.js';
import { base64Encode, buildMimeBase64 } from '../src/ews/mime-build.js';
import BizError from '../src/error/biz-error.js';

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

/** 单一信封：成功与 Fault 响应都只允许一层 soap:Envelope（防双重包裹） */
function assertSingleEnvelope(xml) {
	assert.equal((xml.match(/<soap:Envelope/g) || []).length, 1, '仅一层 soap:Envelope');
	assert.equal((xml.match(/<\/soap:Envelope>/g) || []).length, 1, '仅一个 </soap:Envelope>');
	assert.equal((xml.match(/<\?xml/g) || []).length, 1, '仅一个 <?xml ?> 声明（无嵌套信封）');
	assert.ok(xml.startsWith('<?xml version="1.0" encoding="utf-8"?><soap:Envelope'), 'XML 声明后紧跟信封');
}

/**
 * 成功响应必须是完整 SOAP 信封：SOAP 客户端（TB 145）要求 200 响应带 Envelope，
 * 裸的 <m:XxxResponse> 会导致解析失败 → TB 统一报「身份验证出错」。
 */
function assertSoapEnvelope(xml, operation) {
	assertSingleEnvelope(xml);
	assert.ok(xml.endsWith('</soap:Envelope>'), '信封在末尾闭合 </soap:Envelope>');
	assert.ok(xml.includes('<soap:Body>') && xml.includes('</soap:Body>'), '含 soap:Body');
	assert.ok(xml.includes('<soap:Header><t:ServerVersionInfo'), '含 ServerVersionInfo 头');
	// 应答 Exchange 2013 SP1，且 Version 必须是 TB 认识的标准字面量（交易所 rust/ews ServerVersion）；
	// V2_14 之类的版本号是未知值，V2_7（Exchange 2010 SP1）会让客户端降级/拒收
	assert.ok(
		xml.includes('<t:ServerVersionInfo MajorVersion="15" MinorVersion="0" MajorBuildNumber="847" MinorBuildNumber="0" Version="Exchange2013_SP1" />'),
		'ServerVersionInfo Version = Exchange2013_SP1（TB 标准字面量）'
	);
	assert.ok(!xml.includes('Version="V2_'), '不得输出 V2_xx 版本号（TB 只认标准字面量）');
	if (operation) assert.ok(xml.includes(`<m:${operation}Response`), `信封内保留 m:${operation}Response`);
}

/**
 * email-service 测试桩（data: URL 模块，全局唯一实例）：生产 handlers.js 的 `../service/email-service`
 * 经 resolve hook 重定向到这里 —— send 被替换为记录「收到的账号参数」并返回固定入库结果，
 * 其余方法（delete/receive 等）经 Object.create(real) 原型委托给真实 email-service，
 * 既有 router 级用例（DeleteItem 等）行为不变。真实模块用绝对 file URL import，
 * 不会命中重定向规则（规则只匹配无扩展名的 '../service/email-service'）。
 */
const REAL_EMAIL_SERVICE_URL = new URL('../src/service/email-service.js', import.meta.url).href;
const EMAIL_SERVICE_STUB_URL = 'data:text/javascript,' + encodeURIComponent(
	`import real from ${JSON.stringify(REAL_EMAIL_SERVICE_URL)};
export const sendCalls = [];
export function resetSendCalls() { sendCalls.length = 0; }
const stub = Object.create(real);
stub.send = async (c, params, userId) => {
	sendCalls.push({ params, userId });
	return [{ emailId: 4242, createTime: '2026-10-01 10:00:00' }];
};
export default stub;`
);

/**
 * handlers.js / router.js 的传递依赖里大量 import 省略 .js 扩展名（wrangler 打包能解析、node 不能），
 * 注册一次 resolve hook 补后缀，让 node 也能 import 真实模块做断言。
 * 同一 hook 把 email-service 换成测试桩（必须在 handlers.js 首次 import 前注册）。
 */
let resolveHookReady = false;
function ensureNodeResolveHook() {
	if (resolveHookReady) return;
	const hook = `export async function resolve(specifier, context, next) {
  if (specifier.startsWith('node:') || specifier.startsWith('file:') || specifier.startsWith('data:')) return next(specifier, context);
  if (specifier === '../service/email-service') return { url: ${JSON.stringify(EMAIL_SERVICE_STUB_URL)}, shortCircuit: true };
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
	// 未实现的标准 Distinguished 名 → 空文件夹兜底（不再 ErrorFolderNotFound：TB 见到混合失败会中止收取）
	assert.equal(ewsFolderDef('junkemail').kind, 'empty');
	assert.equal(ewsFolderDef('junkemail').token, 'junkemail', 'token 原样回传请求的 Id');
	assert.equal(ewsFolderDef('junkemail').displayName, 'junkemail', 'DisplayName 原样');
	assert.equal(ewsFolderDef('archive').kind, 'empty');
	assert.equal(ewsFolderDef('calendar').kind, 'empty');
	assert.equal(ewsFolderDef('JunkEmail').token, 'JunkEmail', '大小写原样回传给客户端');
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

	const xml = operationResponse('GetFolder',
		responseMessage('GetFolder', { body: `<m:Folders>${folders.join('')}</m:Folders>` }));
	assertWellFormed(xml);
	assertSoapEnvelope(xml, 'GetFolder');

	// 命名空间：信封 + 操作元素都声明（TB 依赖 messages/types 两个 ns）
	assert.ok(xml.includes('xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'), 'soap ns');
	assert.ok(xml.includes('xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"'), 'types ns');
	assert.ok(xml.includes('xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"'), 'messages ns');
	assert.ok(xml.includes('<t:ServerVersionInfo'), 'ServerVersionInfo header');
	assert.ok(
		xml.includes('<m:GetFolderResponse xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">'),
		'操作根元素保留原 m:/t: xmlns 声明（包信封后这些前缀仍可达）'
	);

	// 结构（重新解析后按元素取值）
	const doc = parseBack.parse(xml);
	const message = doc.Envelope.Body.GetFolderResponse.ResponseMessages.GetFolderResponseMessage;
	assert.equal(message['@_ResponseClass'], 'Success');
	assert.equal(message.ResponseCode, 'NoError');

	const foldersOut = asArray(message.Folders.Folder);
	assert.equal(foldersOut.length, 4);
	const [inbox, deleted, root, weird] = foldersOut;
	// TB 三件套（folder_listener.rs 硬校验）：FolderId@Id + ParentFolderId@Id + DisplayName，缺一即整树同步失败
	assert.equal(inbox.FolderId['@_Id'], 'inbox');
	assert.equal(inbox.ParentFolderId['@_Id'], 'root', 'Distinguished 邮件文件夹的父 = root');
	assert.equal(inbox.FolderClass, 'IPF.Note', '文件夹类是 IPF.Note（IPM.Note 是条目类，TB 会丢弃整树）');
	assert.ok(!xml.includes('<t:FolderClass>IPM.Note</t:FolderClass>'), 'FolderClass 不再出现条目类 IPM.Note');
	assert.equal(inbox.DisplayName, 'Inbox');
	assert.ok(xml.includes('<t:ParentFolderId Id="root" ChangeKey="1"/>'), 'ParentFolderId@Id=root 落在 XML 上');
	assert.equal(inbox.TotalCount, '0');
	assert.equal(inbox.UnreadCount, '0');
	assert.equal(inbox.ChildFolderCount, '0');
	assert.equal(deleted.FolderId['@_Id'], 'deleteditems');
	assert.equal(deleted.ParentFolderId['@_Id'], 'root', 'deleteditems 的父 = root');
	assert.equal(weird.ParentFolderId['@_Id'], 'root', '任意非 root 文件夹都有 ParentFolderId');
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
	const xml = operationResponse('GetItem', responseMessage('GetItem', { body: `<m:Items>${item}</m:Items>` }));
	assertWellFormed(xml);
	assertSoapEnvelope(xml, 'GetItem');

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
	const xml = operationResponse('GetItem', responseMessage('GetItem', { body: `<m:Items>${item}</m:Items>` }));
	assertWellFormed(xml);
	assertSoapEnvelope(xml, 'GetItem');

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
	assertSingleEnvelope(xml);
	assert.ok(xml.includes('<faultcode>soap:Client</faultcode>'));
	assert.ok(xml.includes('&lt;&amp;&gt;'), 'faultstring 中的尖括号/&被转义');
	assert.ok(!xml.includes('"a<&>b.txt"'));
	const bodyXml = (xml.match(/<soap:Body>(.*)<\/soap:Body>/) || [])[1] || '';
	assert.ok(bodyXml.startsWith('<soap:Fault>'), 'Fault 是 soap:Body 的直接子元素（未再包一层信封）');
	assert.ok(!bodyXml.includes('<?xml'), '信封内部不再出现 XML 声明');
	const doc = parseBack.parse(xml);
	const fault = doc.Envelope.Body.Fault;
	assert.equal(fault.faultcode, 'soap:Client');
	assert.equal(fault.detail.ResponseCode, 'ErrorInvalidRequest');
	assert.equal(fault.detail.MessageXml.Value['@_Name'], 'ResponseCode');
	assert.ok(!('Envelope' in fault), 'Fault 内没有嵌套 Envelope（无双重包裹）');
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
	const xml = operationResponse('GetItem', responseMessage('GetItem', { body: `<m:Items>${item}</m:Items>` }));
	assertWellFormed(xml);
	assertSoapEnvelope(xml, 'GetItem');
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

	// 账号文件夹 token（FolderId = acct-<accountId>）：只认纯数字正整数，注入串一律 null
	assert.equal(parseAccountFolder('acct-3'), 3);
	assert.equal(parseAccountFolder('ACCT-3'), 3, '大小写不敏感');
	assert.equal(parseAccountFolder(' acct-12 '), 12);
	assert.equal(parseAccountFolder('acct-abc'), null);
	assert.equal(parseAccountFolder('acct-'), null);
	assert.equal(parseAccountFolder('acct-1abc'), null);
	assert.equal(parseAccountFolder('acct-1 OR 1=1'), null, '带尾巴的注入串拒绝');
	assert.equal(parseAccountFolder('acct--1'), null);
	assert.equal(parseAccountFolder('acct-0'), null, 'accountId 必须 > 0');
	assert.equal(parseAccountFolder('acct-99999999999999999999'), null, '超出安全整数范围拒绝');
	assert.equal(parseAccountFolder('inbox'), null);
	assert.equal(parseAccountFolder(null), null);
	assert.equal(accountFolderId(3), 'acct-3');
	assert.equal(accountFolderId('7'), 'acct-7');

	// ewsFolderDef：Distinguished（含别名）优先，其次账号文件夹（DisplayName 由 handlers 用账号邮箱填充）
	assert.equal(ewsFolderDef('inbox').kind, 'inbox');
	assert.equal(ewsFolderDef('SENTITEMS').kind, 'sent');
	assert.equal(ewsFolderDef('acct-3').kind, 'account');
	assert.equal(ewsFolderDef('acct-3').accountId, 3);
	assert.equal(ewsFolderDef('acct-3').token, 'acct-3');
	assert.equal(ewsFolderDef('acct-3').displayName, '');
	assert.equal(ewsFolderDef('acct-abc'), null);
	assert.equal(ewsFolderDef('nope'), null);
	// 未实现的 Distinguished 名：kind='empty' 空文件夹兜底（计数恒 0，token/DisplayName 原样）
	assert.equal(ewsFolderDef('junkemail').kind, 'empty');
	assert.deepEqual(ewsFolderDef('archive'), { token: 'archive', kind: 'empty', displayName: 'archive' });
	assert.equal(ewsFolderDef('Calendar').token, 'Calendar');
	assert.equal(ewsFolderDef('acct-abc'), null, '非法 acct- token 不因兜底变有效');

	// 文件夹 XML：账号文件夹 ChildFolderCount=0；root 的计数含账号文件夹
	const accountFolderXml = buildFolderXml({ token: 'acct-3', kind: 'account', displayName: 'a@b.c' },
		{ total: 2, unread: 1 }, '3');
	assert.ok(accountFolderXml.includes('<t:FolderId Id="acct-3" ChangeKey="3"/>'), 'FolderId 用 acct-<id>');
	assert.ok(accountFolderXml.includes('<t:ParentFolderId Id="root" ChangeKey="1"/>'), '账号文件夹挂在 root 下');
	assert.ok(accountFolderXml.includes('<t:ChildFolderCount>0</t:ChildFolderCount>'));
	assert.ok(buildFolderXml({ token: 'root', kind: 'root', displayName: 'CloudMail', extraChildCount: 2 })
		.includes('<t:ChildFolderCount>7</t:ChildFolderCount>'), 'root 子文件夹数含账号文件夹');
});

// ---------------------------------------------------------- 14. 不支持操作 ----

testCase('14. 未实现操作：ErrorNotImplemented 风格的 Fault（含操作名）', () => {
	const xml = soapFault('ErrorNotImplemented', 'Operation FindItem is not implemented by the CloudMail EWS bridge.');
	assertWellFormed(xml);
	assertSingleEnvelope(xml);
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
	const xml = operationResponse('SyncFolderItems', responseMessage('SyncFolderItems', {
		body: `<m:SyncState>${escapeXml(encodeSyncState(emptySyncState()))}</m:SyncState>` +
			'<m:IncludesLastItemInRange>true</m:IncludesLastItemInRange>' +
			'<m:Changes><t:Delete><t:ItemId Id="11"/></t:Delete><t:Delete><t:ItemId Id="14"/></t:Delete></m:Changes>'
	}));
	assertWellFormed(xml);
	assertSoapEnvelope(xml, 'SyncFolderItems');
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
	assertSingleEnvelope(fault);
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
		// 成功响应必须是完整 SOAP 信封（handler 经 operationResponse 统一包信封，router 不再二次包裹）
		assert.equal(XMLValidator.validate(xml), true, 'SyncFolderItems 响应必须良构');
		assertSoapEnvelope(xml, 'SyncFolderItems');
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

// --------------------------- 25. ResolveNames：命中 / 无匹配（TB 验证阶段） ---

testCase('25. ResolveNames：命中当前登录用户 → Success；无匹配 → ErrorNameResolutionNoResults（非 Fault）', async () => {
	ensureNodeResolveHook();
	const { dispatch } = await import('../src/ews/handlers.js');

	const user = { userId: 7, email: 'tb-user@example.com' };
	const request = (entry) => `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:ResolveNames xmlns:m="m" ReturnFullContactData="true" SearchScope="ActiveDirectory">
      <m:UnresolvedEntry>${entry}</m:UnresolvedEntry>
    </m:ResolveNames>
  </soap:Body>
</soap:Envelope>`;
	const resolve = async (entry) => {
		const parsed = parseSoapRequest(request(entry));
		assert.equal(parsed.operation, 'ResolveNames');
		const xml = await dispatch({}, parsed, user);
		assert.equal(XMLValidator.validate(xml), true, 'ResolveNames 响应必须良构');
		assertSoapEnvelope(xml, 'ResolveNames');
		return xml;
	};

	// ① 命中（等于登录邮箱）：Success + ResolutionSet / Resolution / Mailbox
	const hitXml = await resolve('tb-user@example.com');
	assert.ok(!hitXml.includes('<soap:Fault>'), '命中不抛 Fault');
	assert.ok(hitXml.includes('<m:ResolutionSet'), 'ResolutionSet 用 messages 命名空间（Exchange messages.xsd）');
	const hit = parseBack.parse(hitXml).Envelope.Body.ResolveNamesResponse.ResponseMessages.ResolveNamesResponseMessage;
	assert.equal(hit['@_ResponseClass'], 'Success');
	assert.equal(hit.ResponseCode, 'NoError');
	assert.equal(hit.ResolutionSet['@_TotalItemsInView'], '1');
	assert.equal(hit.ResolutionSet['@_IncludesLastItemInRange'], 'true');
	const resolution = asArray(hit.ResolutionSet.Resolution)[0];
	assert.equal(resolution.Mailbox.Name, 'tb-user', 'Name = 邮箱本地部分（user 表无显示名字段）');
	assert.equal(resolution.Mailbox.EmailAddress, 'tb-user@example.com');
	assert.equal(resolution.Mailbox.RoutingType, 'SMTP');
	assert.equal(resolution.Mailbox.MailboxType, 'Mailbox');

	// ② 匹配规则：大小写不敏感；全称串 / 本地部分 / 域 / 被用户邮箱包含
	assert.equal(resolveNameMatches('TB-USER@EXAMPLE.COM', user.email), true);
	assert.equal(resolveNameMatches('TB User <tb-user@example.com>', user.email), true);
	assert.equal(resolveNameMatches('example.com', user.email), true);
	assert.equal(resolveNameMatches('tb-user', user.email), true);
	assert.equal(resolveNameMatches('  tb-user@example.co  ', user.email), true, '被用户邮箱包含');
	assert.equal(resolveNameMatches('', user.email), false, '空串不匹配');

	// ③ 无匹配：标准 ResponseMessage Error（不抛 Fault —— TB 会把 Fault 当成认证失败）
	const missXml = await resolve('nobody@elsewhere.test');
	assert.ok(!missXml.includes('<soap:Fault>'), '无结果不是 SOAP Fault');
	const miss = parseBack.parse(missXml).Envelope.Body.ResolveNamesResponse.ResponseMessages.ResolveNamesResponseMessage;
	assert.equal(miss['@_ResponseClass'], 'Error');
	assert.equal(miss.ResponseCode, 'ErrorNameResolutionNoResults');
	assert.ok(!('ResolutionSet' in miss), '无结果不带 ResolutionSet');
	assert.equal(resolveNameMatches('nobody@elsewhere.test', user.email), false);

	// ④ 空 UnresolvedEntry：请求本身非法 → EwsFault（router 转 SOAP Fault）
	await assert.rejects(() => dispatch({}, parseSoapRequest(request('')), user), (error) => {
		assert.equal(error.responseCode, 'ErrorInvalidRequest');
		return true;
	});
});

// --------------------------- 26. GetServerTimeZones：UTC 时区定义结构 --------

testCase('26. GetServerTimeZones：UTC TimeZoneDefinition（Success/NoError，已注册不抛 Fault）', async () => {
	ensureNodeResolveHook();
	const { dispatch } = await import('../src/ews/handlers.js');

	const parsed = parseSoapRequest('<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><m:GetServerTimeZones xmlns:m="m"><m:ReturnFullTimeZoneData>false</m:ReturnFullTimeZoneData></m:GetServerTimeZones></soap:Body></soap:Envelope>');
	assert.equal(parsed.operation, 'GetServerTimeZones');

	const xml = await dispatch({}, parsed, {});
	assert.equal(XMLValidator.validate(xml), true, 'GetServerTimeZones 响应必须良构');
	assertSoapEnvelope(xml, 'GetServerTimeZones');
	const message = parseBack.parse(xml).Envelope.Body.GetServerTimeZonesResponse.ResponseMessages.GetServerTimeZonesResponseMessage;
	assert.equal(message['@_ResponseClass'], 'Success');
	assert.equal(message.ResponseCode, 'NoError');
	const definition = message.TimeZoneDefinitions.TimeZoneDefinition;
	assert.equal(definition['@_Id'], 'UTC');
	assert.equal(definition['@_Name'], 'UTC');
	assert.equal(definition.Periods.Period['@_Bias'], 'PT0M');
	assert.equal(definition.Periods.Period['@_Id'], 'UTC');
	assert.equal(definition.TransitionsGroups.TransitionsGroup['@_Id'], '0');
	assert.equal(definition.TransitionsGroups.TransitionsGroup.Transition.To['@_Kind'], 'Period');
	assert.equal(definition.TransitionsGroups.TransitionsGroup.Transition.To['#text'], 'UTC');
});

// --------------------------- 27. GetMailTips：每个收件人一条 Success --------

testCase('27. GetMailTips：每个收件人一个 MailTipsResponseMessage（Success/NoError）', async () => {
	ensureNodeResolveHook();
	const { dispatch } = await import('../src/ews/handlers.js');

	const parsed = parseSoapRequest(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:GetMailTips xmlns:m="m" xmlns:t="t">
      <m:Recipients>
        <t:Mailbox><t:EmailAddress>a@example.com</t:EmailAddress></t:Mailbox>
        <t:Mailbox><t:EmailAddress>b@example.com</t:EmailAddress><t:Name>B</t:Name></t:Mailbox>
      </m:Recipients>
      <m:MailTipsRequested>All</m:MailTipsRequested>
    </m:GetMailTips>
  </soap:Body>
</soap:Envelope>`);
	assert.equal(parsed.operation, 'GetMailTips');

	const xml = await dispatch({}, parsed, {});
	assert.equal(XMLValidator.validate(xml), true, 'GetMailTips 响应必须良构');
	assertSoapEnvelope(xml, 'GetMailTips');
	const messages = asArray(parseBack.parse(xml).Envelope.Body.GetMailTipsResponse.ResponseMessages.MailTipsResponseMessage);
	assert.equal(messages.length, 2, '每个收件人一个 ResponseMessage');
	assert.deepEqual(messages.map((m) => m['@_ResponseClass']), ['Success', 'Success']);
	assert.deepEqual(messages.map((m) => m.ResponseCode), ['NoError', 'NoError']);
	assert.deepEqual(
		messages.map((m) => m.MailTips.MailTips.RecipientAddress.EmailAddress),
		['a@example.com', 'b@example.com'],
		'回显收件人地址、不含特殊 tips 字段'
	);
});

// --------------- 28. router 级：GetFolder 成功响应 = 完整 SOAP 信封 ---------

testCase('28. router 级：GetFolder 成功/失败响应都是完整 SOAP 信封（Envelope.Body.GetFolderResponse 可达）', async () => {
	ensureNodeResolveHook();
	const { default: ewsApp } = await import('../src/ews/router.js');

	const email = 'tb-user@example.com';
	const password = 'secret-password';
	const jwtSecret = 'unit-test-jwt-secret';
	const cacheKey = 'ews-auth:' + createHash('sha256').update(`${jwtSecret}:${email}:${password}`).digest('hex');
	const kvStore = new Map([[cacheKey, JSON.stringify({ userId: 7, email, status: 0, isDel: 0 })]]);

	// D1 桩：folderCounts 的 count 查询经 drizzle 的 .all()（取 results[0]）→ 空集（0/0）；其余查询同样回空
	function stubD1() {
		const stmt = {
			bind() {
				return stmt;
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

	const env = {
		jwt_secret: jwtSecret,
		kv: {
			get: async (key) => (kvStore.has(key) ? JSON.parse(kvStore.get(key)) : null),
			put: async () => {},
			delete: async () => {}
		},
		db: stubD1()
	};

	const post = (body) => ewsApp.fetch(new Request('https://mail.example.com/EWS/Exchange.asmx', {
		method: 'POST',
		headers: {
			Authorization: 'Basic ' + Buffer.from(`${email}:${password}`).toString('base64'),
			'Content-Type': 'text/xml; charset=utf-8'
		},
		body
	}), env, {});

	// ① 真实 GetFolder（含未知文件夹 token）：完整信封 + 解析路径可达。
	// TB 按序 zip 请求 FolderIds 与 ResponseMessages：每个 Id 一条、顺序 = 请求顺序
	const res = await post(GETFOLDER_REQUEST);
	assert.equal(res.status, 200);
	assert.equal(res.headers.get('content-type'), 'text/xml; charset=utf-8');
	const xml = await res.text();
	assertWellFormed(xml);
	assertSoapEnvelope(xml, 'GetFolder');

	const doc = parseBack.parse(xml);
	const messages = asArray(doc.Envelope.Body.GetFolderResponse.ResponseMessages.GetFolderResponseMessage);
	assert.equal(messages.length, 3, '每个 FolderId 一条 ResponseMessage（inbox/deleteditems/未知）');
	assert.deepEqual(messages.map((m) => m['@_ResponseClass']), ['Success', 'Success', 'Error'],
		'ResponseClass 顺序 = 请求顺序');
	assert.deepEqual(messages.map((m) => m.ResponseCode), ['NoError', 'NoError', 'ErrorFolderNotFound']);
	assert.deepEqual(messages.slice(0, 2).map((m) => m.Folders.Folder.FolderId['@_Id']), ['inbox', 'deleteditems'],
		'每条 ResponseMessage 只含自己请求的那个文件夹（不得合并成一条多 Folder）');
	assert.ok(!messages[2].Folders, '失败那条不带 Folders');

	// ①b TB「收取邮件」的 8 个 DistinguishedFolderId（msgfolderroot 在首位）：数量/顺序/root 成功
	const tbIds = ['msgfolderroot', 'inbox', 'sentitems', 'deleteditems', 'drafts', 'outbox', 'junkemail', 'archive'];
	const tbXml = await (await post(GETFOLDER_REQUEST.replace(
		/<m:FolderIds>[\s\S]*?<\/m:FolderIds>/,
		`<m:FolderIds>${tbIds.map((id) => `<t:DistinguishedFolderId Id="${id}" />`).join('')}</m:FolderIds>`
	))).text();
	assert.equal(XMLValidator.validate(tbXml), true, '8 个 Id 的 GetFolder 响应必须良构');
	const tbMessages = asArray(parseBack.parse(tbXml)
		.Envelope.Body.GetFolderResponse.ResponseMessages.GetFolderResponseMessage);
	assert.equal(tbMessages.length, 8, 'ResponseMessage 数量 = 请求 Id 数量（TB 硬校验）');
	assert.deepEqual(tbMessages.map((m) => m['@_ResponseClass']), Array(8).fill('Success'),
		'全部 Success（任何一个 ErrorFolderNotFound 都会让 TB 中止收取）');
	assert.equal(tbMessages[0].Folders.Folder.FolderId['@_Id'], 'root',
		'root（msgfolderroot）是第一条且成功（TB zip 对齐后要求 root 在首位）');
	assert.deepEqual(tbMessages.map((m) => m.Folders.Folder.FolderId['@_Id']),
		['root', 'inbox', 'sentitems', 'deleteditems', 'drafts', 'outbox', 'junkemail', 'archive'],
		'顺序 = 请求顺序（msgfolderroot 归一成服务端 root；未实现 Distinguished 原样回传）');

	// ② 业务错误（缺 FolderIds → EwsFault）：router 仍回 200 + 单一信封的 Fault（无双重包裹）
	const badXml = await (await post(GETFOLDER_REQUEST.replace(/<m:FolderIds>[\s\S]*?<\/m:FolderIds>/, ''))).text();
	assertWellFormed(badXml);
	assertSingleEnvelope(badXml);
	assert.ok(!badXml.includes('<m:GetFolderResponse'), 'Fault 响应不含成功结构');
	const badBody = (badXml.match(/<soap:Body>(.*)<\/soap:Body>/) || [])[1] || '';
	assert.ok(badBody.startsWith('<soap:Fault>'), 'Fault 是 soap:Body 的直接子元素（无嵌套信封）');
	assert.ok(badXml.includes('ErrorInvalidRequest'));
});

// -------- 29. 可见域：只看登录邮箱同名的收件账号（无同名账号回退 userId 全量） ------

/**
 * 真 SQL 的 D1 桩：drizzle 生成的语句在内存 SQLite（node:sqlite，Node 22.5+ 内置）里真跑，
 * 断言的是真实过滤语义而不是桩回显。drizzle 的 d1 driver 用法：
 *   带列映射的 select → .bind().raw()（按列序映射回 camelCase）；无映射查询 → .all()；
 *   写语句（ews_sync_state 水位落库）→ .bind().run()。
 */
function sqliteD1(db) {
	const wrap = (text) => {
		const params = [];
		const stmt = {
			bind(...values) {
				params.length = 0;
				for (const value of values) params.push(value === undefined ? null : value);
				return stmt;
			},
			all() {
				return { results: db.prepare(text).all(...params), success: true };
			},
			raw() {
				return db.prepare(text).all(...params).map((row) => Object.values(row));
			},
			run() {
				const info = db.prepare(text).run(...params);
				return { success: true, meta: { changes: Number(info.changes), last_row_id: Number(info.lastInsertRowid) } };
			}
		};
		return stmt;
	};
	return { prepare: wrap, batch: async () => [] };
}

/** 最小表结构：与 src/entity/*.js 和 src/init/init.js 的 v4_4DB 迁移一致（只含 EWS 会读到的列） */
function seedEwsDb() {
	const db = new DatabaseSync(':memory:');
	db.exec(`
		CREATE TABLE account (
			account_id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL,
			name TEXT NOT NULL DEFAULT '',
			status INTEGER NOT NULL DEFAULT 0,
			latest_email_time TEXT,
			create_time TEXT,
			user_id INTEGER NOT NULL,
			all_receive INTEGER NOT NULL DEFAULT 0,
			sort INTEGER NOT NULL DEFAULT 0,
			is_del INTEGER NOT NULL DEFAULT 0
		);
		CREATE TABLE email (
			email_id INTEGER PRIMARY KEY AUTOINCREMENT,
			send_email TEXT, name TEXT,
			account_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
			subject TEXT, code TEXT NOT NULL DEFAULT '', text TEXT, content TEXT,
			cc TEXT DEFAULT '[]', bcc TEXT DEFAULT '[]', recipient TEXT,
			to_email TEXT NOT NULL DEFAULT '', to_name TEXT NOT NULL DEFAULT '',
			in_reply_to TEXT DEFAULT '', relation TEXT DEFAULT '', message_id TEXT DEFAULT '',
			type INTEGER NOT NULL DEFAULT 0, status INTEGER NOT NULL DEFAULT 0,
			resend_email_id TEXT, message TEXT,
			unread INTEGER NOT NULL DEFAULT 0,
			create_time TEXT NOT NULL DEFAULT '2026-09-30 08:00:00',
			is_del INTEGER NOT NULL DEFAULT 0, trash INTEGER NOT NULL DEFAULT 0, trash_time TEXT,
			update_time TEXT
		);
		CREATE TABLE attachments (
			att_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, email_id INTEGER NOT NULL,
			account_id INTEGER NOT NULL, key TEXT NOT NULL, filename TEXT, mime_type TEXT, size INTEGER,
			status TEXT NOT NULL DEFAULT '0', type INTEGER NOT NULL DEFAULT 0, disposition TEXT, related TEXT,
			content_id TEXT, encoding TEXT, create_time TEXT, trash INTEGER NOT NULL DEFAULT 0, trash_time TEXT
		);
		CREATE TABLE ews_sync_state (
			user_id INTEGER NOT NULL, folder TEXT NOT NULL, sync_state TEXT, update_time INTEGER,
			PRIMARY KEY (user_id, folder)
		);
		CREATE TABLE ews_tombstone (
			user_id INTEGER NOT NULL, email_id INTEGER NOT NULL, type INTEGER NOT NULL DEFAULT 0,
			trash INTEGER NOT NULL DEFAULT 0, del_time TEXT NOT NULL, PRIMARY KEY (user_id, email_id)
		);
	`);
	// user 7：account 1 = 登录邮箱同名账号、account 2 = 同用户名下别名；user 8 的邮件任何情况下都不可见
	db.exec(`
		INSERT INTO account (account_id, email, name, user_id) VALUES
			(1, 'tb-user@example.com', 'TB User', 7),
			(2, 'alias@example.com', 'Alias', 7),
			(3, 'stranger@example.com', 'Stranger', 8);
		INSERT INTO email (email_id, account_id, user_id, type, unread, trash, is_del, subject, send_email, create_time, update_time) VALUES
			(101, 1, 7, 0, 1, 0, 0, 'inbox acct1 read', 'a@x.y', '2026-09-30 08:00:00', '2026-09-30 08:00:00'),
			(102, 1, 7, 0, 0, 0, 0, 'inbox acct1 unread', 'b@x.y', '2026-09-30 09:00:00', '2026-09-30 09:00:00'),
			(103, 2, 7, 0, 0, 0, 0, 'inbox acct2 unread', 'c@x.y', '2026-09-30 10:00:00', '2026-09-30 10:00:00'),
			(104, 1, 7, 1, 1, 0, 0, 'sent acct1', '', '2026-09-30 11:00:00', '2026-09-30 11:00:00'),
			(105, 2, 7, 1, 1, 0, 0, 'sent acct2', '', '2026-09-30 12:00:00', '2026-09-30 12:00:00'),
			(106, 1, 7, 0, 1, 1, 0, 'trash acct1', 'd@x.y', '2026-09-30 13:00:00', '2026-09-30 13:00:00'),
			(107, 2, 7, 0, 1, 1, 0, 'trash acct2', 'e@x.y', '2026-09-30 14:00:00', '2026-09-30 14:00:00'),
			(108, 3, 8, 0, 0, 0, 0, 'inbox other user', 'f@x.y', '2026-09-30 15:00:00', '2026-09-30 15:00:00');
	`);
	return db;
}

testCase('29. 可见域：Distinguished 文件夹按用户聚合（该用户名下全部收件账号）；他用户不可见', async () => {
	ensureNodeResolveHook();
	const { default: ewsApp } = await import('../src/ews/router.js');

	const jwtSecret = 'unit-test-jwt-secret';
	const password = 'secret-password';
	const kvStore = new Map();
	// 认证走 KV 缓存桩（与 24/28 同法），登录邮箱决定可见域
	for (const [userId, email] of [[7, 'tb-user@example.com'], [7, 'ghost@example.com'], [8, 'stranger@example.com']]) {
		const key = 'ews-auth:' + createHash('sha256').update(`${jwtSecret}:${email}:${password}`).digest('hex');
		kvStore.set(key, JSON.stringify({ userId, email, status: 0, isDel: 0 }));
	}
	const kv = {
		get: async (key) => (kvStore.has(key) ? JSON.parse(kvStore.get(key)) : null),
		put: async () => {},
		delete: async () => {}
	};

	const post = (db, email, body) => ewsApp.fetch(new Request('https://mail.example.com/EWS/Exchange.asmx', {
		method: 'POST',
		headers: {
			Authorization: 'Basic ' + Buffer.from(`${email}:${password}`).toString('base64'),
			'Content-Type': 'text/xml; charset=utf-8'
		},
		body
	}), { jwt_secret: jwtSecret, kv, db: sqliteD1(db) }, {});

	const GET_FOLDERS = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
  <soap:Body>
    <m:GetFolder>
      <m:FolderShape><t:BaseShape>AllProperties</t:BaseShape></m:FolderShape>
      <m:FolderIds>
        <t:DistinguishedFolderId Id="inbox" />
        <t:DistinguishedFolderId Id="sentitems" />
        <t:DistinguishedFolderId Id="deleteditems" />
      </m:FolderIds>
    </m:GetFolder>
  </soap:Body>
</soap:Envelope>`;

	const syncRequest = (folder, state) => `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
  <soap:Body>
    <m:SyncFolderItems>
      <m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape>
      <m:SyncFolderId><t:DistinguishedFolderId Id="${folder}" /></m:SyncFolderId>
      <m:SyncState>${state}</m:SyncState>
      <m:MaxChangesReturned>512</m:MaxChangesReturned>
    </m:SyncFolderItems>
  </soap:Body>
</soap:Envelope>`;

	/** 各文件夹计数（GetFolder）：{ total, unread } */
	async function folderCountsOf(db, email) {
		const xml = await (await post(db, email, GET_FOLDERS)).text();
		assert.equal(XMLValidator.validate(xml), true, 'GetFolder 响应必须良构');
		assertSoapEnvelope(xml, 'GetFolder');
		const messages = asArray(parseBack.parse(xml).Envelope.Body.GetFolderResponse.ResponseMessages.GetFolderResponseMessage);
		const folders = messages.flatMap((message) => asArray(message.Folders.Folder));
		return new Map(folders.map((folder) => [
			folder.FolderId['@_Id'],
			{ total: Number(folder.TotalCount), unread: Number(folder.UnreadCount) }
		]));
	}

	/** SyncFolderItems：返回本轮 Create 的 ItemId 列表 + 解码后的 SyncState */
	async function syncItems(db, email, folder, state = '') {
		const xml = await (await post(db, email, syncRequest(folder, state))).text();
		assert.equal(XMLValidator.validate(xml), true, 'SyncFolderItems 响应必须良构');
		assertSoapEnvelope(xml, 'SyncFolderItems');
		assert.ok(!xml.includes('<soap:Fault>'), '不应出现 Fault');
		const message = parseBack.parse(xml).Envelope.Body.SyncFolderItemsResponse.ResponseMessages.SyncFolderItemsResponseMessage;
		const creates = asArray(message.Changes?.Create)
			.flatMap((node) => asArray(node.Message))
			.map((item) => Number(item.ItemId['@_Id']))
			.sort((a, b) => a - b);
		return { xml, creates, state: decodeSyncState(textOf(message.SyncState)) };
	}

	const db = seedEwsDb();
	const sorted = (ids) => [...ids].sort((a, b) => a - b);

	// ① folderCounts：Distinguished 文件夹 = 用户级聚合（account 1 + account 2 都算）
	const loginFolders = await folderCountsOf(db, 'tb-user@example.com');
	assert.deepEqual(loginFolders.get('inbox'), { total: 3, unread: 2 }, '收件箱聚合该用户名下全部收件账号（101/102/103）');
	assert.deepEqual(loginFolders.get('sentitems'), { total: 2, unread: 0 }, '已发送聚合全部账号（104/105）');
	assert.deepEqual(loginFolders.get('deleteditems'), { total: 2, unread: 0 }, '已删除聚合全部账号（106/107）');

	// ② 首轮全量 + 水位快照同样是用户级（account 2 的 103 在，其他用户的 108 不在）
	const first = await syncItems(db, 'tb-user@example.com', 'inbox');
	assert.deepEqual(first.creates, [101, 102, 103], '首轮发该用户名下全部收件账号的邮件');
	assert.ok(!first.xml.includes('Id="108"'), '其他用户的 ItemId 不出现在响应里');
	// 水位 = 本轮 scope 扫描到的最大 eff（含被跳过的垃圾桶行：它们在 scope 内、用于产出 Delete；
	// 客户端拿到的仍是全部可见邮件，见 creates）
	assert.equal(first.state.wm, '2026-09-30 14:00:00', '水位推进到本轮扫描到的最大 eff（106/107 已进垃圾桶）');
	assert.ok(first.state.wm >= '2026-09-30 10:00:00', '不低于该用户全部可见邮件的 MAX(update_time)');

	// ③ 增量：当前用户的新邮件上报、其他用户的新邮件不上报
	db.prepare(`INSERT INTO email (email_id, account_id, user_id, type, unread, trash, is_del, subject, send_email, create_time, update_time)
	            VALUES (109, 1, 7, 0, 0, 0, 0, 'inbox acct1 new', 'g@x.y', '2026-10-01 00:00:00', '2026-10-01 00:00:00')`).run();
	db.prepare(`INSERT INTO email (email_id, account_id, user_id, type, unread, trash, is_del, subject, send_email, create_time, update_time)
	            VALUES (110, 3, 8, 0, 0, 0, 0, 'inbox other user new', 'h@x.y', '2026-10-01 01:00:00', '2026-10-01 01:00:00')`).run();
	const second = await syncItems(db, 'tb-user@example.com', 'inbox', encodeSyncState(first.state));
	assert.deepEqual(second.creates, [109], '增量只上报当前用户的新邮件');
	assert.ok(!second.xml.includes('Id="110"'), '其他用户的新邮件不上报（userId 边界不放松）');

	// ④ 其他用户只见自己的邮件：stranger（user 8）的 account 3
	const stranger = await folderCountsOf(db, 'stranger@example.com');
	assert.deepEqual(stranger.get('inbox'), { total: 2, unread: 2 }, '只见自己的 108/110');
	assert.deepEqual(stranger.get('sentitems'), { total: 0, unread: 0 });
	assert.deepEqual(stranger.get('deleteditems'), { total: 0, unread: 0 });
	const strangerSync = await syncItems(db, 'stranger@example.com', 'inbox');
	assert.deepEqual(sorted(strangerSync.creates), [108, 110], 'user 8 只同步自己的邮件');
	assert.ok(!strangerSync.xml.includes('Id="101"'), 'user 7 的邮件不可见');

	// ⑤ 别名邮箱登录（无同名账号）：口径与登录邮箱无关（用户级聚合）
	const ghost = await folderCountsOf(db, 'ghost@example.com');
	assert.deepEqual(ghost.get('inbox'), { total: 4, unread: 3 }, '别名登录同样看到该用户名下全部账号的邮件');
	const ghostSync = await syncItems(db, 'ghost@example.com', 'inbox');
	assert.deepEqual(sorted(ghostSync.creates), [101, 102, 103, 109], '别名登录同步该用户全部收件账号的邮件');
	assert.ok(!ghostSync.xml.includes('Id="108"') && !ghostSync.xml.includes('Id="110"'), '其他用户的邮件仍不可见');
});

// ------------- 30. 账号文件夹：acct-<id>（列表 / 内容 / 归属 / token 校验） ------

testCase('30. 账号文件夹：每个 account 一个 acct-<id>（列表/内容/归属校验/非法 token 拒绝）', async () => {
	ensureNodeResolveHook();
	const { default: ewsApp } = await import('../src/ews/router.js');

	const jwtSecret = 'unit-test-jwt-secret';
	const password = 'secret-password';
	const kvStore = new Map();
	for (const [userId, mail] of [[7, 'tb-user@example.com'], [7, 'alias@example.com'], [8, 'stranger@example.com']]) {
		const key = 'ews-auth:' + createHash('sha256').update(`${jwtSecret}:${mail}:${password}`).digest('hex');
		kvStore.set(key, JSON.stringify({ userId, email: mail, status: 0, isDel: 0 }));
	}
	const kv = {
		get: async (key) => (kvStore.has(key) ? JSON.parse(kvStore.get(key)) : null),
		put: async () => {},
		delete: async () => {}
	};

	const post = (db, mail, body) => ewsApp.fetch(new Request('https://mail.example.com/EWS/Exchange.asmx', {
		method: 'POST',
		headers: {
			Authorization: 'Basic ' + Buffer.from(`${mail}:${password}`).toString('base64'),
			'Content-Type': 'text/xml; charset=utf-8'
		},
		body
	}), { jwt_secret: jwtSecret, kv, db: sqliteD1(db) }, {});

	const envelope = (body) => `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
  <soap:Body>${body}</soap:Body>
</soap:Envelope>`;

	const HIERARCHY = envelope('<m:SyncFolderHierarchy>' +
		'<m:FolderShape><t:BaseShape>AllProperties</t:BaseShape></m:FolderShape>' +
		'</m:SyncFolderHierarchy>');
	const GET_FOLDER = (ids) => envelope('<m:GetFolder>' +
		'<m:FolderShape><t:BaseShape>AllProperties</t:BaseShape></m:FolderShape>' +
		`<m:FolderIds>${ids.map((id) => `<t:FolderId Id="${id}"/>`).join('')}</m:FolderIds>` +
		'</m:GetFolder>');
	// 自定义文件夹客户端用 t:FolderId 回传（与 Distinguished 的 DistinguishedFolderId 都要认）
	const SYNC_ITEMS = (folder, state = '') => envelope('<m:SyncFolderItems>' +
		'<m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape>' +
		`<m:SyncFolderId><t:FolderId Id="${folder}"/></m:SyncFolderId>` +
		`<m:SyncState>${state}</m:SyncState>` +
		'<m:MaxChangesReturned>512</m:MaxChangesReturned>' +
		'</m:SyncFolderItems>');

	/** SyncFolderItems：本轮 Create 的 ItemId 列表 + 解码后的 SyncState（响应必须无 Fault） */
	async function syncItems(db, mail, folder, state = '') {
		const xml = await (await post(db, mail, SYNC_ITEMS(folder, state))).text();
		assert.equal(XMLValidator.validate(xml), true, 'SyncFolderItems 响应必须良构');
		assertSoapEnvelope(xml, 'SyncFolderItems');
		assert.ok(!xml.includes('<soap:Fault>'), '不应出现 Fault');
		const message = parseBack.parse(xml).Envelope.Body.SyncFolderItemsResponse.ResponseMessages.SyncFolderItemsResponseMessage;
		const creates = asArray(message.Changes?.Create)
			.flatMap((node) => asArray(node.Message))
			.map((item) => Number(item.ItemId['@_Id']))
			.sort((a, b) => a - b);
		return { xml, creates, state: decodeSyncState(textOf(message.SyncState)) };
	}

	/** GetFolder：Folder 节点列表 + 以 FolderId 为键的映射（ErrorFolderNotFound 时列表为空） */
	async function getFolders(db, mail, ids) {
		const xml = await (await post(db, mail, GET_FOLDER(ids))).text();
		assert.equal(XMLValidator.validate(xml), true, 'GetFolder 响应必须良构');
		assertSoapEnvelope(xml, 'GetFolder');
		const messages = asArray(parseBack.parse(xml).Envelope.Body.GetFolderResponse.ResponseMessages.GetFolderResponseMessage);
		const folders = messages.flatMap((message) => asArray(message.Folders?.Folder));
		return { xml, folders, byId: new Map(folders.map((folder) => [folder.FolderId['@_Id'], folder])) };
	}

	const db = seedEwsDb();

	// ① SyncFolderHierarchy：Distinguished 5 个 + 该用户名下 2 个账号文件夹（DisplayName = 账号邮箱）
	const hierarchyXml = await (await post(db, 'tb-user@example.com', HIERARCHY)).text();
	assert.equal(XMLValidator.validate(hierarchyXml), true, 'SyncFolderHierarchy 响应必须良构');
	assertSoapEnvelope(hierarchyXml, 'SyncFolderHierarchy');
	const hierarchy = parseBack.parse(hierarchyXml)
		.Envelope.Body.SyncFolderHierarchyResponse.ResponseMessages.SyncFolderHierarchyResponseMessage;
	const creates = asArray(hierarchy.Changes.Create).flatMap((node) => asArray(node.Folder));
	const accountFolders = creates.filter((folder) => String(folder.FolderId['@_Id']).startsWith('acct-'));
	assert.deepEqual(accountFolders.map((folder) => folder.FolderId['@_Id']), ['acct-1', 'acct-2'],
		'每个收件账号一个 acct-<accountId> 文件夹');
	assert.equal(accountFolders[0].DisplayName, 'tb-user@example.com', 'DisplayName = 账号邮箱地址');
	assert.equal(accountFolders[1].DisplayName, 'alias@example.com');
	assert.equal(accountFolders[0].ParentFolderId['@_Id'], 'root', '账号文件夹挂在 root 下');
	assert.equal(accountFolders[0].TotalCount, '2', 'acct-1 的可见收件（101/102）');
	assert.equal(accountFolders[0].UnreadCount, '1');
	assert.equal(accountFolders[1].TotalCount, '1', 'acct-2 的可见收件（103）');
	assert.equal(accountFolders[1].UnreadCount, '1');
	assert.equal(accountFolders[0].ChildFolderCount, '0');
	assert.equal(accountFolders[0].FolderId['@_ChangeKey'], '1', 'ChangeKey = accountId');
	assert.equal(accountFolders[1].FolderId['@_ChangeKey'], '2');
	assert.ok(creates.some((folder) => folder.FolderId['@_Id'] === 'inbox'), 'Distinguished 文件夹照旧出现');

	// ①a TB 三件套（rust/protocol_shared/src/safe_xpcom/folder_listener.rs 的 on_folder_created）：
	// 每个 Create 文件夹都必须同时含 t:FolderId@Id + t:ParentFolderId@Id + t:DisplayName，
	// 缺任何一个 → folder_id.ok_or(NS_ERROR_FAILURE) 等 → 整个文件夹同步失败
	assert.ok(creates.length > 0, 'SyncFolderHierarchy 必须产出 Create 事件');
	for (const folder of creates) {
		const id = folder.FolderId?.['@_Id'];
		assert.ok(typeof id === 'string' && id !== '', `每个 Create 文件夹都有 FolderId@Id（实际 ${String(id)}）`);
		assert.equal(folder.ParentFolderId?.['@_Id'], 'root',
			`${id} 的 ParentFolderId@Id = root（TB 缺此件即 NS_ERROR_FAILURE）`);
		assert.ok(typeof folder.DisplayName === 'string' && folder.DisplayName.trim() !== '',
			`${id} 的 DisplayName 非空（TB 缺此件即 NS_ERROR_FAILURE）`);
	}
	// 三件套必须真的落在响应字符串上（元素缺失/前缀错误在解析后可能被掩盖）
	for (const id of ['inbox', 'sentitems', 'deleteditems', 'drafts', 'outbox', 'acct-1', 'acct-2']) {
		assert.ok(new RegExp(
			`<t:Create><t:Folder><t:FolderId Id="${id}"[^>]*/><t:ParentFolderId Id="root" ChangeKey="1"/>` +
			'<t:FolderClass>IPF.Note</t:FolderClass><t:DisplayName>[^<]+</t:DisplayName>'
		).test(hierarchyXml), `Create(${id}) 在 XML 上按序带三件套（FolderId/ParentFolderId/DisplayName）`);
	}
	assert.ok(!creates.some((folder) => folder.FolderId['@_Id'] === 'root'),
		'root 自身不在 Create 列表（不给自己发 ParentFolderId）');
	// root 不在 Create 列表里（它是这些文件夹的父）：它的子文件夹数经 GetFolder(root) 反馈
	const rootGot = await getFolders(db, 'tb-user@example.com', ['root']);
	assert.equal(rootGot.byId.get('root').ChildFolderCount, '7', 'root 子文件夹数 = 5 Distinguished + 2 账号文件夹');

	// ①b 以别名（alias@example.com = account 2）登录：同名账号的文件夹排最前
	const aliasCreates = asArray(parseBack.parse(await (await post(db, 'alias@example.com', HIERARCHY)).text())
		.Envelope.Body.SyncFolderHierarchyResponse.ResponseMessages.SyncFolderHierarchyResponseMessage.Changes.Create)
		.flatMap((node) => asArray(node.Folder));
	assert.deepEqual(aliasCreates.map((folder) => folder.FolderId['@_Id']).filter((id) => id.startsWith('acct-')),
		['acct-2', 'acct-1'], '同名账号（alias@example.com）的文件夹排最前');

	// ② SyncFolderItems(acct-2)：只含该账号的可见收件
	const acct2 = await syncItems(db, 'tb-user@example.com', 'acct-2');
	assert.deepEqual(acct2.creates, [103], 'acct-2 只回 account 2 的可见收件');
	for (const hidden of ['101', '102', '105', '107', '108']) {
		assert.ok(!acct2.xml.includes(`Id="${hidden}"`),
			`ItemId ${hidden} 不出现在 acct-2（他账号/该账号发件/垃圾桶/他用户）`);
	}
	assert.equal(acct2.state.wm, '2026-09-30 14:00:00', '水位 = 该账号 scope 内扫描到的最大 eff（107 已进垃圾桶）');
	const storedFolders = db.prepare('SELECT folder FROM ews_sync_state WHERE user_id = 7 ORDER BY folder')
		.all().map((row) => row.folder);
	assert.ok(storedFolders.includes('acct-2'), `SyncState 以 token 落库（实际：${storedFolders.join(',')}）`);

	// ③ 增量只看该账号：同用户名下他账号的新邮件不进入该文件夹
	db.prepare(`INSERT INTO email (email_id, account_id, user_id, type, unread, trash, is_del, subject, send_email, create_time, update_time)
	            VALUES (111, 2, 7, 0, 0, 0, 0, 'acct2 new', 'g@x.y', '2026-10-01 02:00:00', '2026-10-01 02:00:00')`).run();
	db.prepare(`INSERT INTO email (email_id, account_id, user_id, type, unread, trash, is_del, subject, send_email, create_time, update_time)
	            VALUES (112, 1, 7, 0, 0, 0, 0, 'acct1 new', 'h@x.y', '2026-10-01 03:00:00', '2026-10-01 03:00:00')`).run();
	const acct2b = await syncItems(db, 'tb-user@example.com', 'acct-2', encodeSyncState(acct2.state));
	assert.deepEqual(acct2b.creates, [111], '增量只上报该账号的新邮件');
	assert.ok(!acct2b.xml.includes('Id="112"'), '同用户名下他账号的新邮件不进入该文件夹');

	// ④ GetFolder(acct-1/acct-2)：DisplayName + 计数（只算该账号可见收件）
	const got = await getFolders(db, 'tb-user@example.com', ['acct-1', 'acct-2']);
	assert.deepEqual([...got.byId.keys()], ['acct-1', 'acct-2'], '请求顺序原样返回');
	assert.equal(got.byId.get('acct-1').DisplayName, 'tb-user@example.com');
	assert.equal(got.byId.get('acct-2').DisplayName, 'alias@example.com');
	assert.equal(got.byId.get('acct-1').TotalCount, '3', 'acct-1 = 101/102/112');
	assert.equal(got.byId.get('acct-1').UnreadCount, '2');
	assert.equal(got.byId.get('acct-2').TotalCount, '2', 'acct-2 = 103/111');
	assert.equal(got.byId.get('acct-2').UnreadCount, '2');

	// ⑤ 越权：user 7 请求 user 8 的账号文件夹（acct-3）→ ErrorFolderNotFound（不泄露账号邮箱）
	const foreign = await getFolders(db, 'tb-user@example.com', ['acct-3']);
	assert.equal(foreign.folders.length, 0, '他人账号不回 Folder');
	assert.ok(foreign.xml.includes('ErrorFolderNotFound'), 'GetFolder 他人账号 → ErrorFolderNotFound');
	assert.ok(!foreign.xml.includes('stranger@example.com'), '不泄露他人账号邮箱');
	const foreignSync = await (await post(db, 'tb-user@example.com', SYNC_ITEMS('acct-3'))).text();
	assert.equal(XMLValidator.validate(foreignSync), true, 'Fault 响应必须良构');
	assert.ok(foreignSync.includes('<soap:Fault>') && foreignSync.includes('ErrorFolderNotFound'),
		'SyncFolderItems 他人账号 → Fault');
	assert.ok(!foreignSync.includes('stranger@example.com'));

	// ⑤b 同一请求混装「未实现的 Distinguished（空文件夹成功）+ 他人账号（错误）」：
	//     兜底不得把真越权的 ErrorFolderNotFound 一起吞掉
	const mixed = await getFolders(db, 'tb-user@example.com', ['acct-3', 'junkemail']);
	assert.deepEqual([...mixed.byId.keys()], ['junkemail'], '只有 junkemail 回 Folder（空文件夹）');
	assert.equal(mixed.byId.get('junkemail').TotalCount, '0', '未实现 Distinguished → TotalCount=0');
	assert.ok(mixed.xml.includes('ErrorFolderNotFound'), '他人账号仍是 ErrorFolderNotFound');

	// ⑥ 非法 token（非数字 / 空数字 / 带尾巴 / 0 / 超范围 / 负数）：一律拒绝，绝不落到 SQL
	for (const bad of ['acct-abc', 'acct-', 'acct-1abc', 'acct-0', 'acct-99999999999999999999', 'acct--1']) {
		const res = await getFolders(db, 'tb-user@example.com', [bad]);
		assert.equal(res.folders.length, 0, `${bad} 不回 Folder`);
		assert.ok(res.xml.includes('ErrorFolderNotFound'), `${bad} → ErrorFolderNotFound`);
	}
	const badSync = await (await post(db, 'tb-user@example.com', SYNC_ITEMS('acct-abc'))).text();
	assert.ok(badSync.includes('<soap:Fault>') && badSync.includes('ErrorFolderNotFound'),
		'SyncFolderItems 非数字 token → Fault');
});

// ------- 31. 未实现的 Distinguished 文件夹：GetFolder 空文件夹兜底（不中止 TB 收取） -------

testCase('31. GetFolder 未实现 Distinguished（junkemail/archive/calendar…）→ 空文件夹成功，非法 token 仍报错', async () => {
	ensureNodeResolveHook();
	const { default: ewsApp } = await import('../src/ews/router.js');

	const jwtSecret = 'unit-test-jwt-secret';
	const password = 'secret-password';
	const kvStore = new Map();
	for (const [userId, mail] of [[7, 'tb-user@example.com'], [8, 'stranger@example.com']]) {
		const key = 'ews-auth:' + createHash('sha256').update(`${jwtSecret}:${mail}:${password}`).digest('hex');
		kvStore.set(key, JSON.stringify({ userId, email: mail, status: 0, isDel: 0 }));
	}
	const kv = {
		get: async (key) => (kvStore.has(key) ? JSON.parse(kvStore.get(key)) : null),
		put: async () => {},
		delete: async () => {}
	};

	const post = (db, mail, body) => ewsApp.fetch(new Request('https://mail.example.com/EWS/Exchange.asmx', {
		method: 'POST',
		headers: {
			Authorization: 'Basic ' + Buffer.from(`${mail}:${password}`).toString('base64'),
			'Content-Type': 'text/xml; charset=utf-8'
		},
		body
	}), { jwt_secret: jwtSecret, kv, db: sqliteD1(db) }, {});

	const envelope = (body) => `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
  <soap:Body>${body}</soap:Body>
</soap:Envelope>`;

	// TB「收取邮件」的 GetFolder：BaseShape=IdOnly + 一串 DistinguishedFolderId（已实现与未实现混在一起）
	const getFolderDistinguished = (ids) => envelope('<m:GetFolder>' +
		'<m:FolderShape><t:BaseShape>IdOnly</t:BaseShape></m:FolderShape>' +
		`<m:FolderIds>${ids.map((id) => `<t:DistinguishedFolderId Id="${id}" />`).join('')}</m:FolderIds>` +
		'</m:GetFolder>');
	const syncItemsDistinguished = (folder, state = '') => envelope('<m:SyncFolderItems>' +
		'<m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape>' +
		`<m:SyncFolderId><t:DistinguishedFolderId Id="${folder}" /></m:SyncFolderId>` +
		`<m:SyncState>${state}</m:SyncState>` +
		'<m:MaxChangesReturned>512</m:MaxChangesReturned>' +
		'</m:SyncFolderItems>');

	const db = seedEwsDb();

	// ① 混装请求：全部 ResponseClass=Success（一个 ErrorFolderNotFound 就会让 TB 中止整个收取流程）
	const ids = ['inbox', 'junkemail', 'archive', 'calendar', 'tasks'];
	const xml = await (await post(db, 'tb-user@example.com', getFolderDistinguished(ids))).text();
	assert.equal(XMLValidator.validate(xml), true, 'GetFolder 响应必须良构');
	assertSoapEnvelope(xml, 'GetFolder');
	assert.ok(!xml.includes('ErrorFolderNotFound'), '未实现 Distinguished 不得回 ErrorFolderNotFound');
	assert.ok(!xml.includes('ResponseClass="Error"'), '整响应不得有 Error 级 ResponseMessage');
	const messages = asArray(parseBack.parse(xml).Envelope.Body.GetFolderResponse.ResponseMessages.GetFolderResponseMessage);
	assert.equal(messages.length, ids.length, '每个 FolderId 一条 Success ResponseMessage（TB 按序 zip 请求项）');
	assert.deepEqual(messages.map((message) => message['@_ResponseClass']), Array(ids.length).fill('Success'));
	assert.deepEqual(messages.map((message) => message.ResponseCode), Array(ids.length).fill('NoError'));
	const folders = new Map(messages.map((message) => [message.Folders.Folder.FolderId['@_Id'], message.Folders.Folder]));
	assert.deepEqual([...folders.keys()], ids, 'FolderId Id 原样回传（顺序 + 大小写不变）');
	for (const id of ['junkemail', 'archive', 'calendar', 'tasks']) {
		const folder = folders.get(id);
		assert.equal(folder.DisplayName, id, `${id} DisplayName = 请求里的 Id 原样`);
		assert.equal(folder.ParentFolderId['@_Id'], 'root', `${id} 兜底文件夹也带 ParentFolderId@Id=root（三件套）`);
		assert.equal(folder.TotalCount, '0', `${id} TotalCount=0`);
		assert.equal(folder.UnreadCount, '0', `${id} UnreadCount=0`);
		assert.equal(folder.ChildFolderCount, '0', `${id} ChildFolderCount=0`);
		assert.equal(folder.FolderId['@_ChangeKey'], '1');
	}
	// 已实现的文件夹照旧带真实计数（兜底不得把 inbox 变成空文件夹，也不得泄露他用户邮件）
	assert.equal(folders.get('inbox').TotalCount, '3', 'inbox 仍是用户级聚合（101/102/103）');

	// ② 兜底文件夹上的 SyncFolderItems：空变更 + 可用 SyncState（TB 拿到文件夹后必然跟进同步）
	const syncXml = await (await post(db, 'tb-user@example.com', syncItemsDistinguished('junkemail'))).text();
	assert.equal(XMLValidator.validate(syncXml), true, 'SyncFolderItems 响应必须良构');
	assertSoapEnvelope(syncXml, 'SyncFolderItems');
	assert.ok(!syncXml.includes('<soap:Fault>'), '不应出现 Fault');
	const syncMessage = parseBack.parse(syncXml).Envelope.Body.SyncFolderItemsResponse.ResponseMessages.SyncFolderItemsResponseMessage;
	assert.equal(syncMessage['@_ResponseClass'], 'Success');
	// 三件套恒存在（TB 硬校验）：SyncState（非空）+ IncludesLastItemInRange + Changes（空元素也必须输出）
	assert.ok(textOf(syncMessage.SyncState).length > 0, 'SyncState 是非空字符串');
	assert.equal(syncMessage.IncludesLastItemInRange, 'true');
	assert.ok('Changes' in syncMessage, 'Changes 元素恒存在（可空）');
	assert.equal(syncMessage.Changes, '', '空文件夹：Changes 为空元素');
	assert.ok(decodeSyncState(textOf(syncMessage.SyncState)), 'SyncState 可解析（后续增量可用）');
	for (const hidden of ['101', '108']) {
		assert.ok(!syncXml.includes(`Id="${hidden}"`), `ItemId ${hidden} 不进入兜底文件夹（无数据泄露）`);
	}
	// 空文件夹不落 ews_sync_state（回空变更即返回，无状态可存）
	assert.equal(db.prepare('SELECT COUNT(*) AS n FROM ews_sync_state WHERE folder = ?').get('junkemail').n, 0);

	// ③ 非法 token（既非 Distinguished 也非 acct-）：维持 ErrorFolderNotFound，兜底绝不放宽
	const bogusXml = await (await post(db, 'tb-user@example.com', envelope('<m:GetFolder>' +
		'<m:FolderShape><t:BaseShape>IdOnly</t:BaseShape></m:FolderShape>' +
		'<m:FolderIds><t:FolderId Id="bogus-folder" /><t:FolderId Id="nope" /></m:FolderIds>' +
		'</m:GetFolder>'))).text();
	assert.equal(XMLValidator.validate(bogusXml), true, 'Fault/错误响应同样良构');
	assert.ok(bogusXml.includes('ErrorFolderNotFound'), '非法 token → ErrorFolderNotFound');
	assert.ok(!bogusXml.includes('<m:Folders>'), '非法 token 不回 Folder 节点');

	// ④ 他人账号（acct-3 属于 user 8）：兜底不得吞掉真越权错误
	const foreignXml = await (await post(db, 'tb-user@example.com', envelope('<m:GetFolder>' +
		'<m:FolderShape><t:BaseShape>IdOnly</t:BaseShape></m:FolderShape>' +
		'<m:FolderIds><t:DistinguishedFolderId Id="junkemail" /><t:FolderId Id="acct-3" /></m:FolderIds>' +
		'</m:GetFolder>'))).text();
	const foreignMessages = asArray(parseBack.parse(foreignXml)
		.Envelope.Body.GetFolderResponse.ResponseMessages.GetFolderResponseMessage);
	assert.deepEqual(foreignMessages.map((message) => message['@_ResponseClass']), ['Success', 'Error'],
		'空文件夹成功 + 越权错误各一条 ResponseMessage');
	assert.equal(foreignMessages[0].Folders.Folder.FolderId['@_Id'], 'junkemail');
	assert.equal(foreignMessages[1].ResponseCode, 'ErrorFolderNotFound');
	assert.ok(!foreignXml.includes('stranger@example.com'), '不泄露他人账号邮箱');
});

// ------- 32. FindFolder：root 子文件夹枚举 / 叶子空列表 / 越权 / 多父逐条响应 -------

testCase('32. FindFolder：msgfolderroot 枚举全部子文件夹、叶子回空、他人账号/未知 token 报错、多父逐条响应', async () => {
	ensureNodeResolveHook();
	const { default: ewsApp } = await import('../src/ews/router.js');

	const jwtSecret = 'unit-test-jwt-secret';
	const password = 'secret-password';
	const kvStore = new Map();
	for (const [userId, mail] of [[7, 'tb-user@example.com'], [7, 'alias@example.com'], [8, 'stranger@example.com']]) {
		const key = 'ews-auth:' + createHash('sha256').update(`${jwtSecret}:${mail}:${password}`).digest('hex');
		kvStore.set(key, JSON.stringify({ userId, email: mail, status: 0, isDel: 0 }));
	}
	const kv = {
		get: async (key) => (kvStore.has(key) ? JSON.parse(kvStore.get(key)) : null),
		put: async () => {},
		delete: async () => {}
	};

	const post = (db, mail, body) => ewsApp.fetch(new Request('https://mail.example.com/EWS/Exchange.asmx', {
		method: 'POST',
		headers: {
			Authorization: 'Basic ' + Buffer.from(`${mail}:${password}`).toString('base64'),
			'Content-Type': 'text/xml; charset=utf-8'
		},
		body
	}), { jwt_secret: jwtSecret, kv, db: sqliteD1(db) }, {});

	const envelope = (body) => `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
  <soap:Body>${body}</soap:Body>
</soap:Envelope>`;

	// 父文件夹用 DistinguishedFolderId（root 走 msgfolderroot）或 FolderId（acct-<id>）回传：
	// 两种写法都要认（与既有 GetFolder 的 token 解析一致）
	const FIND_FOLDER = (parents, { traversal = 'Shallow', baseShape = 'AllProperties' } = {}) => envelope(
		`<m:FindFolder Traversal="${traversal}">` +
		`<m:FolderShape><t:BaseShape>${baseShape}</t:BaseShape></m:FolderShape>` +
		'<m:ParentFolderIds>' + parents.map((parent) => (String(parent).startsWith('acct-')
			? `<t:FolderId Id="${parent}" />`
			: `<t:DistinguishedFolderId Id="${parent}" />`)).join('') + '</m:ParentFolderIds>' +
		'</m:FindFolder>');

	/** FindFolder：{ xml, messages, foldersOf(索引) }（响应必须良构 + 完整信封） */
	async function findFolder(db, mail, parents, options) {
		const xml = await (await post(db, mail, FIND_FOLDER(parents, options))).text();
		const wellFormed = XMLValidator.validate(xml);
		assert.equal(wellFormed, true,
			`FindFolder 响应必须良构: ${typeof wellFormed === 'object' ? wellFormed.err?.msg : ''} | ${xml.slice(0, 400)}`);
		assertSoapEnvelope(xml, 'FindFolder');
		assert.ok(!xml.includes('<soap:Fault>'), 'FindFolder 不应抛 Fault（业务错误走 ResponseMessage）');
		const messages = asArray(parseBack.parse(xml)
			.Envelope.Body.FindFolderResponse.ResponseMessages.FindFolderResponseMessage);
		return {
			xml,
			messages,
			foldersOf: (index) => asArray(messages[index]?.RootFolder?.Folders?.Folder)
		};
	}

	const db = seedEwsDb();

	// ① FindFolder(msgfolderroot)：Success + 5 个 Distinguished + 该用户名下全部账号文件夹（DisplayName = 账号邮箱）
	const root = await findFolder(db, 'tb-user@example.com', ['msgfolderroot']);
	assert.equal(root.messages.length, 1, '单个 ParentFolderId → 单条 ResponseMessage');
	assert.equal(root.messages[0]['@_ResponseClass'], 'Success');
	assert.equal(root.messages[0].ResponseCode, 'NoError');
	assert.equal(root.messages[0].RootFolder['@_IncludesLastItemInRange'], 'true');
	const rootFolders = root.foldersOf(0);
	assert.equal(root.messages[0].RootFolder['@_TotalItemsInView'], String(rootFolders.length));
	const rootIds = rootFolders.map((folder) => folder.FolderId['@_Id']);
	assert.deepEqual(rootIds, ['inbox', 'sentitems', 'deleteditems', 'drafts', 'outbox', 'acct-1', 'acct-2'],
		'root 子文件夹 = 5 个 Distinguished + 每个账号文件夹');
	const rootById = new Map(rootFolders.map((folder) => [folder.FolderId['@_Id'], folder]));
	// 复用 buildFolderXml：完整字段（ParentFolderId/DisplayName/计数）都可读
	assert.equal(rootById.get('inbox').DisplayName, 'Inbox');
	assert.equal(rootById.get('inbox').ParentFolderId['@_Id'], 'root');
	// root 的每个子文件夹（Distinguished + 账号文件夹）都带 TB 三件套，缺一即整树失败
	for (const folder of rootFolders) {
		const id = folder.FolderId['@_Id'];
		assert.equal(folder.ParentFolderId?.['@_Id'], 'root', `FindFolder 子项 ${id} 带 ParentFolderId@Id=root`);
		assert.ok(typeof folder.DisplayName === 'string' && folder.DisplayName.trim() !== '',
			`FindFolder 子项 ${id} 带非空 DisplayName`);
	}
	assert.equal(rootById.get('inbox').TotalCount, '3', 'inbox 计数 = 用户级聚合（101/102/103）');
	assert.equal(rootById.get('inbox').UnreadCount, '2');
	assert.equal(rootById.get('acct-1').DisplayName, 'tb-user@example.com', '账号文件夹 DisplayName = 账号邮箱');
	assert.equal(rootById.get('acct-1').TotalCount, '2', 'acct-1 = 101/102');
	assert.equal(rootById.get('acct-2').DisplayName, 'alias@example.com');
	assert.equal(rootById.get('acct-2').TotalCount, '1', 'acct-2 = 103');
	assert.ok(!root.xml.includes('stranger@example.com'), '不泄露他人账号（user 8 的 acct-3 不出现）');
	assert.ok(!rootIds.includes('acct-3') && !rootIds.includes('root'), '不含他人账号，也不把 root 当自己的子文件夹');

	// ①b root 别名 + IdOnly 的浅遍历请求：同样回全部子文件夹（BaseShape 忽略，多余字段无害）
	const rootAlias = await findFolder(db, 'tb-user@example.com', ['root'], { traversal: 'Deep', baseShape: 'IdOnly' });
	assert.equal(rootAlias.messages[0]['@_ResponseClass'], 'Success');
	assert.deepEqual(rootAlias.foldersOf(0).map((folder) => folder.FolderId['@_Id']), rootIds,
		'Traversal/BaseShape 不影响子文件夹集合');

	// ② 叶子父文件夹（inbox/sentitems/junkemail…）：Success + 空子列表（必须仍有 <m:Folders> 节点）
	for (const parent of ['inbox', 'sentitems', 'deleteditems', 'drafts', 'outbox', 'junkemail', 'acct-1']) {
		const leaf = await findFolder(db, 'tb-user@example.com', [parent]);
		assert.equal(leaf.messages[0]['@_ResponseClass'], 'Success', `${parent} 应 Success`);
		assert.equal(leaf.messages[0].ResponseCode, 'NoError');
		assert.deepEqual(leaf.foldersOf(0), [], `${parent} 子文件夹为空`);
		assert.equal(leaf.messages[0].RootFolder['@_TotalItemsInView'], '0');
		assert.ok(leaf.xml.includes('<m:RootFolder ') && leaf.xml.includes('<t:Folders></t:Folders>'),
			`${parent} 仍回 RootFolder/Folders 节点（客户端依赖其存在）`);
		assert.ok(!leaf.xml.includes('acct-1') && !leaf.xml.includes('acct-2'),
			`${parent} 空列表不夹带账号文件夹`);
	}

	// ③ 他人账号（acct-3 属于 user 8）→ Error + ErrorFolderNotFound（不泄露账号是否存在）
	const foreign = await findFolder(db, 'tb-user@example.com', ['acct-3']);
	assert.equal(foreign.messages.length, 1);
	assert.equal(foreign.messages[0]['@_ResponseClass'], 'Error');
	assert.equal(foreign.messages[0].ResponseCode, 'ErrorFolderNotFound');
	assert.equal(foreign.messages[0].RootFolder, undefined, '错误响应不带 RootFolder');
	assert.ok(!foreign.xml.includes('stranger@example.com'), '不泄露他人账号邮箱');

	// ④ 多个 ParentFolderIds：逐个 ResponseMessage（顺序与请求一致），非法 token 只影响自己那条
	const multi = await findFolder(db, 'tb-user@example.com', ['msgfolderroot', 'inbox', 'acct-3']);
	assert.equal(multi.messages.length, 3, '每个 ParentFolderId 一条 ResponseMessage');
	assert.deepEqual(multi.messages.map((message) => message['@_ResponseClass']), ['Success', 'Success', 'Error'],
		'顺序与请求一致：root 成功、inbox 成功、他人账号错误');
	assert.deepEqual(multi.foldersOf(0).map((folder) => folder.FolderId['@_Id']), rootIds, 'root 那条仍回全部子文件夹');
	assert.deepEqual(multi.foldersOf(1), [], 'inbox 那条空列表');
	assert.equal(multi.messages[2].ResponseCode, 'ErrorFolderNotFound');
	// 混装里同一个未知/越权 token 各占一条，不得被吞并成一条
	const dup = await findFolder(db, 'tb-user@example.com', ['bogus-folder', 'acct-3']);
	assert.deepEqual(dup.messages.map((message) => message['@_ResponseClass']), ['Error', 'Error']);
	assert.deepEqual(dup.messages.map((message) => message.ResponseCode),
		['ErrorFolderNotFound', 'ErrorFolderNotFound']);

	// ⑤ 别名登录（alias@example.com = account 2）：只看到该用户名下的账号文件夹（口算同 GetFolder 的可见域）
	const aliasRoot = await findFolder(db, 'alias@example.com', ['msgfolderroot']);
	assert.deepEqual(aliasRoot.foldersOf(0).map((folder) => folder.FolderId['@_Id']), rootIds,
		'同用户名下别名登录看到同样的子文件夹集合');

	// ⑥ 缺 ParentFolderIds → Fault（ErrorInvalidRequest），不静默回空
	const noParents = await (await post(db, 'tb-user@example.com',
		envelope('<m:FindFolder Traversal="Shallow"><m:FolderShape><t:BaseShape>IdOnly</t:BaseShape></m:FolderShape>' +
			'<m:ParentFolderIds></m:ParentFolderIds></m:FindFolder>'))).text();
	assert.equal(XMLValidator.validate(noParents), true, 'Fault 响应必须良构');
	assert.ok(noParents.includes('<soap:Fault>') && noParents.includes('ErrorInvalidRequest'),
		'缺 ParentFolderIds → Fault ErrorInvalidRequest');
});

// ------- 33. TB 严格反序列化：逐条计数、Items>ItemId、Changes 恒存在、MimeContent 无换行 -------

testCase('33. TB 严格反序列化：UpdateItem/DeleteItem 每条一条、CreateItem Items>ItemId、Changes 恒存在、MimeContent 无换行', async () => {
	ensureNodeResolveHook();
	const { default: ewsApp } = await import('../src/ews/router.js');

	const jwtSecret = 'unit-test-jwt-secret';
	const password = 'secret-password';
	const mail = 'tb-user@example.com';
	const kvStore = new Map();
	// 认证缓存（同 29/31）+ setting（DeleteItem → emailService.delete 会读它）
	kvStore.set('setting:', JSON.stringify({ emailPrefixFilter: '', syncDelete: 1 }));
	kvStore.set('ews-auth:' + createHash('sha256').update(`${jwtSecret}:${mail}:${password}`).digest('hex'),
		JSON.stringify({ userId: 7, email: mail, status: 0, isDel: 0 }));
	const kv = {
		get: async (key) => (kvStore.has(key) ? JSON.parse(kvStore.get(key)) : null),
		put: async () => {},
		delete: async () => {}
	};

	const post = (db, body) => ewsApp.fetch(new Request('https://mail.example.com/EWS/Exchange.asmx', {
		method: 'POST',
		headers: {
			Authorization: 'Basic ' + Buffer.from(`${mail}:${password}`).toString('base64'),
			'Content-Type': 'text/xml; charset=utf-8'
		},
		body
	}), { jwt_secret: jwtSecret, kv, db: sqliteD1(db), domain: '["example.com"]' }, {});

	const envelope = (body) => `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
  <soap:Body>${body}</soap:Body>
</soap:Envelope>`;

	/** 每个 m:XxxResponseMessage 都有合法 ResponseClass；响应中不得出现 DescriptiveLinkKey（会破坏 TB 同步解析） */
	function assertResponseClasses(xml, label) {
		const tags = xml.match(/<m:\w+ResponseMessage[^>]*>/g) || [];
		assert.ok(tags.length > 0, `${label}: 至少一条 ResponseMessage`);
		for (const tag of tags) {
			assert.ok(/ResponseClass="(Success|Error|Warning)"/.test(tag), `${label}: ${tag} 带 ResponseClass`);
		}
		assert.ok(!xml.includes('DescriptiveLinkKey'), `${label}: 不含 DescriptiveLinkKey`);
	}

	const db = seedEwsDb();

	// ① UpdateItem：2 个 ItemChange → 2 条 ResponseMessage（1 Success + 1 ErrorItemNotFound）
	const UPDATE = envelope('<m:UpdateItem ConflictResolution="AlwaysOverwrite" MessageDisposition="SaveOnly">' +
		'<m:ItemChanges>' +
		'<t:ItemChange><t:ItemId Id="102"/><t:Updates><t:SetItemField><t:FieldURI FieldURI="message:IsRead"/>' +
		'<t:Message><t:IsRead>true</t:IsRead></t:Message></t:SetItemField></t:Updates></t:ItemChange>' +
		'<t:ItemChange><t:ItemId Id="999"/><t:Updates><t:SetItemField><t:FieldURI FieldURI="message:IsRead"/>' +
		'<t:Message><t:IsRead>true</t:IsRead></t:Message></t:SetItemField></t:Updates></t:ItemChange>' +
		'</m:ItemChanges></m:UpdateItem>');
	const updateXml = await (await post(db, UPDATE)).text();
	assert.equal(XMLValidator.validate(updateXml), true, 'UpdateItem 响应必须良构');
	assertSoapEnvelope(updateXml, 'UpdateItem');
	assert.ok(!updateXml.includes('<soap:Fault>'), 'UpdateItem 不应抛 Fault');
	assertResponseClasses(updateXml, 'UpdateItem');
	const updateMessages = asArray(parseBack.parse(updateXml)
		.Envelope.Body.UpdateItemResponse.ResponseMessages.UpdateItemResponseMessage);
	assert.equal(updateMessages.length, 2, '每个 ItemChange 一条 ResponseMessage（TB 校验数量）');
	assert.deepEqual(updateMessages.map((message) => message['@_ResponseClass']), ['Success', 'Error'],
		'顺序 = ItemChanges 顺序');
	assert.equal(updateMessages[0].ResponseCode, 'NoError');
	assert.equal(updateMessages[0].Items.Message.ItemId['@_Id'], '102', '成功那条含更新后的 ItemId');
	assert.ok(String(updateMessages[0].Items.Message.ItemId['@_ChangeKey']).length > 0, 'ItemId 带 ChangeKey');
	assert.equal(updateMessages[1].ResponseCode, 'ErrorItemNotFound');
	assert.ok(textOf(updateMessages[1].MessageText).includes('999'), '失败那条带 MessageText');
	assert.equal(db.prepare('SELECT unread FROM email WHERE email_id = 102').get().unread, 1, 'IsRead=true 落库');

	// ② DeleteItem：2 个 ItemId → 2 条 ResponseMessage；ErrorItemNotFound 只影响自己那条（TB 容忍）
	const DELETE = envelope('<m:DeleteItem DeleteType="MoveToDeletedItems">' +
		'<m:ItemIds><t:ItemId Id="101"/><t:ItemId Id="999"/></m:ItemIds></m:DeleteItem>');
	const deleteXml = await (await post(db, DELETE)).text();
	assert.equal(XMLValidator.validate(deleteXml), true, 'DeleteItem 响应必须良构');
	assertSoapEnvelope(deleteXml, 'DeleteItem');
	assertResponseClasses(deleteXml, 'DeleteItem');
	const deleteMessages = asArray(parseBack.parse(deleteXml)
		.Envelope.Body.DeleteItemResponse.ResponseMessages.DeleteItemResponseMessage);
	assert.equal(deleteMessages.length, 2, '每个 ItemId 一条 ResponseMessage（TB 校验数量）');
	assert.deepEqual(deleteMessages.map((message) => message['@_ResponseClass']), ['Success', 'Error'],
		'顺序 = ItemIds 顺序');
	assert.equal(deleteMessages[1].ResponseCode, 'ErrorItemNotFound');
	assert.ok(textOf(deleteMessages[1].MessageText).includes('999'), '未找到的 Id 带 MessageText');
	assert.equal(db.prepare('SELECT trash FROM email WHERE email_id = 101').get().trash, 1, '存在的 Id 走软删除');
	assert.equal(db.prepare('SELECT trash FROM email WHERE email_id = 999').get(), undefined);

	// ③ CreateItem 响应结构：TB 从 m:Items 里取 ItemId（缺失 → MissingIdInResponse）
	const createXml = operationResponse('CreateItem',
		responseMessage('CreateItem', { body: createItemItemsXml(4242, '2026-10-01 10:00:00') }));
	assertWellFormed(createXml);
	assertSoapEnvelope(createXml, 'CreateItem');
	const createMessage = parseBack.parse(createXml).Envelope.Body.CreateItemResponse.ResponseMessages.CreateItemResponseMessage;
	assert.equal(createMessage['@_ResponseClass'], 'Success');
	assert.equal(createMessage.Items.Message.ItemId['@_Id'], '4242', 'm:Items > t:Message > t:ItemId 可达');
	assert.equal(createMessage.Items.Message.ItemId['@_ChangeKey'], '2026-10-01 10:00:00');

	// ④ MimeContent：连续 base64（无 CRLF 折行），且不带 InternetMessageHeaders（空 header 会让 TB<149 崩溃）
	const folded = buildMimeBase64({
		from: { email: 'a@example.com', name: 'A' },
		to: [{ email: 'b@example.com' }],
		subject: 'folded',
		dateMs: Date.UTC(2026, 9, 1, 12, 0, 0),
		text: 'hello'
	});
	assert.ok(folded.includes('\r\n'), 'buildMimeBase64 输出本身是 76 列折行');
	assert.ok(folded.length > 76, '样本足够长以触发折行');
	const mimeItem = buildItemXml(MAIL_ROW, { changeKey: 'x', mimeContent: folded });
	assert.ok(!mimeItem.includes('InternetMessageHeader'), '不输出 InternetMessageHeaders（TB 空 header 反序列化崩溃的根因）');
	const mimeText = (mimeItem.match(/<t:MimeContent CharacterSet="UTF-8">([\s\S]*?)<\/t:MimeContent>/) || [])[1];
	assert.ok(typeof mimeText === 'string' && mimeText.length > 76, 'MimeContent 元素存在且有内容');
	assert.ok(!/[\s]/.test(mimeText), 'MimeContent 内是连续 base64（无换行/空白）');
	assert.ok(mimeText.includes('+') || mimeText.includes('/') || /[A-Za-z0-9]/.test(mimeText), '合法 base64 字符集');
	assert.ok(Buffer.from(mimeText, 'base64').toString('utf8').startsWith('MIME-Version: 1.0'),
		'去掉折行后仍能解码回 MIME 原文');

	// ⑤ 三件套恒存在：SyncFolderHierarchy 已有 SyncState → 空 Changes
	const hierarchyXml = await (await post(db, envelope('<m:SyncFolderHierarchy>' +
		'<m:FolderShape><t:BaseShape>AllProperties</t:BaseShape></m:FolderShape>' +
		`<m:SyncState>${encodeSyncState(emptySyncState())}</m:SyncState>` +
		'</m:SyncFolderHierarchy>'))).text();
	assert.equal(XMLValidator.validate(hierarchyXml), true, 'SyncFolderHierarchy 响应必须良构');
	const hierarchyMessage = parseBack.parse(hierarchyXml)
		.Envelope.Body.SyncFolderHierarchyResponse.ResponseMessages.SyncFolderHierarchyResponseMessage;
	assert.ok(textOf(hierarchyMessage.SyncState).length > 0, 'SyncState 非空');
	assert.equal(hierarchyMessage.IncludesLastFolderInRange, 'true');
	assert.ok('Changes' in hierarchyMessage, 'Changes 元素恒存在（TB 硬校验）');
	assert.equal(hierarchyMessage.Changes, '', '已有 SyncState → Changes 空元素');
	assert.ok(hierarchyXml.includes('<m:Changes></m:Changes>'), '空 Changes 以元素形式输出（不是省略）');

	// ⑥ SyncFolderItems：drafts（非邮件文件夹）与「邮件文件夹但本轮无变更」都必须输出空 Changes
	const SYNC = (folder, state = '') => envelope('<m:SyncFolderItems>' +
		'<m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape>' +
		`<m:SyncFolderId><t:DistinguishedFolderId Id="${folder}"/></m:SyncFolderId>` +
		`<m:SyncState>${state}</m:SyncState>` +
		'<m:MaxChangesReturned>256</m:MaxChangesReturned>' +
		'</m:SyncFolderItems>');
	const parseSyncMessage = (xml, label) => {
		assert.equal(XMLValidator.validate(xml), true, `${label} 响应必须良构`);
		assertSoapEnvelope(xml, 'SyncFolderItems');
		return parseBack.parse(xml).Envelope.Body.SyncFolderItemsResponse.ResponseMessages.SyncFolderItemsResponseMessage;
	};

	const draftsMessage = parseSyncMessage(await (await post(db, SYNC('drafts'))).text(), 'SyncFolderItems(drafts)');
	assert.ok(textOf(draftsMessage.SyncState).length > 0, 'drafts: SyncState 非空');
	assert.equal(draftsMessage.IncludesLastItemInRange, 'true');
	assert.ok('Changes' in draftsMessage && draftsMessage.Changes === '', 'drafts: Changes 空元素恒存在');

	// 水位已到最新（无任何增量）→ Changes 仍必须输出（修复前该分支整个元素缺失）
	const quiet = encodeSyncState({ v: 1, wm: '9999-12-31 23:59:59', wid: 0, cur: null });
	const quietXml = await (await post(db, SYNC('inbox', quiet))).text();
	const quietMessage = parseSyncMessage(quietXml, 'SyncFolderItems(inbox/quiet)');
	assert.ok('Changes' in quietMessage && quietMessage.Changes === '', 'inbox 无变更：Changes 空元素恒存在');
	assert.equal(quietMessage.IncludesLastItemInRange, 'true', 'more=false 时必须 true');
	assert.ok(!quietXml.includes('<t:Create>'), '无变更不产出 Create');

	// ⑦ 翻页语义：60 封新邮件 + MaxChangesReturned=256（服务器 clamp 到 50）
	//    首页 50 条 + IncludesLastItemInRange=false，续页拿剩余 + true
	const pageDb = seedEwsDb();
	for (let i = 0; i < 60; i++) {
		pageDb.prepare(`INSERT INTO email (email_id, account_id, user_id, type, unread, trash, is_del, subject, send_email, create_time, update_time)
			VALUES (?, 1, 7, 0, 0, 0, 0, 'bulk', 'b@x.y', '2026-08-01 00:00:00', ?)`)
			.run(500 + i, `2026-08-01 00:${String(i).padStart(2, '0')}:00`);
	}
	const page1Message = parseSyncMessage(await (await post(pageDb, SYNC('inbox'))).text(), 'SyncFolderItems(page1)');
	const page1Creates = asArray(page1Message.Changes.Create).flatMap((node) => asArray(node.Message));
	assert.equal(page1Creates.length, 50, 'MaxChangesReturned=256 被 clamp 到 50（服务器可回更少）');
	assert.equal(page1Message.IncludesLastItemInRange, 'false', '还有下一页 → false');
	assert.ok(textOf(page1Message.SyncState).length > 0, '翻页中 SyncState 非空');
	const page2Message = parseSyncMessage(
		await (await post(pageDb, SYNC('inbox', textOf(page1Message.SyncState)))).text(), 'SyncFolderItems(page2)');
	const page2Creates = asArray(page2Message.Changes.Create).flatMap((node) => asArray(node.Message));
	assert.equal(page2Creates.length, 13, '续页拿剩余 13 条（60 bulk + 3 seed - 50）');
	assert.equal(page2Message.IncludesLastItemInRange, 'true', '发完 → true');
	const seen = new Set([...page1Creates, ...page2Creates].map((item) => Number(item.ItemId['@_Id'])));
	assert.equal(seen.size, 63, '两页合计 63 封、不重不漏');
});

// ---- 34. MimeContent 超限内嵌图：正文可见占位（超限图跳过 + GetAttachment 文案） ----

testCase('34. 超限内嵌图：MIME 里无该图 part、正文显示含阈值的占位；GetAttachment 超限文案指向网页版', async () => {
	ensureNodeResolveHook();
	const { default: ewsApp } = await import('../src/ews/router.js');

	const jwtSecret = 'unit-test-jwt-secret';
	const password = 'secret-password';
	const mail = 'tb-user@example.com';
	const kvStore = new Map();
	// setting（r2Service.storageType 经 settingService 读它）+ 认证缓存
	kvStore.set('setting:', JSON.stringify({ emailPrefixFilter: '' }));
	kvStore.set('ews-auth:' + createHash('sha256').update(`${jwtSecret}:${mail}:${password}`).digest('hex'),
		JSON.stringify({ userId: 7, email: mail, status: 0, isDel: 0 }));
	const kv = {
		get: async (key) => (kvStore.has(key) ? JSON.parse(kvStore.get(key)) : null),
		put: async () => {},
		delete: async () => {}
	};

	// R2 桩：1.5MB 内嵌图（超默认 1MB 上限）+ 两张 8 字节小图（供附件账本护栏用例）；
	// fetched 记录被读取的 key：被跳过的附件必须在读 COS 之前就跳过（CPU/IO 护栏）
	const bigBytes = new Uint8Array(1.5 * 1024 * 1024).fill(0x41);
	const smallBytes = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3, 4]);
	const objects = new Map([
		['attachments/big.png', bigBytes],
		['attachments/small.png', smallBytes],
		['attachments/s1.png', smallBytes],
		['attachments/s2.png', smallBytes]
	]);
	const fetched = [];
	const r2 = {
		get: async (key) => {
			fetched.push(key);
			const bytes = objects.get(key);
			return bytes ? { arrayBuffer: async () => bytes.buffer } : null;
		}
	};

	const db = seedEwsDb();
	// 内嵌图行：type=1（EMBED）；库内正文以 {{domain}}attachments/<key> 引用
	db.prepare(`INSERT INTO email (email_id, account_id, user_id, type, unread, trash, is_del, subject, send_email, create_time, update_time, content)
	            VALUES (201, 1, 7, 0, 1, 0, 0, 'inline oversize', 'a@x.y', '2026-10-01 08:00:00', '2026-10-01 08:00:00', ?)`)
		.run('<p>大图：</p><img src="{{domain}}attachments/big.png">' +
			'<p>小图：</p><img class="thumb" width="40" src="{{domain}}attachments/small.png">');
	db.prepare(`INSERT INTO attachments (att_id, user_id, email_id, account_id, key, filename, mime_type, size, type, content_id) VALUES
	            (1, 7, 201, 1, 'attachments/big.png', 'big.png', 'image/png', ?, 1, '<big@cloud>'),
	            (2, 7, 201, 1, 'attachments/small.png', 'small.png', 'image/png', ?, 1, 'small@cloud')`)
		.run(bigBytes.length, smallBytes.length);
	// 邮件 202：两张小图，用于「本次响应附件账本超限（非单附件超限）」的跳过路径
	db.prepare(`INSERT INTO email (email_id, account_id, user_id, type, unread, trash, is_del, subject, send_email, create_time, update_time, content)
	            VALUES (202, 1, 7, 0, 1, 0, 0, 'inline budget', 'a@x.y', '2026-10-01 08:01:00', '2026-10-01 08:01:00', ?)`)
		.run('<img src="{{domain}}attachments/s1.png"><img src="{{domain}}attachments/s2.png">');
	db.prepare(`INSERT INTO attachments (att_id, user_id, email_id, account_id, key, filename, mime_type, size, type, content_id) VALUES
	            (3, 7, 202, 1, 'attachments/s1.png', 's1.png', 'image/png', ?, 1, 's1@cloud'),
	            (4, 7, 202, 1, 'attachments/s2.png', 's2.png', 'image/png', ?, 1, 's2@cloud')`)
		.run(smallBytes.length, smallBytes.length);

	const post = (body, extraEnv = {}) => ewsApp.fetch(new Request('https://mail.example.com/EWS/Exchange.asmx', {
		method: 'POST',
		headers: {
			Authorization: 'Basic ' + Buffer.from(`${mail}:${password}`).toString('base64'),
			'Content-Type': 'text/xml; charset=utf-8'
		},
		body
	}), { jwt_secret: jwtSecret, kv, db: sqliteD1(db), domain: '["example.com"]', r2, ...extraEnv }, {});

	const envelope = (body) => `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
  <soap:Body>${body}</soap:Body>
</soap:Envelope>`;

	const getItemWithMime = (id) => envelope('<m:GetItem>' +
		'<m:ItemShape><t:BaseShape>Default</t:BaseShape><t:IncludeMimeContent>true</t:IncludeMimeContent></m:ItemShape>' +
		`<m:ItemIds><t:ItemId Id="${id}"/></m:ItemIds>` +
		'</m:GetItem>');
	const mimeOf = (xml) => {
		assert.equal(XMLValidator.validate(xml), true, 'GetItem 响应必须良构');
		assertSoapEnvelope(xml, 'GetItem');
		assert.ok(!xml.includes('<soap:Fault>'), 'GetItem 不应抛 Fault');
		const message = parseBack.parse(xml).Envelope.Body.GetItemResponse.ResponseMessages.GetItemResponseMessage;
		const mime = textOf(message.Items.Message.MimeContent);
		assert.ok(mime.length > 0, 'MimeContent 已重建');
		return Buffer.from(mime.replace(/\s+/g, ''), 'base64').toString('utf8');
	};

	// ① 单附件超限（1.5MB > 1MB）：该图 part 整体不进 MIME，正文里换成可见占位（带阈值 1MB）
	const rawMime = mimeOf(await (await post(getItemWithMime(201))).text());
	assert.ok(rawMime.includes('Content-ID: <small@cloud>'), '小图 part 正常保留');
	assert.ok(!rawMime.includes('big@cloud') && !rawMime.includes('big.png'),
		'超限内嵌图整体不进 MIME（无 Content-ID / 文件名残留）');
	assert.deepEqual(fetched, ['attachments/small.png'], '超限图在读 COS 前就被跳过（不产生字节读取）');

	const bodyText = decodeMimeBodies(rawMime);
	assert.ok(!bodyText.includes('{{domain}}attachments/big.png'), '超限图引用不残留库内占位符');
	assert.ok(!bodyText.includes('cid:big@cloud'), '超限图引用不残留 cid');
	assert.ok(bodyText.includes('<p style="border:1px dashed #999;padding:8px;color:#666;">' +
		'[图片过大（>1MB），此客户端无法加载，请使用网页版查看]</p>'),
		'超限图位置显示带阈值的可见占位文案（整段 <img ...> 被替换）');
	assert.ok(bodyText.includes('cid:small@cloud'), '小图的 cid 引用照常替换');

	// ② 本次响应附件账本超限（limit=10 字节，第二张图 8+8 > 10）：同样产出占位（阈值仍是单附件配置 1MB）
	const budgetMime = mimeOf((await (await post(getItemWithMime(202), { EWS_MAX_TOTAL_ATT_BYTES: '10' })).text()));
	assert.ok(budgetMime.includes('Content-ID: <s1@cloud>') && !budgetMime.includes('s2@cloud'),
		'账本超限后剩余内嵌图被跳过');
	assert.ok(decodeMimeBodies(budgetMime).includes('[图片过大（>1MB）'), '账本超限的内嵌图同样显示占位');
	assert.deepEqual(fetched, ['attachments/small.png', 'attachments/s1.png'], '账本超限的图同样在读 COS 前跳过');

	// ③ 纯函数：带任意属性的 <img ...> 整段替换；未被跳过的 <img> 原样保留；阈值随配置动态显示
	const replaced = replaceInlineImagesWithPlaceholder(
		'<img class="a" width="10" src="{{domain}}attachments/big.png" data-x="1">' +
		'<IMG SRC=\'cid:big@cloud\'>' +
		'<img src="{{domain}}attachments/small.png">',
		new Set(['cid:big@cloud', '{{domain}}attachments/big.png']), 1024 * 1024);
	assert.equal((replaced.match(/图片过大（>1MB）/g) || []).length, 2, '两种引用形态的整个 <img ...> 都被替换');
	assert.ok(!replaced.includes('<img class="a"') && !replaced.includes('<IMG SRC'), '被替换的 img 标签不残留');
	assert.ok(replaced.includes('<img src="{{domain}}attachments/small.png">'), '未被跳过的图片原样保留');
	assert.ok(oversizeInlinePlaceholderHtml(5 * 1024 * 1024).includes('>5MB'), '阈值随 EWS_MAX_ATT_BYTES 动态显示');

	// ④ 附件超限（非内嵌）：GetAttachment 的 Fault 文案明确指引用户用 Web 端下载
	const attXml = await (await post(envelope('<m:GetAttachment>' +
		'<m:AttachmentIds><t:AttachmentId Id="1"/></m:AttachmentIds>' +
		'</m:GetAttachment>'))).text();
	assert.equal(XMLValidator.validate(attXml), true, 'Fault 响应必须良构');
	assert.ok(attXml.includes('<soap:Fault>') && attXml.includes('ErrorInvalidRequest'), '超限附件 → Fault');
	assert.ok(attXml.includes('Please download it from the CloudMail web client'), 'Fault 文案指引用户用 Web 端下载');
});

// ---- 35. CreateItem 发件账号路由：From（MimeContent/结构化）→ 用户名下账号；越权拒绝；缺省回退 ----

testCase('35. CreateItem：From 路由发件账号（MimeContent/结构化/NOCASE）、越权拒绝、缺省回退同名账号', async () => {
	ensureNodeResolveHook();
	const { dispatch, EwsFault } = await import('../src/ews/handlers.js');
	// 生产 handlers.js 里的 email-service 已被 resolve hook 换成桩：sendCalls = 发信调用收到的账号参数
	const { sendCalls, resetSendCalls } = await import(EMAIL_SERVICE_STUB_URL);

	const user = { userId: 7, email: 'tb-user@example.com' };
	const db = seedEwsDb();
	// user 7 名下追加 ciallo.sale 发件账号（account 2 = alias@example.com 用作「本人另一账号」；
	// account 3 = stranger@example.com 属于 user 8，用作越权样本）
	db.prepare(`INSERT INTO account (account_id, email, name, user_id) VALUES (4, 'contact@ciallo.sale', 'Ciallo', 7)`).run();
	const context = { env: { db: sqliteD1(db) } };

	const envelope = (body) => `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
  <soap:Body>${body}</soap:Body>
</soap:Envelope>`;

	const messageWithTo = (extra = '') => '<t:Message>' +
		'<t:ToRecipients><t:Mailbox><t:EmailAddress>rcpt@example.net</t:EmailAddress></t:Mailbox></t:ToRecipients>' +
		'<t:Subject>route test</t:Subject>' +
		'<t:Body BodyType="Text">hello</t:Body>' + extra + '</t:Message>';
	const mimeMessage = (mime) => `<t:Message><t:MimeContent CharacterSet="UTF-8">${mime}</t:MimeContent></t:Message>`;
	const createItem = (messageXml, disposition) => envelope(
		`<m:CreateItem MessageDisposition="${disposition}">` +
		`<m:Items>${messageXml}</m:Items>` +
		'</m:CreateItem>');

	/** 发一封 CreateItem（SendOnly），返回响应 XML；sendCalls 记录 stub 收到的账号参数 */
	async function send(messageXml, disposition = 'SendOnly') {
		resetSendCalls();
		const parsed = parseSoapRequest(createItem(messageXml, disposition));
		assert.equal(parsed.error, undefined, 'CreateItem 请求必须是合法 SOAP');
		assert.equal(parsed.operation, 'CreateItem');
		return dispatch(context, parsed, user);
	}

	// ⓪ 纯函数 parseMimeFrom：base64（含折行）→ MIME 头 From 地址（UTF-8 / 裸地址 / 容错）
	const mimeB64 = (raw) => base64EncodeBytes(new TextEncoder().encode(raw)).replace(/(.{24})/g, '$1\r\n');
	assert.equal(parseMimeFrom(mimeB64('From: "Ciallo 中文" <contact@ciallo.sale>\r\nTo: a@b.c\r\nSubject: x\r\n\r\nHi')),
		'contact@ciallo.sale', 'base64 折行 + 非 ASCII 显示名');
	assert.equal(parseMimeFrom(mimeB64('From: =?UTF-8?q?Ciallo_=E4=B8=AD=E6=96=87?= <contact@ciallo.sale>\r\n\r\n')),
		'contact@ciallo.sale', 'RFC2047 显示名');
	assert.equal(parseMimeFrom(mimeB64('From: contact@ciallo.sale\r\n\r\nbody')), 'contact@ciallo.sale', '裸地址');
	assert.equal(parseMimeFrom(mimeB64('Subject: no from\r\n\r\nFrom: fake@evil.test')), '', '正文里的 From: 文本不算');
	assert.equal(parseMimeFrom(mimeB64('From: \r\n\r\n')), '');
	assert.equal(parseMimeFrom(''), '');
	assert.equal(parseMimeFrom('!!!not-base64!!!'), '', '非法 base64 容错为空');

	// ① TB 145 形态：仅 t:MimeContent（整封 MIME），From=contact@ciallo.sale → ciallo 账号发信
	const cialloMime = buildMimeBase64({
		from: { email: 'contact@ciallo.sale', name: 'Ciallo 中文' },
		to: [{ email: 'rcpt@example.net' }],
		subject: 'mime route',
		dateMs: Date.UTC(2026, 9, 1, 12, 0, 0),
		text: 'hello from mime'
	});
	assert.ok(cialloMime.includes('\r\n'), '前置条件：base64 是 76 列折行形态（cleanBase64 需去空白）');
	const xml1 = await send(mimeMessage(cialloMime));
	assert.equal(XMLValidator.validate(xml1), true, 'CreateItem 响应必须良构');
	assertSoapEnvelope(xml1, 'CreateItem');
	assert.ok(!xml1.includes('<soap:Fault>'), '不应 Fault');
	assert.equal(sendCalls.length, 1, 'emailService.send 被调用一次');
	assert.equal(sendCalls[0].userId, 7);
	assert.equal(sendCalls[0].params.accountId, 4, 'MimeContent From=contact@ciallo.sale → ciallo 账号（account 4）');
	assert.deepEqual(sendCalls[0].params.receiveEmail, ['rcpt@example.net'], 'MimeContent 的 To 被解析成收件人');
	assert.equal(sendCalls[0].params.sendType, 'send');
	assert.ok(xml1.includes('<t:ItemId Id="4242"'), '响应带 stub 返回的 ItemId');

	// ② MimeContent From=本人另一账号（大小写混写）→ NOCASE 命中 account 2
	const aliasMime = buildMimeBase64({
		from: { email: 'Alias@Example.COM', name: 'Alias' },
		to: [{ email: 'rcpt@example.net' }],
		subject: 'alias route',
		dateMs: Date.UTC(2026, 9, 1, 12, 0, 0),
		text: 'hello alias'
	});
	await send(mimeMessage(aliasMime));
	assert.equal(sendCalls[0].params.accountId, 2, 'MimeContent From=Alias@Example.COM → 名下 alias 账号（NOCASE）');

	// ③ From 不属于当前用户（他人账号 / 不存在地址）→ EwsFault，且绝不调用发信
	for (const foreign of ['stranger@example.com', 'nobody@not-owned.test']) {
		const foreignMime = buildMimeBase64({
			from: { email: foreign },
			to: [{ email: 'rcpt@example.net' }],
			subject: 'reject',
			dateMs: Date.UTC(2026, 9, 1, 12, 0, 0),
			text: 'reject me'
		});
		await assert.rejects(() => send(mimeMessage(foreignMime)), (error) => {
			assert.ok(error instanceof EwsFault, `From=${foreign} 必须是 EwsFault`);
			assert.equal(error.responseCode, 'ErrorInvalidRequest');
			assert.ok(error.message.includes('不属于当前账户'), 'faultstring 说明地址不属于当前账户');
			return true;
		});
		assert.equal(sendCalls.length, 0, `From=${foreign} 不调用 emailService.send（禁止冒用身份）`);
	}

	// ④ 结构化 t:From / t:Sender（部分客户端形态）→ 同样的路由（含大小写不敏感）
	const fromXml = await send(messageWithTo(
		'<t:From><t:Mailbox><t:Name>Ciallo</t:Name><t:EmailAddress>CONTACT@CIALLO.SALE</t:EmailAddress></t:Mailbox></t:From>'));
	assert.ok(!fromXml.includes('<soap:Fault>'));
	assert.equal(sendCalls[0].params.accountId, 4, '结构化 t:From（NOCASE）→ ciallo 账号');
	await send(messageWithTo(
		'<t:Sender><t:Mailbox><t:EmailAddress>contact@ciallo.sale</t:EmailAddress></t:Mailbox></t:Sender>'));
	assert.equal(sendCalls[0].params.accountId, 4, 't:Sender 与 t:From 同优先级');

	// ④b 结构化 To/Body 存在（不触发整封 PostalMime 解析）+ From 只在 MimeContent 头里 → parseMimeFrom 兜底
	const partialXml = await send(messageWithTo(`<t:MimeContent CharacterSet="UTF-8">${cialloMime}</t:MimeContent>`));
	assert.ok(!partialXml.includes('<soap:Fault>'));
	assert.equal(sendCalls[0].params.accountId, 4, '结构化字段未覆盖 From 时从 MimeContent 头取（兜底路由）');
	assert.equal(sendCalls[0].params.text, 'hello', '结构化 Body 保持原样');
	assert.deepEqual(sendCalls[0].params.receiveEmail, ['rcpt@example.net'], '结构化 To 保持原样');

	// ⑤ From 缺失 → 回退登录邮箱同名账号（现状回归）
	await send(messageWithTo());
	assert.equal(sendCalls[0].params.accountId, 1, '无 From → 登录邮箱同名账号（account 1）');

	// ⑤b 登录邮箱名下没有任何账号（ghost）且无 From → 仍按现状报「无可用发件账号」
	await assert.rejects(
		() => dispatch(context, parseSoapRequest(createItem(messageWithTo(), 'SendOnly')), { userId: 7, email: 'ghost@example.com' }),
		(error) => {
			assert.ok(error instanceof EwsFault);
			assert.equal(error.responseCode, 'ErrorInvalidRequest');
			assert.ok(error.message.includes('No sender account available'));
			return true;
		});

	// ⑥ SaveOnly 草稿行为保持现状（仍拒绝，不扩展草稿功能）
	await assert.rejects(() => send(messageWithTo(), 'SaveOnly'), (error) => {
		assert.ok(error instanceof EwsFault);
		assert.equal(error.responseCode, 'ErrorInvalidRequest');
		assert.ok(error.message.includes('Drafts are not supported'));
		return true;
	});
});

// ---- 36. 防白屏降级阶梯：跳过项占位清单 + 总量自查 + 构建异常极简兜底 ----

testCase('36. 防白屏降级阶梯：多图/普通附件跳过进占位清单、MimeContent 解码后 ≤1.4×预算；内部异常仍 Success 极简 MIME', async () => {
	ensureNodeResolveHook();
	const { default: ewsApp } = await import('../src/ews/router.js');

	// 先做纯函数断言：清单格式（转义 + 大小人性化）、UTF-8 截断、常量默认值
	assert.equal(EWS_MIME_SAFE_TOTAL, 1024 * 1024, 'EWS_MIME_SAFE_TOTAL 默认 1MB');
	assert.equal(EWS_HTML_MAX_BYTES, 256 * 1024, 'HTML 正文截断阈值 256KB');
	assert.equal(ewsMimeSafeTotal({}), EWS_MIME_SAFE_TOTAL);
	assert.equal(ewsMimeSafeTotal({ EWS_MIME_SAFE_TOTAL: '524288' }), 524288);
	assert.equal(ewsMaxTotalAttBytes({}), EWS_MIME_SAFE_TOTAL, '附件账本默认对齐 CPU 安全预算（不再 2×单附件）');
	assert.equal(ewsMaxTotalAttBytes({ EWS_MAX_TOTAL_ATT_BYTES: '4096' }), 4096, 'env 仍可显式调小/调大');
	assert.equal(humanFileSize(2202009), '2.1MB');
	assert.equal(humanFileSize(1024), '1KB');
	assert.equal(humanFileSize(0), '未知大小');
	const manifestHtml = skippedAttachmentsHtml([{ filename: 'a<b&c>.png', size: 2202009 }, { filename: 'report.pdf', size: 3.4 * 1024 * 1024 }]);
	assert.ok(manifestHtml.includes('• a&lt;b&amp;c&gt;.png（2.1MB）'), 'HTML 清单：文件名转义 + 大小 MB');
	assert.ok(manifestHtml.includes('• report.pdf（3.4MB）'));
	assert.ok(manifestHtml.startsWith('<p style="border:1px dashed #999;padding:8px;color:#666;">[以下内容过大，此客户端无法加载]<br>'));
	assert.ok(skippedAttachmentsText([{ filename: 'a<b>.png', size: 1024 }]).includes('• a<b>.png（1KB）'), '纯文本清单不转义');
	assert.equal(skippedAttachmentsHtml([]), '', '无跳过项不产出清单');
	const cut = truncateUtf8Bytes('中'.repeat(100), 10);
	assert.equal(cut.truncated, true);
	assert.ok(Buffer.byteLength(cut.text, 'utf8') <= 10, '按 UTF-8 字节截断');
	assert.equal(truncateUtf8Bytes('abc', 10).truncated, false);
	assert.equal(truncateUtf8Bytes('abc', 2).text, 'ab');
	assert.equal(truncateUtf8Bytes('a😀b', 5).text, 'a😀', '不截出半个代理对');
	// 回归：>32KB 的分块 base64 不得在中段出现补位符（曾导致 atob/TB 在 '=' 处截断 → 白屏）
	const chunked = base64Encode(new Uint8Array(100 * 1024).fill(0x42)).replace(/\s+/g, '');
	assert.ok(!chunked.slice(0, -2).includes('='), '分块 base64 中段无补位符');
	assert.equal(Buffer.from(chunked, 'base64').length, 100 * 1024, '分块 base64 解码字节数精确');

	const jwtSecret = 'unit-test-jwt-secret';
	const password = 'secret-password';
	const mail = 'tb-user@example.com';
	const kvStore = new Map();
	kvStore.set('setting:', JSON.stringify({ emailPrefixFilter: '' }));
	kvStore.set('ews-auth:' + createHash('sha256').update(`${jwtSecret}:${mail}:${password}`).digest('hex'),
		JSON.stringify({ userId: 7, email: mail, status: 0, isDel: 0 }));
	const kv = {
		get: async (key) => (kvStore.has(key) ? JSON.parse(kvStore.get(key)) : null),
		put: async () => {},
		delete: async () => {}
	};

	// 900KB 内嵌图 ×2（单张 < 1MB 单附件上限；两张累计 1.8MB > 1MB 账本 → 第二张必须跳过）
	const imgBytes = new Uint8Array(900 * 1024).fill(0x42);
	const pdfBytes = new Uint8Array(2 * 1024 * 1024).fill(0x25); // 2MB 普通附件 > 单附件上限 → 跳过 + 清单
	const boomBytes = new Uint8Array(1024).fill(0x7f);           // 正常大小，但 COS 读取抛错 → 极简兜底
	const objects = new Map([
		['attachments/i1.png', imgBytes],
		['attachments/i2.png', imgBytes],
		['attachments/report.pdf', pdfBytes],
		['attachments/boom.bin', boomBytes]
	]);
	const fetched = [];
	const r2 = {
		get: async (key) => {
			fetched.push(key);
			if (key === 'attachments/boom.bin') throw new Error('COS read exploded');
			const bytes = objects.get(key);
			return bytes ? { arrayBuffer: async () => bytes.buffer } : null;
		}
	};

	const db = seedEwsDb();
	// 301：两张 900KB 内嵌图（正文各引用一次）
	db.prepare(`INSERT INTO email (email_id, account_id, user_id, type, unread, trash, is_del, subject, send_email, create_time, update_time, content)
	            VALUES (301, 1, 7, 0, 1, 0, 0, 'two big inline', 'a@x.y', '2026-10-02 08:00:00', '2026-10-02 08:00:00', ?)`)
		.run('<p>图一：</p><img src="{{domain}}attachments/i1.png"><p>图二：</p><img src="{{domain}}attachments/i2.png">');
	db.prepare(`INSERT INTO attachments (att_id, user_id, email_id, account_id, key, filename, mime_type, size, type, content_id) VALUES
	            (11, 7, 301, 1, 'attachments/i1.png', 'i1.png', 'image/png', ?, 1, 'i1@cloud'),
	            (12, 7, 301, 1, 'attachments/i2.png', 'i2.png', 'image/png', ?, 1, 'i2@cloud')`)
		.run(imgBytes.length, imgBytes.length);
	// 302：2MB 普通附件（type=0，之前被静默跳过/卷入，现在必须进占位清单）
	db.prepare(`INSERT INTO email (email_id, account_id, user_id, type, unread, trash, is_del, subject, send_email, create_time, update_time, content)
	            VALUES (302, 1, 7, 0, 1, 0, 0, 'big attachment', 'a@x.y', '2026-10-02 08:01:00', '2026-10-02 08:01:00', '<p>见附件</p>')`).run();
	db.prepare(`INSERT INTO attachments (att_id, user_id, email_id, account_id, key, filename, mime_type, size, type, content_id) VALUES
	            (13, 7, 302, 1, 'attachments/report.pdf', 'report.pdf', 'application/pdf', ?, 0, '')`)
		.run(pdfBytes.length);
	// 303：COS 读取抛错的正常附件（触发 buildMimeForRow 整体 try/catch）
	db.prepare(`INSERT INTO email (email_id, account_id, user_id, type, unread, trash, is_del, subject, send_email, create_time, update_time, content)
	            VALUES (303, 1, 7, 0, 1, 0, 0, 'boom attachment', 'a@x.y', '2026-10-02 08:02:00', '2026-10-02 08:02:00', '<p>boom</p>')`).run();
	db.prepare(`INSERT INTO attachments (att_id, user_id, email_id, account_id, key, filename, mime_type, size, type, content_id) VALUES
	            (14, 7, 303, 1, 'attachments/boom.bin', 'boom.bin', 'application/octet-stream', ?, 0, '')`)
		.run(boomBytes.length);
	// 304：>256KB 的 HTML 正文（截断 + 提示；尾部唯一标记必须被截掉）
	db.prepare(`INSERT INTO email (email_id, account_id, user_id, type, unread, trash, is_del, subject, send_email, create_time, update_time, content, text)
	            VALUES (304, 1, 7, 0, 1, 0, 0, 'huge html', 'a@x.y', '2026-10-02 08:03:00', '2026-10-02 08:03:00', ?, 'plain small')`)
		.run('<p>' + 'x'.repeat(300 * 1024) + 'ZZZ-TAIL-MARKER</p>');
	// 305：普通小邮件（回归：不受降级阶梯影响）
	db.prepare(`INSERT INTO email (email_id, account_id, user_id, type, unread, trash, is_del, subject, send_email, create_time, update_time, content, text)
	            VALUES (305, 1, 7, 0, 1, 0, 0, 'small mail', 'a@x.y', '2026-10-02 08:04:00', '2026-10-02 08:04:00', '<p>hello small</p>', 'plain body')`).run();

	const post = (body, extraEnv = {}) => ewsApp.fetch(new Request('https://mail.example.com/EWS/Exchange.asmx', {
		method: 'POST',
		headers: {
			Authorization: 'Basic ' + Buffer.from(`${mail}:${password}`).toString('base64'),
			'Content-Type': 'text/xml; charset=utf-8'
		},
		body
	}), { jwt_secret: jwtSecret, kv, db: sqliteD1(db), domain: '["example.com"]', r2, ...extraEnv }, {});

	const envelope = (body) => `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
  <soap:Body>${body}</soap:Body>
</soap:Envelope>`;
	const getItemWithMime = (id) => envelope('<m:GetItem>' +
		'<m:ItemShape><t:BaseShape>Default</t:BaseShape><t:IncludeMimeContent>true</t:IncludeMimeContent></m:ItemShape>' +
		`<m:ItemIds><t:ItemId Id="${id}"/></m:ItemIds>` +
		'</m:GetItem>');

	const safeRawBytes = Math.floor(EWS_MIME_SAFE_TOTAL * 1.4);
	// 外层 base64 文本长度上界：解码后 raw ≤ 1.4×预算 ⇒ base64 字符数 ≤ ceil(raw/3)*4（+padding）
	const maxOuterBase64 = Math.ceil(safeRawBytes / 3) * 4 + 8;
	const mimeOf = (xml) => {
		assert.equal(XMLValidator.validate(xml), true, 'GetItem 响应必须良构');
		assertSoapEnvelope(xml, 'GetItem');
		assert.ok(!xml.includes('<soap:Fault>'), 'GetItem 不应抛 Fault');
		assert.ok(xml.includes('ResponseClass="Success"'), 'GetItem 必须 Success（绝不 5xx/Fault）');
		const message = parseBack.parse(xml).Envelope.Body.GetItemResponse.ResponseMessages.GetItemResponseMessage;
		const mime = textOf(message.Items.Message.MimeContent);
		assert.ok(mime.length > 0, 'MimeContent 已重建（降级后也有极简 MIME）');
		assert.ok(base64DecodedSize(mime) <= safeRawBytes,
			`MimeContent 解码后 ${base64DecodedSize(mime)} 字节必须 ≤ 1.4×预算 ${safeRawBytes}`);
		assert.ok(mime.length <= maxOuterBase64, `外层 base64 ${mime.length} 字符必须 ≤ ${maxOuterBase64}`);
		return Buffer.from(mime, 'base64').toString('utf8');
	};

	// ① 多图（2×900KB）：第一张进 MIME、第二张超账本被跳过 → 第二张进占位清单（含文件名与大小）
	const bigRaw = mimeOf(await (await post(getItemWithMime(301))).text());
	assert.ok(bigRaw.includes('Content-ID: <i1@cloud>'), '第一张 900KB 图在预算内，正常进 MIME');
	assert.ok(!bigRaw.includes('i2@cloud'), '第二张超累计账本，图 part 不进 MIME');
	assert.ok(!bigRaw.includes('filename="i2.png"'), '第二张图不作为附件 part 残留');
	assert.deepEqual(fetched, ['attachments/i1.png'], '第二张在读 COS 前就被跳过（不产生字节读取）');
	const bigBody = decodeMimeBodies(bigRaw);
	assert.ok(bigBody.includes('cid:i1@cloud'), '第一张图的 cid 引用照常替换');
	assert.ok(bigBody.includes('[以下内容过大，此客户端无法加载]'), '正文末尾出现统一占位清单');
	assert.ok(bigBody.includes('• i2.png（900KB）'), '清单含被跳过内嵌图文件名与人性化大小（<1MB 显示 KB）');
	assert.ok(bigBody.includes('[图片过大（>1MB）'), '被跳过内嵌图位置仍有可见占位（现状行为保持）');

	// ② 普通附件 2MB（type=0）：超单附件上限 → 跳过并进清单（不再是无声缺失）
	const pdfRaw = mimeOf(await (await post(getItemWithMime(302))).text());
	assert.ok(!pdfRaw.includes('filename="report.pdf"'), '超限普通附件不进 MIME part');
	assert.deepEqual(fetched, ['attachments/i1.png'], '超限普通附件同样在读 COS 前跳过');
	const pdfBody = decodeMimeBodies(pdfRaw);
	assert.ok(pdfBody.includes('[以下内容过大，此客户端无法加载]'), '普通附件跳过也有占位清单');
	assert.ok(pdfBody.includes('• report.pdf（2MB）'), '清单含普通附件文件名与大小');

	// ③ 构建内部异常（COS 抛错）：整体 try/catch → 仍 Success + 极简 text/plain MIME（不白屏）
	const boomXml = await (await post(getItemWithMime(303))).text();
	const boomRaw = mimeOf(boomXml);
	assert.ok(fetched.includes('attachments/boom.bin'), '确实读到了抛错附件（异常路径被触发）');
	const boomBody = decodeMimeBodies(boomRaw);
	assert.ok(boomBody.includes('此邮件包含较大内容，无法在当前客户端加载，请使用网页版查看。'), '极简 MIME 含降级说明');
	assert.ok(boomBody.includes('邮件主题：boom attachment'), '极简 MIME 保留主题');
	assert.ok(boomBody.includes('邮件日期：2026-10-02 08:02:00'), '极简 MIME 保留日期');
	assert.ok(!boomRaw.includes('Content-Disposition: attachment'), '极简 MIME 不带任何附件 part');

	// ④ 超长 HTML（>256KB）：截断 + 末尾提示，尾部内容不出现
	const hugeRaw = mimeOf(await (await post(getItemWithMime(304))).text());
	const hugeBody = decodeMimeBodies(hugeRaw);
	assert.ok(hugeBody.includes('（内容过长已截断，请使用网页版查看完整内容）'), '超长正文带截断提示');
	assert.ok(!hugeBody.includes('ZZZ-TAIL-MARKER'), '超出 256KB 的尾部内容被截掉');
	assert.ok(hugeBody.includes('plain small'), 'text/plain 正文保留');

	// ⑤ 普通小邮件回归：无清单、无截断、正文完整
	const smallRaw = mimeOf(await (await post(getItemWithMime(305))).text());
	const smallBody = decodeMimeBodies(smallRaw);
	assert.ok(smallBody.includes('hello small') && smallBody.includes('plain body'), '小邮件正文完整');
	assert.ok(!smallBody.includes('[以下内容过大') && !smallBody.includes('内容过长已截断'), '小邮件不出现任何降级痕迹');
});

// ---- 37. 纯附件无正文：清单本身就是正文（html/text 皆空也必须输出） ----

testCase('37. 纯附件无正文邮件（html/text 皆空 + 2MB 附件）：MimeContent 始终输出占位清单（HTML + text）', async () => {
	ensureNodeResolveHook();
	const { default: ewsApp } = await import('../src/ews/router.js');

	const jwtSecret = 'unit-test-jwt-secret';
	const password = 'secret-password';
	const mail = 'tb-user@example.com';
	const kvStore = new Map();
	kvStore.set('setting:', JSON.stringify({ emailPrefixFilter: '' }));
	kvStore.set('ews-auth:' + createHash('sha256').update(`${jwtSecret}:${mail}:${password}`).digest('hex'),
		JSON.stringify({ userId: 7, email: mail, status: 0, isDel: 0 }));
	const kv = {
		get: async (key) => (kvStore.has(key) ? JSON.parse(kvStore.get(key)) : null),
		put: async () => {},
		delete: async () => {}
	};

	// 2MB 普通附件 > 默认单附件上限 1MB → 必须被跳过并进占位清单；
	// fetched 证明被跳过的附件在读 COS 前就被截住（不产生字节读取）
	const pdfBytes = new Uint8Array(2 * 1024 * 1024).fill(0x25);
	const fetched = [];
	const r2 = {
		get: async (key) => {
			fetched.push(key);
			if (key === 'attachments/pure.pdf') return { arrayBuffer: async () => pdfBytes.buffer };
			return null;
		}
	};

	const db = seedEwsDb();
	// 306：纯附件邮件，content / text 列均为 NULL（用户实测形态：正文完全为空）
	db.prepare(`INSERT INTO email (email_id, account_id, user_id, type, unread, trash, is_del, subject, send_email, create_time, update_time)
	            VALUES (306, 1, 7, 0, 1, 0, 0, 'pure attachment', 'a@x.y', '2026-10-03 08:00:00', '2026-10-03 08:00:00')`).run();
	db.prepare(`INSERT INTO attachments (att_id, user_id, email_id, account_id, key, filename, mime_type, size, type, content_id) VALUES
	            (15, 7, 306, 1, 'attachments/pure.pdf', 'pure.pdf', 'application/pdf', ?, 0, '')`)
		.run(pdfBytes.length);

	const post = (body) => ewsApp.fetch(new Request('https://mail.example.com/EWS/Exchange.asmx', {
		method: 'POST',
		headers: {
			Authorization: 'Basic ' + Buffer.from(`${mail}:${password}`).toString('base64'),
			'Content-Type': 'text/xml; charset=utf-8'
		},
		body
	}), { jwt_secret: jwtSecret, kv, db: sqliteD1(db), domain: '["example.com"]', r2 }, {});

	const envelope = (body) => `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
  <soap:Body>${body}</soap:Body>
</soap:Envelope>`;
	const getItemWithMime = (id) => envelope('<m:GetItem>' +
		'<m:ItemShape><t:BaseShape>Default</t:BaseShape><t:IncludeMimeContent>true</t:IncludeMimeContent></m:ItemShape>' +
		`<m:ItemIds><t:ItemId Id="${id}"/></m:ItemIds>` +
		'</m:GetItem>');

	const xml = await (await post(getItemWithMime(306))).text();
	assert.equal(XMLValidator.validate(xml), true, 'GetItem 响应必须良构');
	assertSoapEnvelope(xml, 'GetItem');
	assert.ok(!xml.includes('<soap:Fault>'), 'GetItem 不应抛 Fault');
	assert.ok(xml.includes('ResponseClass="Success"'), 'GetItem 必须 Success');
	const message = parseBack.parse(xml).Envelope.Body.GetItemResponse.ResponseMessages.GetItemResponseMessage;
	const mime = textOf(message.Items.Message.MimeContent);
	assert.ok(mime.length > 0, 'MimeContent 已重建');
	const rawMime = Buffer.from(mime, 'base64').toString('utf8');
	const body = decodeMimeBodies(rawMime);

	// 被跳过的 2MB 附件：MIME 里无它的 part（预期），占位清单是唯一提示
	assert.ok(!rawMime.includes('filename="pure.pdf"'), '超限附件不作为 MIME part 输出（预期）');
	assert.deepEqual(fetched, [], '超限附件在读 COS 前就被跳过');
	assert.ok(body.includes('[以下内容过大，此客户端无法加载]'), 'MimeContent 出现占位清单标题');
	assert.ok(body.includes('• pure.pdf（2MB）'), '清单含被跳过附件的文件名与人性化大小');
	// 正文为空时清单本身就是 HTML 正文（含 <p> 标签），TB 的 HTML 渲染路径必须能看到
	assert.ok(rawMime.includes('Content-Type: multipart/alternative'), '清单同时以 html + text 两种形态输出');
	assert.ok(rawMime.includes('Content-Type: text/plain') && rawMime.includes('Content-Type: text/html'),
		'text/plain 与 text/html part 都存在');
	assert.ok(body.includes('<p style="border:1px dashed #999;padding:8px;color:#666;">') && body.includes('• pure.pdf（2MB）'),
		'HTML 清单原文可见（文件名与大小）');
});

// ---- 38. 占位清单零链接纯提示 + CreateItem 发信上限入口打回 ----

testCase('38. 占位清单零链接（仅文件名/大小/网页版指引，无 <a> 无 URL）+ CreateItem 超限中文打回（不调 send）+ BizError→Fault 映射', async () => {
	// ① 纯函数：清单只含文件名 + 人性化大小 + 网页版指引；即使传入伪造 url 也必须被忽略
	const plainHtml = skippedAttachmentsHtml([
		{ filename: 'a&b.pdf', size: 2202009, url: 'https://evil.example/attachments/a?expires=1&sign=abc' },
		{ filename: 'report.pdf', size: 3.4 * 1024 * 1024 }
	]);
	assert.ok(plainHtml.startsWith('<p style="border:1px dashed #999;padding:8px;color:#666;">[以下内容过大，此客户端无法加载]<br>'));
	assert.ok(plainHtml.includes('• a&amp;b.pdf（2.1MB）') && plainHtml.includes('• report.pdf（3.4MB）'),
		'清单含文件名（转义）与人性化大小');
	assert.ok(plainHtml.includes('请登录网页版查看或下载。'), '带网页版查看/下载指引');
	assert.ok(!plainHtml.includes('<a ') && !plainHtml.includes('href=') && !plainHtml.includes('http'),
		'零链接：传入的 url 被忽略，清单无 <a>/href/URL（离线签名凭据一律不签发）');
	const plainText = skippedAttachmentsText([{ filename: 'a.pdf', size: 1024, url: 'https://x/?a=1&b=2' }]);
	assert.ok(plainText.includes('• a.pdf（1KB）') && plainText.includes('请登录网页版查看或下载。'), '纯文本清单同款提示');
	assert.ok(!plainText.includes('http') && !plainText.includes('<a '), '纯文本清单同样零链接');
	assert.equal(skippedAttachmentsText([]), '', '无跳过项不产出清单');

	// ② 常量：默认 35MB，env 可调（对齐 ewsMaxAttBytes 风格）
	assert.equal(EWS_SEND_MAX_BYTES, 35 * 1024 * 1024, 'EWS_SEND_MAX_BYTES 默认 35MB');
	assert.equal(ewsSendMaxBytes({}), EWS_SEND_MAX_BYTES);
	assert.equal(ewsSendMaxBytes({ EWS_SEND_MAX_BYTES: '5242880' }), 5242880);
	assert.equal(ewsSendMaxBytes({ EWS_SEND_MAX_BYTES: 'abc' }), EWS_SEND_MAX_BYTES);
	assert.equal(ewsSendMaxBytes({ EWS_SEND_MAX_BYTES: '0' }), EWS_SEND_MAX_BYTES);

	// ③ E2E：被跳过附件在 MimeContent 正文里是纯信息提示——不含任何链接/签名 URL
	ensureNodeResolveHook();
	const { default: ewsApp } = await import('../src/ews/router.js');
	const { dispatch, EwsFault } = await import('../src/ews/handlers.js');
	const { sendCalls, resetSendCalls } = await import(EMAIL_SERVICE_STUB_URL);

	const jwtSecret = 'unit-test-jwt-secret';
	const password = 'secret-password';
	const mail = 'tb-user@example.com';
	const kvStore = new Map();
	kvStore.set('setting:', JSON.stringify({ emailPrefixFilter: '' }));
	kvStore.set('ews-auth:' + createHash('sha256').update(`${jwtSecret}:${mail}:${password}`).digest('hex'),
		JSON.stringify({ userId: 7, email: mail, status: 0, isDel: 0 }));
	const kv = {
		get: async (key) => (kvStore.has(key) ? JSON.parse(kvStore.get(key)) : null),
		put: async () => {},
		delete: async () => {}
	};
	const pdfBytes = new Uint8Array(2 * 1024 * 1024).fill(0x25);
	const fetched = [];
	const r2 = {
		get: async (key) => {
			fetched.push(key);
			return key === 'attachments/direct.pdf' ? { arrayBuffer: async () => pdfBytes.buffer } : null;
		}
	};
	const db = seedEwsDb();
	db.prepare(`INSERT INTO email (email_id, account_id, user_id, type, unread, trash, is_del, subject, send_email, create_time, update_time)
	            VALUES (401, 1, 7, 0, 1, 0, 0, 'clickable attachment', 'a@x.y', '2026-10-04 08:00:00', '2026-10-04 08:00:00')`).run();
	db.prepare(`INSERT INTO attachments (att_id, user_id, email_id, account_id, key, filename, mime_type, size, type, content_id) VALUES
	            (16, 7, 401, 1, 'attachments/direct.pdf', 'direct.pdf', 'application/pdf', ?, 0, '')`)
		.run(pdfBytes.length);

	const post = (body) => ewsApp.fetch(new Request('https://mail.example.com/EWS/Exchange.asmx', {
		method: 'POST',
		headers: {
			Authorization: 'Basic ' + Buffer.from(`${mail}:${password}`).toString('base64'),
			'Content-Type': 'text/xml; charset=utf-8'
		},
		body
	}), { jwt_secret: jwtSecret, kv, db: sqliteD1(db), domain: '["example.com"]', r2 }, {});

	const envelope = (body) => `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
  <soap:Body>${body}</soap:Body>
</soap:Envelope>`;
	const getItemWithMime = (id) => envelope('<m:GetItem>' +
		'<m:ItemShape><t:BaseShape>Default</t:BaseShape><t:IncludeMimeContent>true</t:IncludeMimeContent></m:ItemShape>' +
		`<m:ItemIds><t:ItemId Id="${id}"/></m:ItemIds>` +
		'</m:GetItem>');

	const xml401 = await (await post(getItemWithMime(401))).text();
	assert.equal(XMLValidator.validate(xml401), true, 'GetItem 响应必须良构');
	assertSoapEnvelope(xml401, 'GetItem');
	assert.ok(!xml401.includes('<soap:Fault>'), 'GetItem 不应抛 Fault');
	const mime401 = textOf(parseBack.parse(xml401).Envelope.Body.GetItemResponse.ResponseMessages.GetItemResponseMessage.Items.Message.MimeContent);
	const body401 = decodeMimeBodies(Buffer.from(mime401, 'base64').toString('utf8'));

	assert.ok(body401.includes('[以下内容过大，此客户端无法加载]') && body401.includes('• direct.pdf（2MB）')
		&& body401.includes('请登录网页版查看或下载。'), '占位清单为纯信息提示（文件名 + 大小 + 网页版指引）');
	assert.ok(!body401.includes('<a ') && !body401.includes('href=') && !body401.includes('http'),
		'MimeContent 清单零链接：无 <a>/href/http（签名 URL 可转发，绝不进邮件）');
	assert.deepEqual(fetched, [], '被跳过附件不读 COS（下载须走 Web 端完整流程）');

	// ④ CreateItem：MimeContent 解码后 40MiB > 35MiB → 入口中文打回，绝不进入 emailService.send
	const user = { userId: 7, email: mail };
	const ctx = { env: { db: sqliteD1(db) } };
	const createPayload = (mimeText) => ({
		'@_MessageDisposition': 'SendOnly',
		Items: {
			Message: {
				From: { Mailbox: { EmailAddress: mail } },
				ToRecipients: { Mailbox: { EmailAddress: 'rcpt@example.net' } },
				Subject: 'size guard',
				Body: { '@_BodyType': 'Text', '#text': 'hi' },
				MimeContent: { '@_CharacterSet': 'UTF-8', '#text': mimeText }
			}
		}
	});
	// 全 'A' 的 base64：base64DecodedSize = floor(len*3/4)，按目标字节数反推长度
	const mimeOfDecodedSize = (bytes) => 'A'.repeat(Math.ceil(bytes / 3) * 4);

	resetSendCalls();
	await assert.rejects(
		() => dispatch(ctx, { operation: 'CreateItem', payload: createPayload(mimeOfDecodedSize(40 * 1024 * 1024)) }, user),
		(error) => {
			assert.ok(error instanceof EwsFault, '超限 → EwsFault（而非 500/透传 Resend 英文错误）');
			assert.equal(error.responseCode, 'ErrorInvalidRequest');
			assert.ok(error.message.includes('邮件过大') && error.message.includes('Resend 无法投递'),
				`Fault 含中文超限提示: ${error.message}`);
			return true;
		});
	assert.equal(sendCalls.length, 0, '40MB MimeContent 在入口打回，emailService.send 零调用');

	// ⑤ 边界：解码 36,000,000 字节（十进制 36MB < 35MiB=36,700,160）放行；
	//    结构化字段齐全，无需解析/解码 MimeContent（避免测试里真的构造 36MB MIME）
	resetSendCalls();
	const okXml = await dispatch(ctx, { operation: 'CreateItem', payload: createPayload(mimeOfDecodedSize(36_000_000)) }, user);
	assert.ok(okXml.includes('<m:CreateItemResponse') && okXml.includes('ResponseClass="Success"'), '35MiB 以内的超大 MimeContent 正常走发信');
	assert.equal(sendCalls.length, 1, '边界内继续调用 emailService.send');
	assert.equal(sendCalls[0].params.subject, 'size guard');

	// ⑥ BizError → Fault 映射：Resend 拒绝等业务错误必须转成带 message 的 Fault，不能 500 泄露
	resetSendCalls();
	const stub = (await import(EMAIL_SERVICE_STUB_URL)).default;
	const originalSend = stub.send;
	stub.send = async () => { throw new BizError('Resend 拒绝投递：Daily quota exceeded', 501); };
	try {
		await assert.rejects(
			() => dispatch(ctx, { operation: 'CreateItem', payload: createPayload(mimeOfDecodedSize(1024)) }, user),
			(error) => {
				assert.ok(error instanceof EwsFault, 'emailService.send 抛 BizError → EwsFault');
				assert.equal(error.responseCode, 'ErrorInvalidRequest');
				assert.ok(error.message.includes('Daily quota exceeded'), 'Fault messageText 保留 BizError 业务原因');
				return true;
			});
	} finally {
		stub.send = originalSend;
	}
	resetSendCalls();
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
