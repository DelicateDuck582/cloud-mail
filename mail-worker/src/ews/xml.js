/**
 * EWS 的 XML 层：SOAP 请求解析 + 响应模板生成。
 *
 * 解析用 fast-xml-parser（removeNSPrefix: true：soap:/t:/m: 等命名空间前缀统一剥离，
 * 元素名不依赖客户端使用的前缀）；生成侧手写模板字符串并统一走 escapeXml 转义。
 *
 * 本文件除 fast-xml-parser 外不 import 项目模块，可直接被 node 单测（scripts/test-ews-smoke.mjs）。
 */

import { XMLParser } from 'fast-xml-parser';

export const SOAP_NS = 'http://schemas.xmlsoap.org/soap/envelope/';
export const MESSAGES_NS = 'http://schemas.microsoft.com/exchange/services/2006/messages';
export const TYPES_NS = 'http://schemas.microsoft.com/exchange/services/2006/types';

export const ATTR_PREFIX = '@_';
export const TEXT_KEY = '#text';

const parser = new XMLParser({
	removeNSPrefix: true,
	ignoreAttributes: false,
	attributeNamePrefix: ATTR_PREFIX,
	parseTagValue: false,
	parseAttributeValue: false,
	trimValues: true,
	allowBooleanAttributes: false
});

/**
 * XML 文本转义。同时剥掉 XML 1.0 不允许的控制字符（邮件主题/正文里可能带），
 * 否则响应会变成非法 XML 导致客户端解析失败。
 */
export function escapeXml(value) {
	if (value === null || value === undefined) return '';
	return String(value)
		.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '')
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&apos;');
}

/** 元素内容数组化：fast-xml-parser 单个子元素不是数组 */
export function asArray(value) {
	if (value === null || value === undefined) return [];
	return Array.isArray(value) ? value : [value];
}

/** 取子元素原始节点 */
export function child(node, name) {
	if (!node || typeof node !== 'object') return undefined;
	return node[name];
}

/** 取第一个同名子元素（数组时取首个） */
export function firstChild(node, name) {
	const value = child(node, name);
	return Array.isArray(value) ? value[0] : value;
}

/**
 * 取全部同名子元素：EWS 请求里 FolderId/ItemId/Mailbox/FileAttachment 等都可能重复出现，
 * 单个时 fast-xml-parser 不返回数组，统一用本函数归一（禁止用 firstChild 读重复元素）。
 */
export function children(node, name) {
	return asArray(child(node, name));
}

/** 取元素属性（解析后形如 @_Id）；不存在返回 null */
export function attr(node, name) {
	if (!node || typeof node !== 'object') return null;
	const value = node[ATTR_PREFIX + name];
	if (value === undefined || value === null) return null;
	return String(value);
}

/** 取元素文本；空元素返回 ''，纯文本节点直接返回自身 */
export function textOf(node) {
	if (node === null || node === undefined) return '';
	if (typeof node === 'object') {
		const value = node[TEXT_KEY];
		return value === null || value === undefined ? '' : String(value);
	}
	return String(node);
}

/** EWS 的布尔元素是 'true'/'false'（部分客户端会发 1/0） */
export function isTrueFlag(node) {
	const value = textOf(node).trim().toLowerCase();
	return value === 'true' || value === '1';
}

/**
 * 解析请求 SOAP 信封，返回 { operation, payload, header }；
 * 结构不合法时返回 { error }（由调用方转成 SOAP Fault，不再抛异常）。
 */
export function parseSoapRequest(xmlText) {
	const text = typeof xmlText === 'string' ? xmlText.trim() : '';
	if (text === '') return { error: 'EmptyRequest' };
	// 安全：拒绝 DTD，避免实体展开类攻击
	if (/<!DOCTYPE/i.test(text)) return { error: 'DoctypeNotAllowed' };

	let doc;
	try {
		doc = parser.parse(text);
	} catch (e) {
		return { error: 'MalformedXml' };
	}

	const envelope = doc?.Envelope;
	if (!envelope || typeof envelope !== 'object') return { error: 'NotSoapEnvelope' };

	const body = envelope.Body;
	if (!body || typeof body !== 'object') return { error: 'EmptySoapBody' };

	// Body 的第一个元素子节点即本次操作（'?xml' 声明和 @_ 属性跳过）
	const operation = Object.keys(body).find((key) => key !== TEXT_KEY && !key.startsWith(ATTR_PREFIX) && !key.startsWith('?'));
	if (!operation) return { error: 'EmptySoapBody' };

	return { operation, payload: body[operation], header: envelope.Header ?? null };
}

/** SOAP 信封 + ServerVersionInfo（部分客户端会据此判断服务端版本，缺失时降级） */
export function soapEnvelope(innerXml) {
	return '<?xml version="1.0" encoding="utf-8"?>' +
		`<soap:Envelope xmlns:soap="${SOAP_NS}" xmlns:t="${TYPES_NS}" xmlns:m="${MESSAGES_NS}">` +
		'<soap:Header><t:ServerVersionInfo MajorVersion="15" MinorVersion="0" MajorBuildNumber="1" MinorBuildNumber="0" Version="V2_7" /></soap:Header>' +
		`<soap:Body>${innerXml}</soap:Body>` +
		'</soap:Envelope>';
}

/**
 * SOAP Fault。EWS 惯例 HTTP 200 + Fault body（业务错误码同时放进 detail/m:ResponseCode）。
 */
export function soapFault(responseCode, faultString, faultCode = 'soap:Client') {
	const inner = '<soap:Fault>' +
		`<faultcode>${escapeXml(faultCode)}</faultcode>` +
		`<faultstring xml:lang="en-US">${escapeXml(faultString)}</faultstring>` +
		'<detail>' +
		`<m:ResponseCode>${escapeXml(responseCode)}</m:ResponseCode>` +
		`<m:MessageXml><t:Value Name="ResponseCode">${escapeXml(responseCode)}</t:Value></m:MessageXml>` +
		'</detail>' +
		'</soap:Fault>';
	return soapEnvelope(inner);
}

/** <m:XxxResponse><m:ResponseMessages>…</m:ResponseMessages></m:XxxResponse> */
export function operationResponse(operationName, responseMessagesXml) {
	return `<m:${operationName}Response xmlns:m="${MESSAGES_NS}" xmlns:t="${TYPES_NS}">` +
		`<m:ResponseMessages>${responseMessagesXml}</m:ResponseMessages>` +
		`</m:${operationName}Response>`;
}

/**
 * 单条 ResponseMessage。responseClass: Success | Error | Warning；
 * messageText 仅 Error/Warning 时输出（EWS 的 MessageText 元素）。
 */
export function responseMessage(name, { responseClass = 'Success', responseCode = 'NoError', messageText = '', body = '' } = {}) {
	const messageTextXml = messageText === '' ? '' : `<m:MessageText>${escapeXml(messageText)}</m:MessageText>`;
	return `<m:${name}ResponseMessage ResponseClass="${escapeXml(responseClass)}">` +
		`<m:ResponseCode>${escapeXml(responseCode)}</m:ResponseCode>` +
		messageTextXml +
		body +
		`</m:${name}ResponseMessage>`;
}
