/**
 * EWS 端点路由（Thunderbird 145+ 原生 Exchange 账号）。
 *
 * index.js 的 fetch 入口对 /EWS/Exchange.asmx（大小写不敏感）把请求交给本实例：
 *   - 非 POST → 405
 *   - HTTP Basic 认证失败 → 401 + WWW-Authenticate（不带 SOAP body，客户端会重发凭据）
 *   - 认证通过 → c.set('user', userRow)，解析 SOAP 后分发到 handlers.js
 *   - 成功 → HTTP 200 + 完整 SOAP 信封（handler 经 operationResponse 已包好信封，这里不再二次包裹）
 *   - 业务错误 → HTTP 200 + SOAP Fault（EWS 惯例，TB 两种都吃）
 *
 * 独立 Hono 实例的目的：handler 拿到的是真正的 Hono context c，
 * 可直接复用 email-service / att-service / setting-service 等全部现有 service。
 */

import { Hono } from 'hono';
import { authenticate } from './auth.js';
import { parseSoapRequest, soapFault } from './xml.js';
import { dispatch, EwsFault } from './handlers.js';
import { EWS_MAX_REQUEST_BYTES } from './const.js';
import { precheckContentLength, readLimitedText } from './request-guard.js';

const ewsApp = new Hono();

function xmlResponse(body) {
	return new Response(body, {
		status: 200,
		headers: {
			'Content-Type': 'text/xml; charset=utf-8',
			'Cache-Control': 'no-store'
		}
	});
}

function unauthorizedResponse() {
	return new Response('Unauthorized', {
		status: 401,
		headers: {
			'WWW-Authenticate': 'Basic realm="CloudMail EWS"',
			'Content-Type': 'text/plain; charset=utf-8',
			'Cache-Control': 'no-store'
		}
	});
}

/** 请求体超限：HTTP 413 + SOAP Fault（在把 body 读进内存之前就拒绝） */
function tooLargeResponse(bytes) {
	return new Response(soapFault('ErrorInvalidRequest',
		`Request body is too large for EWS (${bytes} bytes > ${EWS_MAX_REQUEST_BYTES} bytes).`), {
		status: 413,
		headers: {
			'Content-Type': 'text/xml; charset=utf-8',
			'Cache-Control': 'no-store'
		}
	});
}

ewsApp.all('*', async (c) => {
	if (c.req.method !== 'POST') {
		return new Response('Method Not Allowed', {
			status: 405,
			headers: { Allow: 'POST', 'Content-Type': 'text/plain; charset=utf-8' }
		});
	}

	let user = null;
	try {
		user = await authenticate(c);
	} catch (error) {
		// KV/D1 未绑定或数据库未初始化等基础设施异常：按认证失败处理，不向客户端泄露内部细节
		console.error('[ews] authentication failed:', error);
		return unauthorizedResponse();
	}
	if (!user) {
		return unauthorizedResponse();
	}
	// 与项目 userContext 约定对齐：后续 service 通过 c.get('user').userId 取当前用户
	c.set('user', user);

	// 读体前的预检：有可信 Content-Length 且超限 → 立即 413，绝不把大 body 读进内存
	const precheck = precheckContentLength(c.req.header('content-length'), EWS_MAX_REQUEST_BYTES);
	if (precheck.state === 'too-large') {
		return tooLargeResponse(precheck.declared);
	}

	let bodyText = '';
	try {
		if (precheck.state === 'unknown') {
			// chunked 等没有可信长度：流式累计字节，累计超限立即中止读取
			const limited = await readLimitedText(c.req.raw.body, EWS_MAX_REQUEST_BYTES);
			if (limited.tooLarge) {
				return tooLargeResponse(limited.bytes);
			}
			bodyText = limited.text;
		} else {
			bodyText = await c.req.text();
		}
	} catch (e) {
		return xmlResponse(soapFault('ErrorInvalidRequest', 'Unable to read the request body.'));
	}
	// 双保险：Content-Length 可被伪造，读完后仍复查一次
	if (bodyText.length > EWS_MAX_REQUEST_BYTES) {
		return tooLargeResponse(bodyText.length);
	}

	// 诊断日志（已认证用户的请求，泄露风险低）：tail CF 日志可确认 TB 各阶段实际发送的 SOAP 原文
	// 截断放宽到 2500：TB 一次 GetFolder/FindFolder 会点名十来个 Distinguished 文件夹，
	// 500 字符看不到完整 FolderIds 列表（排查「只发 GetFolder 就停」时必需）
	console.log('EWS req body:', bodyText.slice(0, 2500));

	const parsed = parseSoapRequest(bodyText);
	if (parsed.error) {
		return xmlResponse(soapFault('ErrorInvalidRequest', `Malformed SOAP request: ${parsed.error}.`));
	}

	try {
		return xmlResponse(await dispatch(c, parsed, user));
	} catch (error) {
		if (error instanceof EwsFault) {
			return xmlResponse(soapFault(error.responseCode, error.message));
		}
		console.error(`[ews] ${parsed.operation} failed:`, error);
		// 安全：非预期异常不回内部细节（与 hono 的 onError 同策略）
		return xmlResponse(soapFault('ErrorInternalServerError', 'Internal server error.'));
	}
});

export default ewsApp;
