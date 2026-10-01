/**
 * EWS 端点路由（Thunderbird 145+ 原生 Exchange 账号）。
 *
 * index.js 的 fetch 入口对 /EWS/Exchange.asmx（大小写不敏感）把请求交给本实例：
 *   - 非 POST → 405
 *   - HTTP Basic 认证失败 → 401 + WWW-Authenticate（不带 SOAP body，客户端会重发凭据）
 *   - 认证通过 → c.set('user', userRow)，解析 SOAP 后分发到 handlers.js
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

	let bodyText = '';
	try {
		bodyText = await c.req.text();
	} catch (e) {
		return xmlResponse(soapFault('ErrorInvalidRequest', 'Unable to read the request body.'));
	}
	if (bodyText.length > EWS_MAX_REQUEST_BYTES) {
		return xmlResponse(soapFault('ErrorInvalidRequest',
			`Request body is too large for EWS (${bodyText.length} bytes > ${EWS_MAX_REQUEST_BYTES} bytes).`));
	}

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
