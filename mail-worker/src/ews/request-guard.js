/**
 * EWS 请求体大小护栏（纯函数 + 流工具，零项目依赖，可被 node 直接 import 单测）。
 *
 * 为什么需要：`await c.req.text()` 是先整读再比大小，超限时 body 早已进 isolate 内存，
 * 比较失去意义。这里把判断提前到「读体之前 / 读取过程中」：
 *   1) Content-Length 存在且可信：数值超限 → 调用方直接返回 413，不读体；
 *   2) Content-Length 缺失或不可信（chunked、非法值等）：流式累计字节，
 *      累计超限立即 cancel 读取（内存占用有界，最多多读一个 chunk）；
 *   3) 读完后调用方仍按字符数复查一次（双保险，防伪造的 Content-Length）。
 *
 * 第 2 条的思路与 doc/cos-proxy-worker.js 的 tempLimitedBody 一致。
 */

/**
 * 解析 Content-Length：只接受纯十进制（多值/负数/带单位等一律视为不可信 → null）。
 * @returns {number|null}
 */
export function parseContentLength(headerValue) {
	if (headerValue === null || headerValue === undefined) return null;
	const text = String(headerValue).trim();
	if (!/^\d{1,15}$/.test(text)) return null;
	const value = Number(text);
	return Number.isSafeInteger(value) ? value : null;
}

/**
 * 读体前的预检。
 * @returns {{ state: 'ok'|'too-large'|'unknown', declared: number|null }}
 *   - ok：有可信 Content-Length 且未超限 → 可以正常整读（读后复查兜底）；
 *   - too-large：有可信 Content-Length 且超限 → 立即 413，不读体；
 *   - unknown：没有/不可信 → 必须走 readLimitedText 流式计数。
 */
export function precheckContentLength(headerValue, maxBytes) {
	const declared = parseContentLength(headerValue);
	if (declared === null) return { state: 'unknown', declared: null };
	const limit = Number(maxBytes);
	return { state: Number.isFinite(limit) && declared > limit ? 'too-large' : 'ok', declared };
}

/**
 * 流式读取 body 为文本，逐块累计字节数；累计超过 maxBytes 立即取消读取并返回 tooLarge。
 * @param {ReadableStream|null|undefined} body
 * @returns {Promise<{ text: string }|{ tooLarge: true, bytes: number }>}
 */
export async function readLimitedText(body, maxBytes) {
	if (!body || typeof body.getReader !== 'function') return { text: '' };
	const limit = Number(maxBytes);
	const reader = body.getReader();
	const decoder = new TextDecoder();
	let bytes = 0;
	let text = '';
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			bytes += value.byteLength;
			if (Number.isFinite(limit) && bytes > limit) {
				try {
					await reader.cancel();
				} catch (e) {
					// 取消失败不影响结论：已经超限
				}
				return { tooLarge: true, bytes };
			}
			text += decoder.decode(value, { stream: true });
		}
		text += decoder.decode();
	} finally {
		try {
			reader.releaseLock();
		} catch (e) {
			// reader 已释放/已出错：忽略
		}
	}
	return { text };
}
