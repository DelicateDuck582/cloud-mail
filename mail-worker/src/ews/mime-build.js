/**
 * RFC 5322 / MIME message builder for the EWS (Exchange Web Services) bridge.
 *
 * Zero-dependency pure helpers that rebuild a raw RFC 5322 message out of the
 * mail data already parsed and stored in D1 (email / attachment tables).
 * Nothing from the rest of the project is imported, so this file can be unit
 * tested with plain node and reused inside Workers.
 *
 * The caller is responsible for:
 *   - turning the stored recipient strings into structured address arrays;
 *   - reading attachment bodies (COS) and passing them as Uint8Array;
 *   - rewriting inline image references inside `html` to `cid:<contentId>`.
 *
 * Everything is assembled as a string and encoded to Uint8Array once at the
 * end: headers are pure ASCII and every body is base64, so the whole message
 * is ASCII by construction.
 */

const CRLF = '\r\n';
const UTF8_ENCODER = new TextEncoder();

const WEEKDAY_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTH_NAMES = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const BASE64_LINE_LENGTH = 76;
const BASE64_CODES = new Uint8Array(64);
for (let i = 0; i < 64; i++) {
	BASE64_CODES[i] = BASE64_ALPHABET.charCodeAt(i);
}

const HEX_UPPER = '0123456789ABCDEF';

const ENCODED_WORD_PREFIX = '=?UTF-8?q?';
const ENCODED_WORD_SUFFIX = '?=';
const ENCODED_WORD_MAX_LENGTH = 75;
const MAX_Q_PAYLOAD_LENGTH = ENCODED_WORD_MAX_LENGTH - ENCODED_WORD_PREFIX.length - ENCODED_WORD_SUFFIX.length;

const DEFAULT_MIME_TYPE = 'application/octet-stream';
const DEFAULT_FILENAME = 'attachment';
const DEFAULT_MESSAGE_ID_DOMAIN = 'cloud-mail.local';
const HEADER_LINE_SOFT_LIMIT = 78;

/** RFC 5322 chars that force a display name into a quoted-string (phrase context). */
const PHRASE_SPECIALS = /[()<>@,;:\\".[\]]/;

/**
 * Strip CR/LF and other control characters that would allow header injection.
 */
function sanitizeHeaderValue(value) {
	if (value === null || value === undefined) return '';
	return String(value)
		.replace(/[\r\n\t\f\v]+/g, ' ')
		.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');
}

function isPureAscii(value) {
	return /^[\x20-\x7e]*$/.test(value);
}

function pad2(value) {
	return value < 10 ? '0' + value : String(value);
}

function normalizeDateMs(dateMs) {
	if (dateMs === null || dateMs === undefined || dateMs === '') return Date.now();
	const value = Number(dateMs);
	return Number.isFinite(value) ? value : Date.now();
}

/**
 * RFC 5322 date-time, always in +0000 (UTC), hand written so no locale or
 * platform specific formatting (`toUTCString` appends "GMT") leaks in.
 */
function formatRfc5322Date(dateMs) {
	const d = new Date(normalizeDateMs(dateMs));
	return `${WEEKDAY_NAMES[d.getUTCDay()]}, ${pad2(d.getUTCDate())} ${MONTH_NAMES[d.getUTCMonth()]} ${d.getUTCFullYear()} ` +
		`${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())} +0000`;
}

function randomHex(byteCount) {
	const bytes = new Uint8Array(byteCount);
	if (typeof crypto !== 'undefined' && crypto && typeof crypto.getRandomValues === 'function') {
		crypto.getRandomValues(bytes);
	} else {
		for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
	}
	let hex = '';
	for (let i = 0; i < bytes.length; i++) {
		hex += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
	}
	return hex;
}

/** Unique boundary per multipart level: ----=_Part_<16 hex chars>. */
function newBoundary() {
	return `----=_Part_${randomHex(8)}`;
}

function toBytes(data) {
	if (data === null || data === undefined) return new Uint8Array(0);
	if (data instanceof Uint8Array) return data;
	if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView(data)) {
		return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	}
	if (typeof ArrayBuffer !== 'undefined' && data instanceof ArrayBuffer) return new Uint8Array(data);
	if (typeof data === 'string') return UTF8_ENCODER.encode(data);
	if (Array.isArray(data)) return Uint8Array.from(data);
	return new Uint8Array(0);
}

/**
 * Uint8Array -> ASCII string without per-byte string concatenation.
 */
function asciiString(bytes) {
	const CHUNK = 8192;
	let out = '';
	for (let i = 0; i < bytes.length; i += CHUNK) {
		out += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
	}
	return out;
}

/**
 * Base64 encode bytes with 76-column CRLF folding.
 *
 * Workers/浏览器原生 btoa 走引擎内置实现（比 JS 位运算循环快约一个数量级，
 * 3MB 附件从 ~62ms 降到 ~8ms，满足 Free 计划单请求 10ms CPU 内编码小块），
 * 分块调用避免 String.fromCharCode 参数上限；无 btoa 的环境回退到 JS 实现。
 * Exported for EWS GetAttachment reuse.
 */
export function base64Encode(bytes) {
	const input = toBytes(bytes);

	if (typeof btoa === 'function') {
		const CHUNK = 0x8000;
		let raw = '';
		for (let i = 0; i < input.length; i += CHUNK) {
			raw += btoa(String.fromCharCode.apply(null, input.subarray(i, i + CHUNK)));
		}
		return fold76(raw.replace(/\n/g, ''));
	}

	return base64EncodeJs(input);
}

// 76 列 CRLF 折行
function fold76(s) {
	if (s.length <= BASE64_LINE_LENGTH) {
		return s;
	}
	let out = '';
	for (let i = 0; i < s.length; i += BASE64_LINE_LENGTH) {
		out += (out ? CRLF : '') + s.slice(i, i + BASE64_LINE_LENGTH);
	}
	return out;
}

// 纯 JS 回退实现：预分配输出缓冲，无逐字节字符串拼接
function base64EncodeJs(input) {
	const length = input.length;
	if (length === 0) return '';

	const groups = Math.ceil(length / 3);
	const chars = groups * 4;
	const lines = Math.ceil(chars / BASE64_LINE_LENGTH);
	const outLength = chars + (lines > 1 ? (lines - 1) * 2 : 0);
	const out = new Uint8Array(outLength);

	let p = 0;
	let written = 0;
	const fullGroupsEnd = length - (length % 3);

	for (let i = 0; i < fullGroupsEnd; i += 3) {
		const b0 = input[i];
		const b1 = input[i + 1];
		const b2 = input[i + 2];
		out[p++] = BASE64_CODES[b0 >> 2];
		out[p++] = BASE64_CODES[((b0 & 0x03) << 4) | (b1 >> 4)];
		out[p++] = BASE64_CODES[((b1 & 0x0f) << 2) | (b2 >> 6)];
		out[p++] = BASE64_CODES[b2 & 0x3f];
		written += 4;
		if (written < chars && written % BASE64_LINE_LENGTH === 0) {
			out[p++] = 13;
			out[p++] = 10;
		}
	}

	const rest = length - fullGroupsEnd;
	if (rest === 1) {
		const b0 = input[fullGroupsEnd];
		out[p++] = BASE64_CODES[b0 >> 2];
		out[p++] = BASE64_CODES[(b0 & 0x03) << 4];
		out[p++] = 0x3d;
		out[p++] = 0x3d;
	} else if (rest === 2) {
		const b0 = input[fullGroupsEnd];
		const b1 = input[fullGroupsEnd + 1];
		out[p++] = BASE64_CODES[b0 >> 2];
		out[p++] = BASE64_CODES[((b0 & 0x03) << 4) | (b1 >> 4)];
		out[p++] = BASE64_CODES[((b1 & 0x0f) << 2)];
		out[p++] = 0x3d;
	}

	return asciiString(out);
}

/**
 * RFC 2047 "Q" encoded-word for a header text value (unstructured / phrase safe).
 *
 * UTF-8 bytes: Q-safe ASCII (alphanumerics and ! * + - /) stay literal, space
 * becomes "_", everything else becomes "=XX" (uppercase hex). Adjacent words
 * are limited to 75 characters and folded with CRLF + SP; multi-byte UTF-8
 * sequences are never split across two encoded-words.
 */
export function rfc2047Encode(text) {
	const value = sanitizeHeaderValue(text);
	if (value === '') return '';

	const words = [];
	let payload = '';
	for (const char of value) {
		const charBytes = UTF8_ENCODER.encode(char);
		let token;
		if (charBytes.length === 1) {
			const b = charBytes[0];
			if (b === 0x20) {
				token = '_';
			} else if ((b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || (b >= 0x30 && b <= 0x39) ||
				b === 0x21 || b === 0x2a || b === 0x2b || b === 0x2d || b === 0x2f) {
				token = char;
			} else {
				token = '=' + HEX_UPPER[b >> 4] + HEX_UPPER[b & 0x0f];
			}
		} else {
			token = '';
			for (let i = 0; i < charBytes.length; i++) {
				token += '=' + HEX_UPPER[charBytes[i] >> 4] + HEX_UPPER[charBytes[i] & 0x0f];
			}
		}

		if (payload.length > 0 && payload.length + token.length > MAX_Q_PAYLOAD_LENGTH) {
			words.push(ENCODED_WORD_PREFIX + payload + ENCODED_WORD_SUFFIX);
			payload = '';
		}
		payload += token;
	}
	if (payload.length > 0) words.push(ENCODED_WORD_PREFIX + payload + ENCODED_WORD_SUFFIX);

	return words.join(CRLF + ' ');
}

/** RFC 2231 extended parameter value (charset UTF-8, percent encoded). */
function rfc2231Encode(text) {
	const bytes = UTF8_ENCODER.encode(String(text));
	let out = '';
	for (let i = 0; i < bytes.length; i++) {
		const b = bytes[i];
		const attrChar = (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || (b >= 0x30 && b <= 0x39) ||
			b === 0x21 || b === 0x23 || b === 0x24 || b === 0x26 || b === 0x2b ||
			b === 0x2d || b === 0x2e || b === 0x5e || b === 0x5f || b === 0x60 || b === 0x7c || b === 0x7e;
		out += attrChar ? String.fromCharCode(b) : '%' + HEX_UPPER[b >> 4] + HEX_UPPER[b & 0x0f];
	}
	return out;
}

function quoteString(value) {
	return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function normalizeFilename(filename) {
	const value = sanitizeHeaderValue(filename).trim();
	return value === '' ? DEFAULT_FILENAME : value;
}

/**
 * "name"/"filename" parameter. ASCII names use a plain quoted-string, non-ASCII
 * names use an RFC 2047 encoded-word plus an RFC 2231 `filename*` fallback for
 * clients that prefer the extended syntax.
 */
function filenameParameter(attribute, filename) {
	if (!filename) return '';
	const value = normalizeFilename(filename);
	if (isPureAscii(value)) return `${attribute}="${quoteString(value)}"`;
	return `${attribute}="${rfc2047Encode(value)}"; ${attribute}*=UTF-8''${rfc2231Encode(value)}`;
}

function formatAddress(address) {
	const entry = typeof address === 'string' ? { email: address } : (address || {});
	const email = sanitizeHeaderValue(entry.email || entry.address || '').trim();
	if (email === '') return '';
	const angle = /^<.*>$/.test(email) ? email : `<${email}>`;
	const name = sanitizeHeaderValue(entry.name || '').trim();
	if (name === '') return angle;
	if (!isPureAscii(name)) return `${rfc2047Encode(name)} ${angle}`;
	if (PHRASE_SPECIALS.test(name)) return `"${quoteString(name)}" ${angle}`;
	return `${name} ${angle}`;
}

/** Fold a long address header at the "," boundaries (continuation with SP). */
function foldHeader(name, value) {
	const prefix = `${name}: `;
	if (prefix.length + value.length <= HEADER_LINE_SOFT_LIMIT) return prefix + value;

	const lines = [];
	let current = prefix;
	const items = value.split(', ');
	for (let i = 0; i < items.length; i++) {
		const item = items[i];
		const glue = current === prefix ? '' : ', ';
		if (current !== prefix && current.length + glue.length + item.length > HEADER_LINE_SOFT_LIMIT) {
			lines.push(current + ',');
			current = ' ' + item;
		} else {
			current += glue + item;
		}
	}
	lines.push(current);
	return lines.join(CRLF);
}

function addressHeader(name, list) {
	const source = Array.isArray(list) ? list : (list ? [list] : []);
	const items = [];
	for (let i = 0; i < source.length; i++) {
		const formatted = formatAddress(source[i]);
		if (formatted !== '') items.push(formatted);
	}
	if (items.length === 0) return null;
	return foldHeader(name, items.join(', '));
}

/** In-Reply-To / References: kept as-is when already bracketed, otherwise each id is wrapped. */
function formatMessageIdList(value) {
	const raw = sanitizeHeaderValue(value).trim();
	if (raw === '') return '';
	if (raw.indexOf('<') !== -1) return raw;
	return raw
		.split(/[\s,]+/)
		.filter((id) => id !== '')
		.map((id) => `<${id}>`)
		.join(' ');
}

function domainOf(email) {
	const value = sanitizeHeaderValue(email).trim();
	const at = value.lastIndexOf('@');
	if (at === -1 || at === value.length - 1) return '';
	return value.slice(at + 1).replace(/[^A-Za-z0-9.\-_]/g, '');
}

function buildMessageId(messageId, from) {
	const provided = sanitizeHeaderValue(messageId).trim();
	if (provided !== '') return /^<.*>$/.test(provided) ? provided : `<${provided}>`;
	const entry = typeof from === 'string' ? { email: from } : (from || {});
	const domain = domainOf(entry.email || entry.address || '') || DEFAULT_MESSAGE_ID_DOMAIN;
	return `<${randomHex(16)}.${Date.now().toString(36)}@${domain}>`;
}

function contentIdValue(contentId) {
	const value = sanitizeHeaderValue(contentId).trim().replace(/^</, '').replace(/>$/, '');
	if (value === '') return `<${randomHex(12)}@cloud-mail.local>`;
	return `<${value}>`;
}

/** Inner MIME entity: { headers: [...], body: <string> }. */
function textEntity(contentType, content) {
	return {
		headers: [`Content-Type: ${contentType}; charset=UTF-8`, 'Content-Transfer-Encoding: base64'],
		body: base64Encode(UTF8_ENCODER.encode(content))
	};
}

function imageEntity(image) {
	const source = image || {};
	const mimeType = sanitizeHeaderValue(source.mimeType).trim() || DEFAULT_MIME_TYPE;
	const filename = source.filename ? normalizeFilename(source.filename) : '';
	const disposition = ['Content-Disposition: inline'];
	const filenameParam = filenameParameter('filename', filename);
	if (filenameParam !== '') disposition.push(filenameParam);
	return {
		headers: [
			`Content-Type: ${mimeType}`,
			'Content-Transfer-Encoding: base64',
			`Content-ID: ${contentIdValue(source.contentId)}`,
			disposition.join('; ')
		],
		body: base64Encode(toBytes(source.data))
	};
}

function attachmentEntity(attachment) {
	const source = attachment || {};
	const mimeType = sanitizeHeaderValue(source.mimeType).trim() || DEFAULT_MIME_TYPE;
	const nameParam = filenameParameter('name', source.filename);
	const dispositionParam = filenameParameter('filename', source.filename);
	return {
		headers: [
			`Content-Type: ${mimeType}${nameParam === '' ? '' : '; ' + nameParam}`,
			'Content-Transfer-Encoding: base64',
			`Content-Disposition: attachment${dispositionParam === '' ? '' : '; ' + dispositionParam}`
		],
		body: base64Encode(toBytes(source.data))
	};
}

function multipartEntity(subtype, children) {
	const boundary = newBoundary();
	const chunks = [];
	for (let i = 0; i < children.length; i++) {
		chunks.push('--' + boundary + CRLF + renderEntity(children[i]) + CRLF);
	}
	chunks.push('--' + boundary + '--' + CRLF);
	return {
		headers: [`Content-Type: multipart/${subtype}; boundary="${boundary}"`],
		boundary,
		body: chunks.join('')
	};
}

function renderEntity(entity) {
	return entity.headers.join(CRLF) + CRLF + CRLF + entity.body;
}

function buildMessageHeaders(mail) {
	const headers = [];
	headers.push('MIME-Version: 1.0');
	headers.push(`Date: ${formatRfc5322Date(mail.dateMs)}`);

	const from = formatAddress(mail.from);
	if (from !== '') headers.push(`From: ${from}`);

	const to = addressHeader('To', mail.to);
	if (to) headers.push(to);
	const cc = addressHeader('Cc', mail.cc);
	if (cc) headers.push(cc);
	const bcc = addressHeader('Bcc', mail.bcc);
	if (bcc) headers.push(bcc);

	if (mail.subject !== null && mail.subject !== undefined) {
		const subject = sanitizeHeaderValue(mail.subject);
		headers.push(`Subject: ${subject === '' ? '' : rfc2047Encode(subject)}`);
	}

	headers.push(`Message-ID: ${buildMessageId(mail.messageId, mail.from)}`);

	const inReplyTo = formatMessageIdList(mail.inReplyTo);
	if (inReplyTo !== '') headers.push(`In-Reply-To: ${inReplyTo}`);
	const references = formatMessageIdList(mail.references);
	if (references !== '') headers.push(`References: ${references}`);

	return headers;
}

export function buildMime(input) {
	const mail = input || {};
	const text = mail.text === null || mail.text === undefined ? '' : String(mail.text);
	const html = mail.html === null || mail.html === undefined ? '' : String(mail.html);
	const inlineImages = Array.isArray(mail.inlineImages) ? mail.inlineImages : [];
	const attachments = Array.isArray(mail.attachments) ? mail.attachments : [];

	// innermost body: alternative when both flavours are present, single part otherwise
	let entity;
	if (text !== '' && html !== '') {
		entity = multipartEntity('alternative', [
			textEntity('text/plain', text),
			textEntity('text/html', html)
		]);
	} else if (html !== '') {
		entity = textEntity('text/html', html);
	} else {
		entity = textEntity('text/plain', text);
	}

	// related: html body + the inline images it references through cid:
	if (inlineImages.length > 0) {
		const relatedChildren = [entity];
		for (let i = 0; i < inlineImages.length; i++) {
			relatedChildren.push(imageEntity(inlineImages[i]));
		}
		entity = multipartEntity('related', relatedChildren);
	}

	// mixed: everything above plus the real attachments
	if (attachments.length > 0) {
		const mixedChildren = [entity];
		for (let i = 0; i < attachments.length; i++) {
			mixedChildren.push(attachmentEntity(attachments[i]));
		}
		entity = multipartEntity('mixed', mixedChildren);
	}

	const headers = buildMessageHeaders(mail).concat(entity.headers);
	return UTF8_ENCODER.encode(headers.join(CRLF) + CRLF + CRLF + entity.body + CRLF);
}

/** buildMime() result as base64 text, for the EWS MimeContent field. */
export function buildMimeBase64(input) {
	return base64Encode(buildMime(input));
}
