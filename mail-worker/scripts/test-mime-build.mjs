/**
 * Self test for src/ews/mime-build.js — run with plain node, no packages:
 *
 *   cd mail-worker && node scripts/test-mime-build.mjs
 *
 * The production file lives in a CommonJS package scope (mail-worker/package.json
 * has no "type"), so it is imported through its file URL and, if node refuses to
 * parse it as ESM, retried from a data: URL holding the very same source.
 */

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const MODULE_URL = new URL('../src/ews/mime-build.js', import.meta.url);

async function loadBuilder(url) {
	try {
		return await import(url.href);
	} catch (error) {
		console.warn(`  (file URL import failed: ${error.message} — retrying through a data: URL)`);
		const source = await readFile(url, 'utf8');
		return import('data:text/javascript;base64,' + Buffer.from(source, 'utf8').toString('base64'));
	}
}

const { buildMime, buildMimeBase64, rfc2047Encode, base64Encode } = await loadBuilder(MODULE_URL);

const DECODER = new TextDecoder('utf-8');
const ENCODER = new TextEncoder();
const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

const decode = (message) => DECODER.decode(message);

/** Every base64 body line of the message (used for the 76 column check). */
function base64BodyLines(raw) {
	return raw.split('\r\n').filter((line) => /^[A-Za-z0-9+/]{4,}={0,2}$/.test(line));
}

/** Decoding (utf-8) of every base64 blob in the message, joined with "|". */
function decodeAllBodies(raw) {
	const blobs = [];
	let current = [];
	for (const line of raw.split('\r\n')) {
		if (/^[A-Za-z0-9+/]{4,}={0,2}$/.test(line)) {
			current.push(line);
		} else if (current.length > 0) {
			blobs.push(current.join(''));
			current = [];
		}
	}
	if (current.length > 0) blobs.push(current.join(''));
	return blobs.map((blob) => Buffer.from(blob, 'base64').toString('utf8')).join('|');
}

/** Header value including its folded continuation lines (CRLF + SP kept). */
function headerValue(raw, name) {
	const match = raw.match(new RegExp(`^${name}: ([^\\r\\n]*(?:\\r\\n [^\\r\\n]*)*)`, 'm'));
	assert.ok(match, `${name} header present`);
	return match[1];
}

/** Decode the Q encoded-words of a header value back to UTF-8 text. */
function decodeEncodedWords(value) {
	const words = value.split(/\r\n[ ]/).filter((word) => word.startsWith('=?UTF-8?q?'));
	const bytes = [];
	for (const word of words) {
		const payload = word.slice('=?UTF-8?q?'.length, -2);
		for (let i = 0; i < payload.length; i++) {
			const char = payload[i];
			if (char === '_') {
				bytes.push(0x20);
			} else if (char === '=') {
				bytes.push(parseInt(payload.slice(i + 1, i + 3), 16));
				i += 2;
			} else {
				bytes.push(char.charCodeAt(0));
			}
		}
	}
	return DECODER.decode(Uint8Array.from(bytes));
}

function isLeakingHeaderLine(raw, name) {
	const headerBlock = raw.slice(0, raw.indexOf('\r\n\r\n'));
	return headerBlock.split('\r\n').some((line) => line.startsWith(name + ':'));
}

const cases = [];
function testCase(name, fn) {
	cases.push({ name, fn });
}

// ---------------------------------------------------------------- case 1 ----

const PNG_IMAGE = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4, 5, 6, 7]);
const PNG_IMAGE_2 = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 9, 8, 7, 6, 5]);
const PDF_BYTES = Uint8Array.from([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37, 0x0a, 0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a]);
const CSV_BYTES = ENCODER.encode('id,name\n1,张三\n2,李四\n');

const DATE_MS = Date.UTC(2026, 9, 1, 12, 0, 0);

const FULL_MESSAGE = buildMime({
	from: { email: 'sender@example.com', name: '张伟' },
	to: [{ email: 'rcpt@example.com', name: '李四' }],
	cc: [{ email: 'cc@example.com' }],
	subject: '测试主题 Hello World — Quarterly Report (2026)',
	dateMs: DATE_MS,
	messageId: '<abc123@example.com>',
	inReplyTo: '<parent@example.com>',
	references: '<r1@example.com>, <r2@example.com>',
	text: '纯文本正文第一行\n第二行 with plain text',
	html: '<html><body><p>hi 中文</p><img src="cid:img1@local"><img src="cid:img2@local"></body></html>',
	inlineImages: [
		{ contentId: 'img1@local', filename: '图1.png', mimeType: 'image/png', data: PNG_IMAGE },
		{ contentId: 'img2@local', filename: '图2.png', mimeType: 'image/jpeg', data: PNG_IMAGE_2 }
	],
	attachments: [
		{ filename: '季度报告.pdf', mimeType: 'application/pdf', data: PDF_BYTES },
		{ filename: 'data.csv', mimeType: 'text/csv', data: CSV_BYTES }
	]
});
const FULL_RAW = decode(FULL_MESSAGE);

testCase('case 1: nested multiparts, headers and encodings', () => {
	assert.ok(FULL_MESSAGE instanceof Uint8Array, 'buildMime returns a Uint8Array');
	const boundaryMatches = [...FULL_RAW.matchAll(/Content-Type: multipart\/([a-z]+); boundary="([^"]+)"/g)];
	assert.deepEqual(boundaryMatches.map((m) => m[1]), ['mixed', 'related', 'alternative'], 'mixed > related > alternative order');
	const [mixed, related, alternative] = boundaryMatches.map((m) => m[2]);
	for (const boundary of [mixed, related, alternative]) {
		assert.match(boundary, /^----=_Part_[0-9a-f]{16}$/, `boundary shape: ${boundary}`);
	}
	assert.equal(new Set([mixed, related, alternative]).size, 3, 'each level uses a unique boundary');

	const mixedOpen = FULL_RAW.indexOf('--' + mixed);
	const mixedClose = FULL_RAW.indexOf('--' + mixed + '--');
	const relatedOpen = FULL_RAW.indexOf('--' + related);
	const relatedClose = FULL_RAW.indexOf('--' + related + '--');
	const alternativeOpen = FULL_RAW.indexOf('--' + alternative);
	assert.ok(mixedOpen !== -1 && mixedClose > mixedOpen, 'mixed delimiters present');
	assert.ok(relatedOpen > mixedOpen && relatedClose < mixedClose, 'related nested inside mixed');
	assert.ok(alternativeOpen > relatedOpen && alternativeOpen < relatedClose, 'alternative nested inside related');

	// part headers
	assert.equal((FULL_RAW.match(/Content-Transfer-Encoding: base64/g) || []).length, 6, '2 text + 2 inline + 2 attachment parts are base64');
	assert.ok(FULL_RAW.includes('Content-ID: <img1@local>') && FULL_RAW.includes('Content-ID: <img2@local>'), 'inline Content-ID headers');
	assert.equal((FULL_RAW.match(/Content-Disposition: inline/g) || []).length, 2, 'inline images use inline disposition');
	assert.equal((FULL_RAW.match(/Content-Disposition: attachment/g) || []).length, 2, 'attachments use attachment disposition');
	assert.match(FULL_RAW, /^MIME-Version: 1\.0$/m);
	assert.match(FULL_RAW, /^From: =\?UTF-8\?q\?[^\r\n]*\?= <sender@example\.com>$/m, 'non-ASCII display name is RFC2047 encoded');
	assert.match(FULL_RAW, /^To: =\?UTF-8\?q\?[^\r\n]*\?= <rcpt@example\.com>$/m);
	assert.match(FULL_RAW, /^Cc: <cc@example\.com>$/m);
	assert.match(FULL_RAW, /^Message-ID: <abc123@example\.com>$/m);
	assert.match(FULL_RAW, /^In-Reply-To: <parent@example\.com>$/m);
	assert.match(FULL_RAW, /^References: <r1@example\.com>, <r2@example\.com>$/m);

	// subject + filenames are RFC2047 Q encoded
	const subjectLine = headerValue(FULL_RAW, 'Subject');
	assert.ok(subjectLine.includes('=?UTF-8?q?'), 'Subject uses =?UTF-8?q?');
	assert.equal(decodeEncodedWords(subjectLine), '测试主题 Hello World — Quarterly Report (2026)', 'Subject round-trips');
	assert.ok(/Content-Type: application\/pdf; name="=\?UTF-8\?q\?/.test(FULL_RAW), 'non-ASCII attachment name is encoded');
	assert.ok(/Content-Disposition: attachment; filename="=\?UTF-8\?q\?/.test(FULL_RAW), 'non-ASCII attachment filename is encoded');
	assert.ok(/filename="data\.csv"/.test(FULL_RAW), 'ASCII filename stays a plain quoted-string');

	// Date: hand written RFC5322 (+0000), no locale involved
	const dateLine = headerValue(FULL_RAW, 'Date');
	assert.match(dateLine, /^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} \+0000$/, 'Date format');
	assert.equal(dateLine, `${WEEKDAYS[new Date(DATE_MS).getUTCDay()]}, 01 Oct 2026 12:00:00 +0000`, 'Date value is exact UTC');

	// bodies are base64, folded at 76 columns, and carry the original content
	const bodyLines = base64BodyLines(FULL_RAW);
	assert.ok(bodyLines.length > 0, 'base64 body lines found');
	for (const line of bodyLines) {
		assert.ok(line.length <= 76, `base64 line width ${line.length} <= 76`);
	}
	const decodedBodies = decodeAllBodies(FULL_RAW);
	assert.ok(decodedBodies.includes('cid:img1@local') && decodedBodies.includes('cid:img2@local'), 'html keeps cid: references');
	assert.ok(decodedBodies.includes('纯文本正文第一行'), 'text/plain content survives');
	assert.ok(decodedBodies.includes('季度报告') === false, 'filename is in the header, not the body');
});

// ---------------------------------------------------------------- case 2 ----

testCase('case 2: plain text only message', () => {
	const raw = decode(buildMime({
		from: { email: 'a@example.com' },
		to: [{ email: 'b@example.com' }],
		subject: 'plain',
		dateMs: DATE_MS,
		text: 'hello world'
	}));
	assert.match(raw, /^Content-Type: text\/plain; charset=UTF-8$/m);
	assert.match(raw, /^Content-Transfer-Encoding: base64$/m);
	assert.ok(!raw.includes('multipart/'), 'single part message has no multipart container');
	assert.ok(!raw.includes('Content-ID:'), 'no inline parts');
	assert.ok(raw.startsWith('MIME-Version: 1.0\r\n'), 'MIME-Version comes first');
	assert.match(raw, /^Message-ID: <[0-9a-f]{32}\.[a-z0-9]+@example\.com>$/m, 'Message-ID generated with the sender domain');
	assert.ok(decodeAllBodies(raw).includes('hello world'));
});

// ---------------------------------------------------------------- case 3 ----

testCase('case 3: header injection is neutralised', () => {
	const raw = decode(buildMime({
		from: { email: 'a@example.com', name: 'evil\r\nX-Evil-From: 1' },
		to: [{ email: 'b@example.com' }],
		subject: 'harmless\r\nBcc: evil@x',
		dateMs: DATE_MS,
		text: 'hi'
	}));
	assert.ok(!isLeakingHeaderLine(raw, 'Bcc'), 'no Bcc header line');
	assert.ok(!isLeakingHeaderLine(raw, 'X-Evil-From'), 'no injected X-Evil-From header line');
	assert.ok(!raw.includes('\r\nBcc:'), 'no CRLF + Bcc sequence');
	assert.equal((raw.match(/\r\n/g) || []).length, raw.split('\r\n').length - 1, 'sane line endings');
	const headerBlock = raw.slice(0, raw.indexOf('\r\n\r\n'));
	assert.equal(headerBlock.split('\r\n').length, 8, 'exactly MIME-Version/Date/From/To/Subject/Message-ID + Content-Type/Content-Transfer-Encoding');
	assert.equal(decodeEncodedWords(headerValue(raw, 'Subject')), 'harmless Bcc: evil@x', 'injected text is folded into the subject value');
});

// ---------------------------------------------------------------- case 4 ----

testCase('case 4: 3MB attachment encoding performance', () => {
	const size = 3 * 1024 * 1024;
	const big = new Uint8Array(size);
	for (let offset = 0; offset < size; offset += 65536) {
		crypto.getRandomValues(big.subarray(offset, Math.min(offset + 65536, size)));
	}
	const started = Date.now();
	const base64 = buildMimeBase64({
		from: { email: 'a@example.com' },
		to: [{ email: 'b@example.com' }],
		subject: 'big attachment',
		dateMs: DATE_MS,
		text: 'see attachment',
		attachments: [{ filename: 'big.bin', mimeType: 'application/octet-stream', data: big }]
	});
	const elapsed = Date.now() - started;
	assert.ok(base64.length > 4_000_000, `base64 output is ${base64.length} chars`);
	assert.ok(elapsed < 500, `buildMimeBase64 took ${elapsed}ms (< 500ms)`);
	const lines = base64.split('\r\n');
	assert.ok(lines.every((line) => line.length <= 76), '3MB payload still folded at 76 columns');
	assert.equal(lines.join('').length % 4, 0, 'base64 total length is a multiple of 4');
	console.log(`  3MB random attachment -> ${(base64.length / 1024 / 1024).toFixed(2)} MiB base64 in ${elapsed}ms`);
});

// ---------------------------------------------------------------- case 5 ----

testCase('case 5: base64Encode matches btoa', () => {
	assert.equal(base64Encode(new Uint8Array(0)), '', 'empty input');
	assert.equal(base64Encode(Uint8Array.from([0x66])), btoa('f'));
	assert.equal(base64Encode(Uint8Array.from([0x66, 0x6f])), btoa('fo'));
	assert.equal(base64Encode(Uint8Array.from([0x66, 0x6f, 0x6f])), btoa('foo'));
	assert.equal(base64Encode(Uint8Array.from([0x66, 0x6f, 0x6f, 0x62])), btoa('foob'));
	for (let round = 0; round < 25; round++) {
		const length = Math.floor(Math.random() * 200);
		const sample = new Uint8Array(length);
		crypto.getRandomValues(sample);
		let binary = '';
		for (const byte of sample) binary += String.fromCharCode(byte);
		assert.equal(base64Encode(sample).replace(/\r\n/g, ''), btoa(binary), `random ${length} byte sample`);
	}
	// helpers that EWS reuses
	assert.equal(rfc2047Encode('abc XYZ-123'), '=?UTF-8?q?abc_XYZ-123?=');
	assert.equal(rfc2047Encode('A\r\nB'), '=?UTF-8?q?A_B?=');
	const long = rfc2047Encode('中文'.repeat(40));
	const words = long.split('\r\n ');
	assert.ok(words.length > 1, 'long subject is folded into several encoded-words');
	for (const word of words) {
		assert.ok(word.length <= 75, `encoded-word length ${word.length} <= 75`);
	}
	assert.equal(decodeEncodedWords(long), '中文'.repeat(40), 'folded encoded-words round-trip');
});

// ---------------------------------------------------------------- runner ----

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
