/**
 * 邮件 HTML 前端白名单清洗（纵深防御）。
 * 后端 mail-worker 存储时已清洗（src/utils/html-sanitize.js），此处为渲染前二次防线：
 *  - 兜底已入库的旧邮件 / 未经过后端清洗的数据
 *  - 渲染点：邮件详情 ShadowHtml、回复/转发编辑器注入、列表摘要文本提取
 * 规则与后端保持一致（DOMParser 解析，事件属性、危险标签、javascript: URL 一律移除）。
 */

// 标签白名单（邮件排版常用）
const SAFE_TAGS = new Set([
	'a', 'abbr', 'address', 'article', 'aside', 'b', 'bdi', 'bdo', 'big', 'blockquote', 'br',
	'caption', 'center', 'cite', 'code', 'col', 'colgroup', 'dd', 'del', 'details', 'dfn', 'div',
	'dl', 'dt', 'em', 'figcaption', 'figure', 'font', 'footer', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
	'header', 'hr', 'i', 'img', 'ins', 'kbd', 'li', 'main', 'mark', 'nav', 'ol', 'p', 'picture', 'pre',
	'q', 'rp', 'rt', 'ruby', 's', 'samp', 'section', 'small', 'source', 'span', 'strike', 'strong',
	'sub', 'summary', 'sup', 'table', 'tbody', 'td', 'tfoot', 'th', 'thead', 'track', 'tr', 'tt', 'u',
	'ul', 'var', 'video', 'audio', 'wbr'
]);

// 危险标签：整体移除（连同内容）
const REMOVE_TAGS = new Set([
	'script', 'style', 'iframe', 'object', 'embed', 'applet', 'svg', 'math', 'meta', 'link',
	'base', 'template', 'noscript', 'noframes', 'frame', 'frameset', 'dialog', 'portal'
]);

// 表单相关标签：移除元素本身
const FORM_TAGS = new Set([
	'form', 'fieldset', 'legend', 'label', 'input', 'button', 'select', 'option', 'optgroup',
	'textarea', 'datalist', 'output', 'progress', 'meter', 'keygen'
]);

// 属性白名单：* 为通用属性，其余按标签
const SAFE_ATTRS = {
	'*': ['style', 'title', 'dir', 'lang', 'align', 'width', 'height'],
	'a': ['href', 'name', 'target', 'rel', 'hreflang'],
	'img': ['src', 'alt', 'srcset', 'longdesc', 'usemap'],
	'video': ['src', 'controls', 'poster', 'muted', 'loop', 'preload', 'playsinline', 'width', 'height'],
	'audio': ['src', 'controls', 'muted', 'loop', 'preload'],
	'source': ['src', 'type', 'srcset', 'sizes', 'media'],
	'table': ['border', 'cellpadding', 'cellspacing', 'bgcolor', 'summary', 'rules'],
	'td': ['colspan', 'rowspan', 'headers', 'abbr', 'scope', 'bgcolor', 'nowrap'],
	'th': ['colspan', 'rowspan', 'headers', 'abbr', 'scope', 'bgcolor', 'nowrap'],
	'tr': ['bgcolor'],
	'col': ['span', 'width', 'bgcolor'],
	'colgroup': ['span', 'width', 'bgcolor'],
	'ol': ['start', 'type'],
	'li': ['value', 'type'],
	'ul': ['type'],
	'blockquote': ['cite'],
	'q': ['cite'],
	'del': ['cite', 'datetime'],
	'ins': ['cite', 'datetime'],
	'pre': ['wrap']
};

// 需要校验 URL 协议的属性
const URL_ATTRS = new Set(['href', 'src', 'poster', 'cite', 'longdesc', 'usemap']);

// URL 解析基址：仅用于把相对路径解析成绝对 URL，不产生任何网络请求
const URL_BASE = 'https://example.invalid/';

// 允许的协议（含冒号）
const SAFE_SCHEMES = new Set(['http:', 'https:', 'mailto:', 'tel:', 'cid:']);

// 仅允许图片 data URL（svg 可携带脚本，排除）
const SAFE_DATA_URL = /^data:image\/(png|jpe?g|gif|webp|bmp|avif)(;|,)/i;

export function isSafeUrl(value) {
	// 安全：浏览器解析 URL 前会移除 TAB/LF/CR 等控制字符与空白，
	// 例如 "java\tscript:alert(1)" 实际会被解析为 "javascript:"。
	// 因此先按同等规则剥离 \u0000-\u0020 与 \u007f 控制字符，再交给 URL 解析做协议判定，
	// 避免空白/控制字符混淆绕过（旧实现的正则 ^[a-zA-Z][a-zA-Z0-9+.-]*: 会被此类输入骗过）
	const norm = String(value == null ? '' : value).replace(/[\u0000-\u0020\u007f]+/g, '').trim();
	if (!norm) return true;

	let parsed;
	try {
		parsed = new URL(norm, URL_BASE);
	} catch (e) {
		// 解析失败（畸形 URL）一律视为不安全
		return false;
	}

	const protocol = parsed.protocol.toLowerCase();

	// 相对路径 / {{domain}}xxx / attachments/xxx / //cdn.com 经基址解析后为 http(s)
	if (SAFE_SCHEMES.has(protocol)) {
		return true;
	}

	if (protocol === 'data:') {
		return SAFE_DATA_URL.test(norm);
	}

	// 其余协议（javascript:、vbscript:、blob: 等）与无法识别的形式一律拒绝
	return false;
}

function isSafeSrcset(value) {
	const candidates = String(value || '').split(',');
	for (const cand of candidates) {
		// 浏览器按空白把候选拆成「URL + 描述符」且会剥离控制字符，
		// 这里先剥控制字符再取第一个空白分隔片段，与新 isSafeUrl 的判定保持一致
		const cleaned = cand.replace(/[\u0000-\u001f\u007f]/g, '');
		const url = cleaned.trim().split(/\s+/)[0];
		if (url && !isSafeUrl(url)) {
			return false;
		}
	}
	return true;
}

export function sanitizeCss(css) {
	if (!css) return '';
	let out = String(css);

	if (/expression\s*\(|javascript\s*:|vbscript\s*:|-moz-binding|behavior\s*:|@import|@charset|@namespace/i.test(out)) {
		out = out.replace(/url\(([^)]*)\)/g, '');
	}

	out = out.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, (match, quote, url) => {
		return isSafeUrl(url.trim()) ? match : '';
	});

	return out;
}

/**
 * 清洗邮件 HTML 字符串。使用 DOMParser 解析（script 不会执行、img 不会加载），
 * 返回清洗后的 HTML 片段。
 */
export function sanitizeHtml(html) {
	if (!html || typeof html !== 'string') return html;
	if (html.length > 10 * 1024 * 1024) return html;

	try {
		const doc = new DOMParser().parseFromString(html, 'text/html');
		cleanNode(doc.body);
		return doc.body.innerHTML;
	} catch (e) {
		console.error('sanitizeHtml error:', e);
		return html;
	}
}

function cleanNode(root) {
	const all = Array.from(root.querySelectorAll('*'));

	for (const el of all) {
		const tag = el.tagName.toLowerCase();

		if (REMOVE_TAGS.has(tag)) {
			el.remove();
			continue;
		}

		if (FORM_TAGS.has(tag)) {
			if (tag === 'form' || tag === 'fieldset') {
				el.replaceWith(...el.childNodes);
			} else {
				el.remove();
			}
			continue;
		}

		if (!SAFE_TAGS.has(tag)) {
			el.replaceWith(...el.childNodes);
			continue;
		}

		const allowed = SAFE_ATTRS['*'].concat(SAFE_ATTRS[tag] || []);

		for (const attr of Array.from(el.attributes)) {
			const name = attr.name.toLowerCase();

			if (name.startsWith('on')) {
				el.removeAttribute(attr.name);
				continue;
			}

			if (name === 'autoplay' || name === 'srcdoc' || name === 'formaction' ||
				name === 'formmethod' || name === 'action' || name === 'xlink:href' ||
				name === 'autofocus' || name === 'ping') {
				el.removeAttribute(attr.name);
				continue;
			}

			if (!allowed.includes(name)) {
				el.removeAttribute(attr.name);
				continue;
			}

			if (URL_ATTRS.has(name)) {
				if (!isSafeUrl(attr.value)) {
					el.removeAttribute(attr.name);
				}
				continue;
			}

			if (name === 'srcset') {
				if (!isSafeSrcset(attr.value)) {
					el.removeAttribute(attr.name);
				}
				continue;
			}

			if (name === 'style') {
				const clean = sanitizeCss(attr.value);
				if (clean) {
					el.setAttribute('style', clean);
				} else {
					el.removeAttribute('style');
				}
				continue;
			}
		}

		// 安全：新窗口打开的链接补 rel="noopener noreferrer"，防反向 Tab 劫持
		if (tag === 'a' && (el.getAttribute('target') || '').toLowerCase() === '_blank') {
			const rel = (el.getAttribute('rel') || '').split(/\s+/).filter(Boolean);
			if (!rel.includes('noopener')) rel.push('noopener');
			if (!rel.includes('noreferrer')) rel.push('noreferrer');
			el.setAttribute('rel', rel.join(' '));
		}
	}
}

export default { sanitizeHtml, sanitizeCss, isSafeUrl };
