import { parseHTML } from 'linkedom';

/**
 * 邮件 HTML 白名单清洗（防存储型 XSS）。
 * 策略：
 *  - 仅保留邮件排版常用标签（其余标签「拆标签保留文本」）
 *  - 整体移除 script/style/iframe/object/embed/svg/math/meta/link/base 等危险标签
 *  - 移除 form/input/button/select 等表单控件（防钓鱼）
 *  - 移除所有 on* 事件属性、autoplay、srcdoc、action、xlink:href 等危险属性
 *  - href/src 等 URL 属性仅允许 http/https/mailto/tel/cid、data:image/*、相对路径
 *  - style 属性过滤 expression/javascript/vbscript/-moz-binding/@import 与非法 url()
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

export function isSafeUrl(value) {
	const url = String(value || '').trim();
	if (!url) return true;

	// 带协议时仅允许白名单协议
	if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(url)) {
		const scheme = url.split(':')[0].toLowerCase();
		if (scheme === 'http' || scheme === 'https' || scheme === 'mailto' || scheme === 'tel' || scheme === 'cid') {
			return true;
		}
		if (scheme === 'data') {
			// 仅允许图片 data URL（svg 可携带脚本，排除）
			return /^data:image\/(png|jpe?g|gif|webp|bmp|avif)(;|,)/i.test(url);
		}
		return false;
	}

	// 相对路径 / {{domain}}xxx / attachments/xxx / //cdn.com 均放行
	return true;
}

function isSafeSrcset(value) {
	const candidates = String(value || '').split(',');
	for (const cand of candidates) {
		const url = cand.trim().split(/\s+/)[0];
		if (url && !isSafeUrl(url)) {
			return false;
		}
	}
	return true;
}

export function sanitizeCss(css) {
	if (!css) return '';
	let out = String(css);

	// 绝对禁止的危险关键字
	if (/expression\s*\(|javascript\s*:|vbscript\s*:|-moz-binding|behavior\s*:|@import|@charset|@namespace/i.test(out)) {
		out = out.replace(/url\(([^)]*)\)/g, '');
	}

	// 移除非法 url() 片段
	out = out.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, (match, quote, url) => {
		return isSafeUrl(url.trim()) ? match : '';
	});

	return out;
}

/**
 * 直接清洗一个已解析的 linkedom document（就地修改）。
 * 与 imgReplace 共用一次解析，避免重复开销。
 */
export function sanitizeDocument(document) {
	const all = Array.from(document.querySelectorAll('*'));

	for (const el of all) {
		const tag = (el.tagName || '').toLowerCase();

		if (REMOVE_TAGS.has(tag)) {
			el.remove();
			continue;
		}

		if (FORM_TAGS.has(tag)) {
			// form/fieldset 拆标签保留内部文本，其余控件直接移除
			if (tag === 'form' || tag === 'fieldset') {
				el.replaceWith(...el.childNodes);
			} else {
				el.remove();
			}
			continue;
		}

		// 白名单外标签：拆标签保留文本内容
		if (!SAFE_TAGS.has(tag)) {
			el.replaceWith(...el.childNodes);
			continue;
		}

		const allowed = SAFE_ATTRS['*'].concat(SAFE_ATTRS[tag] || []);

		for (const attr of Array.from(el.attributes)) {
			const name = attr.name.toLowerCase();

			// 事件属性一律移除
			if (name.startsWith('on')) {
				el.removeAttribute(attr.name);
				continue;
			}

			// 明确危险/无意义属性
			if (name === 'autoplay' || name === 'srcdoc' || name === 'formaction' ||
				name === 'formmethod' || name === 'action' || name === 'xlink:href' ||
				name === 'autofocus' || name === 'ping') {
				el.removeAttribute(attr.name);
				continue;
			}

			// 白名单校验
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
	}
}

/**
 * 清洗 HTML 字符串（含解析开销，适合独立调用）。
 */
export function sanitizeHtml(content) {
	if (!content || typeof content !== 'string') return content;
	// 防御超大输入导致 CPU/内存耗尽
	if (content.length > 10 * 1024 * 1024) return content;

	try {
		const { document } = parseHTML(content);
		sanitizeDocument(document);
		return document.toString();
	} catch (e) {
		console.error('sanitizeHtml error:', e);
		return content;
	}
}

export default { sanitizeHtml, sanitizeDocument, sanitizeCss, isSafeUrl };

