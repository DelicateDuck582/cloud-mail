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

export function isSafeUrl(value) {
	const url = String(value || '').trim();
	if (!url) return true;

	if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(url)) {
		const scheme = url.split(':')[0].toLowerCase();
		if (scheme === 'http' || scheme === 'https' || scheme === 'mailto' || scheme === 'tel' || scheme === 'cid') {
			return true;
		}
		if (scheme === 'data') {
			return /^data:image\/(png|jpe?g|gif|webp|bmp|avif)(;|,)/i.test(url);
		}
		return false;
	}
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
	}
}

export default { sanitizeHtml, sanitizeCss, isSafeUrl };
