import { describe, it, expect } from 'vitest';
import { sanitizeHtml, sanitizeCss, isSafeUrl } from '../src/utils/html-sanitize';
import emailHtmlTemplate from '../src/template/email-html';

describe('html-sanitize', () => {

	it('移除 script 标签及其内容', () => {
		const out = sanitizeHtml('<div>hello<script>alert(1)<\/script>world</div>');
		expect(out).not.toContain('script');
		expect(out).not.toContain('alert');
		expect(out).toContain('hello');
		expect(out).toContain('world');
	});

	it('移除 on* 事件属性，保留 img', () => {
		const out = sanitizeHtml('<img src="https://a.com/1.png" onerror="steal()" onload="x()" alt="pic">');
		expect(out).toContain('<img');
		expect(out).toContain('src="https://a.com/1.png"');
		expect(out).not.toContain('onerror');
		expect(out).not.toContain('onload');
		expect(out).toContain('alt="pic"');
	});

	it('移除 javascript: 协议 URL，保留 https/mailto', () => {
		const out = sanitizeHtml('<a href="javascript:alert(1)" onclick="x()">bad</a><a href="https://ok.com" target="_blank">good</a><a href="mailto:a@b.com">mail</a>');
		expect(out).not.toContain('javascript:');
		expect(out).not.toContain('onclick');
		expect(out).toContain('https://ok.com');
		expect(out).toContain('mailto:a@b.com');
		expect(out).toContain('target="_blank"');
	});

	it('移除 iframe/object/embed/svg/math 危险标签', () => {
		const out = sanitizeHtml('<iframe src="https://evil.com"></iframe><object data="x"></object><embed src="y"><svg onload="alert(1)"></svg><math><mtext></mtext></math>ok');
		expect(out).not.toContain('iframe');
		expect(out).not.toContain('object');
		expect(out).not.toContain('embed');
		expect(out).not.toContain('svg');
		expect(out).not.toContain('math');
		expect(out).toContain('ok');
	});

	it('移除表单控件（form 拆标签保留文本，input/button 移除）', () => {
		const out = sanitizeHtml('<form action="https://evil.com"><input value="x"><button>go</button>text</form>');
		expect(out).not.toContain('form');
		expect(out).not.toContain('input');
		expect(out).not.toContain('button');
		expect(out).not.toContain('action=');
		expect(out).toContain('text');
	});

	it('移除 style 中的 javascript: url()，保留正常 CSS', () => {
		const css = sanitizeCss('background:url(javascript:alert(1));color:#fff');
		expect(css).not.toContain('javascript:');
		expect(css).toContain('color:#fff');

		const out = sanitizeHtml('<div style="background:url(javascript:alert(1));color:red">x</div>');
		expect(out).not.toContain('javascript:');
		expect(out).toContain('color:red');
	});

	it('data: 仅允许图片，data:text/html 被移除', () => {
		expect(isSafeUrl('data:image/png;base64,AAAA')).toBe(true);
		expect(isSafeUrl('data:text/html;base64,AAAA')).toBe(false);
		expect(isSafeUrl('javascript:alert(1)')).toBe(false);
		expect(isSafeUrl('vbscript:msgbox(1)')).toBe(false);
		expect(isSafeUrl('https://ok.com')).toBe(true);
		expect(isSafeUrl('{{domain}}attachments/abc.png')).toBe(true);
		expect(isSafeUrl('/attachments/abc.png')).toBe(true);
		expect(isSafeUrl('//cdn.example.com/x.png')).toBe(true);
	});

	it('srcset 含非法 URL 时移除整个 srcset', () => {
		const bad = sanitizeHtml('<img src="https://a.com/1.png" srcset="javascript:alert(1) 1x">');
		expect(bad).not.toContain('srcset');

		const good = sanitizeHtml('<img src="https://a.com/1.png" srcset="https://a.com/1.png 1x, https://a.com/2.png 2x">');
		expect(good).toContain('srcset');
	});

	it('保留正常排版标签与内嵌图片占位符', () => {
		const out = sanitizeHtml('<table border="1"><tr><td style="color:#333">cell</td></tr></table><p><strong>bold</strong></p>');
		expect(out).toContain('<table');
		expect(out).toContain('<td');
		expect(out).toContain('style="color:#333"');
		expect(out).toContain('<strong>');
		expect(out).toContain('cell');

		const imgOut = sanitizeHtml('<img src="{{domain}}attachments/abc.png" alt="图">');
		expect(imgOut).toContain('{{domain}}attachments/abc.png');
	});

	it('白名单外标签拆标签保留文本', () => {
		const out = sanitizeHtml('<marquee>滚动的字</marquee><custom-tag>自定义</custom-tag>');
		expect(out).not.toContain('marquee');
		expect(out).not.toContain('custom-tag');
		expect(out).toContain('滚动的字');
		expect(out).toContain('自定义');
	});

	it('空/非字符串输入原样返回', () => {
		expect(sanitizeHtml('')).toBe('');
		expect(sanitizeHtml(null)).toBe(null);
		expect(sanitizeHtml(undefined)).toBe(undefined);
	});

	it('TG 预览模板 emailHtmlTemplate 输出清洗后的邮件内容', () => {
		const out = emailHtmlTemplate(
			'<script>alert(1)<\/script><img src="https://x.com/a.png" onerror="steal()"><div style="background:url(javascript:bad())">hi</div>',
			'https://oss.example.com'
		);
		expect(out).not.toContain('alert(1)');
		expect(out).not.toContain('steal()');
		expect(out).not.toContain('onerror');
		expect(out).not.toContain('javascript:');
		expect(out).toContain('https://x.com/a.png');
		expect(out).toContain('hi');
	});

	it('TG 预览模板 body style 被清洗后注入', () => {
		const out = emailHtmlTemplate(
			'<body style="background:#fff;background:url(javascript:bad())"><p>ok</p></body>',
			'https://oss.example.com'
		);
		expect(out).toContain('background:#fff');
		expect(out).not.toContain('javascript:');
		expect(out).toContain('ok');
	});
});
