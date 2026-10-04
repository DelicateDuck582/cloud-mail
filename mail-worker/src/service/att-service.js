import orm from '../entity/orm';
import { att } from '../entity/att';
import { and, eq, isNull, inArray, desc } from 'drizzle-orm';
import r2Service from './r2-service';
import constant from '../const/constant';
import fileUtils from '../utils/file-utils';
import { attConst } from '../const/entity-const';
import { parseHTML } from 'linkedom';
import { v4 as uuidv4 } from 'uuid';
import domainUtils from '../utils/domain-uitls';
import settingService from "./setting-service";

const MIME_OCTET_STREAM = 'application/octet-stream';
// 允许内联展示的 MIME 白名单：image/svg+xml、text/html 等可执行内容永不入内
const MIME_WHITELIST = new Set([
	'image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/avif', 'image/bmp',
	'application/pdf', 'text/plain'
]);
// 子类型的合法性（阻断 CRLF / 路径字符等注入到对象元数据与响应头）
const MIME_SUBTYPE_RE = /^[a-z0-9][a-z0-9.+-]{0,30}$/;

// MIME 归一：白名单之外（含 image/svg+xml、text/html）统一落 application/octet-stream
function normalizeMimeType(rawMime) {
	const mime = String(rawMime ?? '').split(';')[0].trim().toLowerCase();
	if (!mime) {
		return MIME_OCTET_STREAM;
	}
	if (mime === 'image/svg+xml' || mime === 'text/html' || mime === 'application/xhtml+xml') {
		return MIME_OCTET_STREAM;
	}
	const [type, subtype] = mime.split('/');
	if (!type || !subtype || !MIME_SUBTYPE_RE.test(subtype)) {
		return MIME_OCTET_STREAM;
	}
	if (type === 'video' || type === 'audio') {
		return mime;
	}
	return MIME_WHITELIST.has(mime) ? mime : MIME_OCTET_STREAM;
}

// 文件名清洗：剥离控制字符（CR/LF 等）与引号 / 反斜杠，防响应头注入
function sanitizeFilename(rawFilename) {
	const name = String(rawFilename ?? '')
		.replace(/[\r\n\t\x00-\x1f\x7f]/g, '')
		.replace(/["\\]/g, '_')
		.trim()
		.slice(0, 200);
	return name || 'file';
}

// 构造 Content-Disposition：双引号包裹 + ASCII fallback + RFC 5987 filename*，防头注入
function buildContentDisposition(kind, rawFilename) {
	const filename = sanitizeFilename(rawFilename);
	const asciiFallback = filename.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_') || 'file';
	const encoded = encodeURIComponent(filename).replace(/['()*]/g, ch => '%' + ch.charCodeAt(0).toString(16).toUpperCase());
	return `${kind === 'inline' ? 'inline' : 'attachment'}; filename="${asciiFallback}"; filename*=UTF-8''${encoded}`;
}

// 附件元数据统一归一（入库 / 入 COS 共用）：MIME 白名单化 + 文件名清洗 + disposition 清洗
// inline 仅在 MIME 归一后属于白名单时才允许，其余一律强制 attachment
function normalizeAttMetadata(rawMime, rawFilename, inline) {
	const contentType = normalizeMimeType(rawMime);
	const filename = sanitizeFilename(rawFilename);
	const allowInline = !!inline && contentType !== MIME_OCTET_STREAM;
	return {
		contentType,
		filename,
		contentDisposition: buildContentDisposition(allowInline ? 'inline' : 'attachment', filename)
	};
}

const attService = {

	async addAtt(c, attachments) {

		for (let attachment of attachments) {

			// 入库 / 入 COS 前统一归一：MIME 白名单（SVG/HTML 强制 octet-stream）+ disposition 清洗
			const meta = normalizeAttMetadata(attachment.mimeType, attachment.filename, !!attachment.contentId);

			const metadate = {
				contentType: meta.contentType,
				contentDisposition: meta.contentDisposition
			}

			if (attachment.contentId) {
				metadate.cacheControl = `max-age=259200`
			}

			// 数据库元数据与 COS 对象元数据保持一致（归一后的 MIME / 清洗后的文件名）
			attachment.mimeType = meta.contentType;
			attachment.filename = meta.filename;

			await r2Service.putObj(c, attachment.key, attachment.content, metadate);

		}

		await orm(c).insert(att).values(attachments).run();
	},

	list(c, params, userId) {
		const { emailId } = params;

		return orm(c).select().from(att).where(
			and(
				eq(att.emailId, emailId),
				eq(att.userId, userId),
				eq(att.type, attConst.type.ATT),
				isNull(att.contentId)
			)
		).all();
	},

	async toImageUrlHtml(c, content) {

		const { r2Domain } = await settingService.query(c);

		const { document } = parseHTML(content);

		const images = Array.from(document.querySelectorAll('img'));

		let imageDataList = [];

		for (const img of images) {

			//邮件正文base64图片转cid附件
			const src = img.getAttribute('src');
			if (src && src.startsWith('data:image')) {
				const file = fileUtils.base64ToFile(src);
				const buff = await file.arrayBuffer();
				const cid = uuidv4().replace(/-/g, '');
				const key = constant.ATTACHMENT_PREFIX + await fileUtils.getBuffHash(buff) + fileUtils.getExtFileName(file.name);

				img.setAttribute('src', 'cid:' + cid);

				const attData = {};
				attData.key = key;
				attData.filename = file.name;
				attData.mimeType = file.type;
				attData.size = file.size;
				attData.buff = buff;
				attData.content = fileUtils.base64ToDataStr(src);
				attData.contentId = cid;

				imageDataList.push(attData);
			}

			//邮件正文站内图片转cid附件
			if (src && (src.startsWith(domainUtils.toOssDomain(r2Domain)) || src.startsWith('attachments/'))) {

				const cid = uuidv4().replace(/-/g, '')
				img.setAttribute('src', 'cid:' + cid);

				const attData = {};

				if (src.startsWith(domainUtils.toOssDomain(r2Domain))) {
					attData.key = src.replace(domainUtils.toOssDomain(r2Domain) + '/','');
				}

				if (src.startsWith('attachments/')) {
					attData.key = src;
				}

				attData.contentId = cid;
				attData.type = attConst.type.EMBED;
				imageDataList.push(attData);

			}

			const hasInlineWidth = img.hasAttribute('width');
			const style = img.getAttribute('style') || '';
			const hasStyleWidth = /(^|\s)width\s*:\s*[^;]+/.test(style);

			if (!hasInlineWidth && !hasStyleWidth) {
				const newStyle = (style ? style.trim().replace(/;$/, '') + '; ' : '') + 'max-width: 100%;';
				img.setAttribute('style', newStyle);
			}
		}

		//查询已有内嵌url图片信息
		const keys = [...new Set(imageDataList.filter(item => !item.content).map(item => item.key))];
		const dbImageList  = await this.selectOneByKeys(c, keys);

		//设置给当前附件
		await Promise.all(imageDataList.map(async image => {
			if (image.content) {
				return;
			}

			const dbImage = dbImageList.find(dbImage => image.key === dbImage.key);
			if (!dbImage) {
				return;
			}

			image.size = dbImage.size;
			image.filename = dbImage.filename;
			image.mimeType = dbImage.mimeType;
			image.contentType = dbImage.mimeType;

			const obj = await r2Service.getObj(c, image.key);
			if (!obj) {
				return;
			}

			image.content = obj instanceof ArrayBuffer ? obj : await obj.arrayBuffer();
		}))

		imageDataList = imageDataList.filter(image => image.content);

		return { imageDataList, html: document.toString() };
	},

	async saveSendAtt(c, attList, userId, accountId, emailId) {

		const attDataList = [];

		for (let att of attList) {
			// 用户可控的 MIME / 文件名：先归一再做 key 与入库，非白名单类型强制 octet-stream + attachment
			const meta = normalizeAttMetadata(att.type, att.filename, false);
			att.mimeType = meta.contentType;
			att.filename = meta.filename;
			att.buff = fileUtils.base64ToUint8Array(att.content);
			att.key = constant.ATTACHMENT_PREFIX + await fileUtils.getBuffHash(att.buff) + fileUtils.getExtFileName(att.filename);
			const attData = { userId, accountId, emailId };
			attData.key = att.key;
			attData.size = att.buff.length;
			attData.filename = att.filename;
			attData.mimeType = meta.contentType;
			attData.type = attConst.type.ATT;
			attDataList.push(attData);
		}

		await orm(c).insert(att).values(attDataList).run();

		for (let att of attList) {
			await r2Service.putObj(c, att.key, att.buff, {
				contentType: att.mimeType,
				contentDisposition: buildContentDisposition('attachment', att.filename)
			});
		}

	},

	async saveArticleAtt(c, attDataList, userId, accountId, emailId) {

		for (let attData of attDataList) {
			attData.userId = userId;
			attData.emailId = emailId;
			attData.accountId = accountId;
			attData.type = attConst.type.EMBED;
			if (!attData.buff) {
				continue;
			}
			// 内嵌图同样归一：只有白名单类型允许 inline，其余强制 octet-stream + attachment
			const meta = normalizeAttMetadata(attData.mimeType, attData.filename, true);
			attData.mimeType = meta.contentType;
			attData.filename = meta.filename;
			await r2Service.putObj(c, attData.key, attData.buff, {
				contentType: meta.contentType,
				cacheControl: `max-age=259200`,
				contentDisposition: meta.contentDisposition
			});
			delete attData.buff;
		}

		await orm(c).insert(att).values(attDataList).run();

	},

	async removeByUserIds(c, userIds) {
		await this.removeAttByField(c, 'user_id', userIds);
	},

	async removeByEmailIds(c, emailIds) {
		await this.removeAttByField(c, 'email_id', emailIds);
	},

	selectByEmailIds(c, emailIds) {
		return orm(c).select().from(att).where(
			and(
				inArray(att.emailId, emailIds),
				eq(att.type, attConst.type.ATT)
			))
			.all();
	},

	async removeAttByField(c, fieldName, fieldValues) {

		const sqlList = [];

		fieldValues.forEach(value => {

			sqlList.push(

				c.env.db.prepare(
					`SELECT a.key, a.att_id
						FROM attachments a
							   JOIN (SELECT key
									 FROM attachments
									 GROUP BY key
									 HAVING COUNT (*) = 1) t
									ON a.key = t.key
						WHERE a.${fieldName} = ?;`
					).bind(value)
			)

			sqlList.push(c.env.db.prepare(`DELETE FROM attachments WHERE ${fieldName} = ?`).bind(value))

		});

		const attListResult = await c.env.db.batch(sqlList);

		const delKeyList = attListResult.flatMap(r => r.results ? r.results.map(row => row.key) : []);

		if (delKeyList.length > 0) {
			try {
				await this.batchDelete(c, delKeyList);
			} catch (e) {
				console.error('删除附件文件失败：', e);
			}
		}

	},

	async batchDelete(c, keys) {
		if (!keys.length) return;

		const BATCH_SIZE = 1000;

		for (let i = 0; i < keys.length; i += BATCH_SIZE) {
			const batch = keys.slice(i, i + BATCH_SIZE);
			await r2Service.delete(c, batch);
		}

	},

	async removeByAccountId(c, accountId) {
		await this.removeAttByField(c, "account_id", [accountId])
	},

	selectOneByKeys(c, keys) {
		if (!keys || keys.length === 0) {
			return []
		}
		return orm(c).select().from(att).where(inArray(att.key, keys)).orderBy(desc(att.attId)).groupBy(att.key).all();
	}
};

export default attService;
