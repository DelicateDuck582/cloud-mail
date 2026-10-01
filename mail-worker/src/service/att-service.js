import orm from '../entity/orm';
import { att } from '../entity/att';
import { and, eq, isNull, inArray, desc, or, count, sql, lt } from 'drizzle-orm';
import user from '../entity/user';
import email from '../entity/email';
import role from '../entity/role';
import r2Service from './r2-service';
import s3Service from './s3-service';
import constant from '../const/constant';
import fileUtils from '../utils/file-utils';
import { parseHTML } from 'linkedom';
import { v4 as uuidv4 } from 'uuid';
import domainUtils from '../utils/domain-uitls';
import settingService from "./setting-service";
import signUtils from '../utils/sign-utils';
import BizError from '../error/biz-error';
import { t } from '../i18n/i18n';
import dayjs from 'dayjs';
import { attConst, isDel } from '../const/entity-const';
import starService from './star-service';

// D1 单条语句最多 100 个绑定参数，统一按 90 分片，留安全余量（keys / ids / emailIds 等 inArray 一律走这里）
const SQL_BIND_LIMIT = 90;
// clearTrash 单次 cron 调用的批次数护栏：最多处理 20 批（约 1800 行），防止超大垃圾桶导致 cron 超时
const CLEAR_TRASH_MAX_BATCHES = 20;
// 管理端批量操作入参上限，超出要求调用方分批
const TOO_MANY_ATT_IDS = `单次操作不能超过 ${SQL_BIND_LIMIT} 个附件，请分批操作 Too many attachment ids (max ${SQL_BIND_LIMIT}), please split into batches`;

const chunkArray = (list, size) => {
	const chunks = [];
	for (let i = 0; i < list.length; i += size) {
		chunks.push(list.slice(i, i + size));
	}
	return chunks;
};

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

// removeAttByField 的 fieldName 会拼进 SQL，只允许内部常量值
const REMOVE_ATT_FIELDS = new Set(['user_id', 'email_id', 'account_id']);

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

	async list(c, params, userId) {
		const { emailId } = params;

		const attList = await orm(c).select().from(att).where(
			and(
				eq(att.emailId, emailId),
				eq(att.userId, userId),
				eq(att.type, attConst.type.ATT),
				isNull(att.contentId)
			)
		).all();

		const { r2Domain } = await settingService.query(c);
		await signUtils.addAttUrl(c, attList, r2Domain);

		return attList;
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

			//邮件正文站内图片转cid附件（去掉签名参数，防止 key 被 ?expires=&sign= 污染）
			const cleanSrc = (src || '').split('?')[0];

			if (cleanSrc && (cleanSrc.startsWith(domainUtils.toOssDomain(r2Domain)) || cleanSrc.startsWith('attachments/'))) {

				const cid = uuidv4().replace(/-/g, '')
				img.setAttribute('src', 'cid:' + cid);

				const attData = {};

				if (cleanSrc.startsWith(domainUtils.toOssDomain(r2Domain))) {
					attData.key = cleanSrc.replace(domainUtils.toOssDomain(r2Domain) + '/','');
				}

				if (cleanSrc.startsWith('attachments/')) {
					attData.key = cleanSrc;
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

		// 内嵌图数量校验前置：超限直接报错，避免先付出 DB 查询 / COS 读取的代价
		if (imageDataList.length > 10) {
			throw new BizError(t('imageAttLimit'));
		}

		//查询已有内嵌url图片信息（只允许引用本人 key，防止通过他人 key 越权读取对象）
		const currentUserId = c?.get?.('user')?.userId ?? null;
		const keys = [...new Set(imageDataList.filter(item => !item.content).map(item => item.key))];
		const dbImageList  = await this.selectOneByKeys(c, keys, currentUserId);

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

	async selectByEmailIds(c, emailIds) {
		if (!emailIds || emailIds.length === 0) {
			return [];
		}
		const rows = [];
		for (const chunk of chunkArray([...new Set(emailIds)], SQL_BIND_LIMIT)) {
			const part = await orm(c).select().from(att).where(
				and(
					inArray(att.emailId, chunk),
					eq(att.type, attConst.type.ATT),
					eq(att.trash, 0)
				))
				.all();
			rows.push(...part);
		}
		return rows;
	},

	async removeAttByField(c, fieldName, fieldValues) {

		// fieldName 由调用方常量传入，但会拼进 SQL：显式白名单断言，防注入
		if (!REMOVE_ATT_FIELDS.has(fieldName)) {
			throw new BizError(`非法的字段名 Illegal field name: ${fieldName}`);
		}

		const delKeyList = [];

		for (const value of fieldValues) {

			// 先按 att_id 精确取出本次要删的行（不再用全局 HAVING COUNT(*)=1 的口径：
			// 同 key 多行时会被伪造认领/计数污染，导致引用归零的文件删不掉而成为孤儿）
			const rowResult = await c.env.db.prepare(
				`SELECT att_id, key FROM attachments WHERE ${fieldName} = ?`
			).bind(value).all();

			const rows = rowResult?.results || [];
			const ids = rows.map(row => row.att_id).filter(id => id != null);
			const keys = [...new Set(rows.map(row => row.key).filter(Boolean))];
			if (ids.length === 0) {
				continue;
			}

			const idChunks = chunkArray(ids, SQL_BIND_LIMIT);
			const keyChunks = chunkArray(keys, SQL_BIND_LIMIT);

			// D1 batch 事务化：同一批内先删行、再按剩余行统计每个 key 的引用数，
			// 把「查引用→删对象→删行」的窗口期竞态收敛为「最多多删一次无人引用的对象」（幂等安全）
			const stmtList = [];
			for (const chunk of idChunks) {
				stmtList.push(c.env.db.prepare(
					`DELETE FROM attachments WHERE att_id IN (${chunk.map(() => '?').join(',')})`
				).bind(...chunk));
			}
			for (const chunk of keyChunks) {
				stmtList.push(c.env.db.prepare(
					`SELECT key, COUNT(*) AS cnt FROM attachments WHERE key IN (${chunk.map(() => '?').join(',')}) GROUP BY key`
				).bind(...chunk));
			}

			const results = await c.env.db.batch(stmtList);

			// batch 结果与语句顺序一致：尾部 keyChunks.length 条为引用统计
			const refMap = {};
			results.slice(idChunks.length).forEach(result => {
				(result?.results || []).forEach(row => { refMap[row.key] = row.cnt; });
			});

			for (const key of keys) {
				if (!(Number(refMap[key]) > 0)) {
					delKeyList.push(key);
				}
			}

		}

		const keysToDelete = [...new Set(delKeyList)];

		if (keysToDelete.length > 0) {
			try {
				await this.batchDelete(c, keysToDelete);
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

	// 按 key 查询附件（只查归属指定用户的行：防止按 key 引用他人对象；分片查询规避 D1 绑定参数上限）
	async selectOneByKeys(c, keys, userId) {
		if (!keys || keys.length === 0) {
			return []
		}
		if (userId === null || userId === undefined) {
			return []
		}
		const rows = [];
		for (const chunk of chunkArray([...new Set(keys.filter(Boolean))], SQL_BIND_LIMIT)) {
			const part = await orm(c).select().from(att).where(
				and(inArray(att.key, chunk), eq(att.userId, userId))
			).orderBy(desc(att.attId)).groupBy(att.key).all();
			rows.push(...part);
		}
		return rows;
	},

	// 附件管理列表：管理员可看全部/按用户筛选，普通用户只能看自己的
	async manageList(c, params, currentUserId, isAdmin) {

		const { userId: filterUserId, emailId, keyword, size = 20, num = 1, trash = 0 } = params;

		const conditions = [
			eq(att.trash, Number(trash) === 1 ? 1 : 0)
		];

		// 非管理员只能看自己的附件
		if (!isAdmin) {
			conditions.push(eq(att.userId, currentUserId));
		} else if (filterUserId) {
			conditions.push(eq(att.userId, Number(filterUserId)));
		}

		if (emailId) {
			conditions.push(eq(att.emailId, Number(emailId)));
		}

		// 关键字：文件名 / 用户邮箱 / 邮件主题
		if (keyword) {
			conditions.push(or(
				sql`${att.filename} LIKE ${'%' + keyword + '%'}`,
				sql`${user.email} LIKE ${'%' + keyword + '%'}`,
				sql`${email.subject} LIKE ${'%' + keyword + '%'}`
			));
		}

		const pageSize = Math.min(Number(size) || 20, 50);
		const pageNum = Math.max(Number(num) || 1, 1);
		const where = and(...conditions);

		const list = await orm(c).select({
			attId: att.attId,
			userId: att.userId,
			emailId: att.emailId,
			accountId: att.accountId,
			key: att.key,
			filename: att.filename,
			mimeType: att.mimeType,
			size: att.size,
			type: att.type,
			disposition: att.disposition,
			createTime: att.createTime,
			trash: att.trash,
			trashTime: att.trashTime,
			userEmail: user.email,
			userRole: role.name,
			subject: email.subject,
			sendEmail: email.sendEmail
		}).from(att)
			.leftJoin(user, eq(user.userId, att.userId))
			.leftJoin(role, eq(role.roleId, user.type))
			.leftJoin(email, eq(email.emailId, att.emailId))
			.where(where)
			.orderBy(desc(att.attId))
			.limit(pageSize)
			.offset((pageNum - 1) * pageSize)
			.all();

		const totalRow = await orm(c).select({ total: count() }).from(att)
			.leftJoin(user, eq(user.userId, att.userId))
			.leftJoin(role, eq(role.roleId, user.type))
			.leftJoin(email, eq(email.emailId, att.emailId))
			.where(where)
			.get();

		const { r2Domain } = await settingService.query(c);

		// admin 用户的权限组显示为"超级管理员"（其角色记录在 DB 里仍是普通角色）
		list.forEach(row => {
			if (row.userEmail && row.userEmail === c.env.admin) {
				row.userRole = '超级管理员';
			}
		});

		await signUtils.addAttUrl(c, list, r2Domain);

		return { list, total: totalRow.total };
	},

	// 删除附件（软删除）：移入垃圾桶，并连带软删原邮件（垃圾桶期间邮件不可看）
	async manageDelete(c, params, currentUserId, isAdmin) {

		const { attIds } = params;
		const idList = String(attIds || '').split(',').map(Number).filter(Boolean);
		if (idList.length === 0) {
			return;
		}

		// 入参上限：超过单条 D1 语句绑定参数上限时要求分批，避免执行期报错
		if (idList.length > SQL_BIND_LIMIT) {
			throw new BizError(TOO_MANY_ATT_IDS);
		}

		const rows = await orm(c).select().from(att).where(inArray(att.attId, idList)).all();

		// 权限：管理员可删任意，普通用户只能删自己的
		// 统一响应：无权限与附件不存在一律静默成功，避免用 200/403 差异枚举他人附件
		const allowed = isAdmin ? rows : rows.filter(r => r.userId === currentUserId);
		if (allowed.length === 0) {
			return;
		}

		const ids = allowed.map(r => r.attId);
		const now = dayjs().format('YYYY-MM-DD HH:mm:ss');

		await orm(c).update(att).set({ trash: 1, trashTime: now }).where(inArray(att.attId, ids)).run();

		// 连带软删原邮件 + 该邮件的全部附件（保持邮件与附件状态一致，避免垃圾桶期间/7天清理后产生孤儿附件）
		const emailIds = [...new Set(allowed.map(r => r.emailId).filter(Boolean))];
		if (emailIds.length > 0) {
			await orm(c).update(email).set({ isDel: isDel.DELETE, trash: 1, trashTime: now }).where(inArray(email.emailId, emailIds)).run();
			await orm(c).update(att).set({ trash: 1, trashTime: now }).where(and(inArray(att.emailId, emailIds), eq(att.trash, 0))).run();
		}
	},

	// 物理删除一批附件行：先删行，再按剩余行统计每个 key 的引用数，引用归零才删存储对象
	// 顺序保证把「查引用→删对象→删行」的窗口期竞态收敛为「最多多删一次无人引用的对象」（幂等安全），不会漏删产生孤儿
	async purgeAttRows(c, rows) {

		const ids = rows.map(r => r.attId);
		const keys = [...new Set(rows.map(r => r.key).filter(Boolean))];

		for (const chunk of chunkArray(ids, SQL_BIND_LIMIT)) {
			await orm(c).delete(att).where(inArray(att.attId, chunk)).run();
		}

		const delKeys = [];
		if (keys.length > 0) {
			const remainMap = new Map();
			for (const chunk of chunkArray(keys, SQL_BIND_LIMIT)) {
				const refRows = await orm(c).select({ key: att.key, cnt: count(att.attId) }).from(att)
					.where(inArray(att.key, chunk))
					.groupBy(att.key)
					.all();
				refRows.forEach(r => { remainMap.set(r.key, Number(r.cnt) || 0); });
			}
			for (const key of keys) {
				if ((remainMap.get(key) || 0) === 0) {
					delKeys.push(key);
				}
			}
		}

		if (delKeys.length > 0) {
			try {
				await this.batchDelete(c, delKeys);
			} catch (e) {
				// 行已删除：存储删除失败只留下不可访问的孤儿对象（可后续清理），不影响调用方继续推进
				console.error('删除附件文件失败：', e);
			}
		}

		return { ids, keys, delKeys };
	},

	// 物理删除邮件：只有该邮件已无任何附件记录时才删（与附件清理保持同一判定口径）
	// 删除邮件时同步清理收藏记录，避免残留孤儿 star 行（参照 email-service.physicsDelete）
	async deleteEmailsWithoutAtt(c, emailIds) {

		const ids = [...new Set((emailIds || []).filter(Boolean))];
		if (ids.length === 0) {
			return [];
		}

		const remainSet = new Set();
		for (const chunk of chunkArray(ids, SQL_BIND_LIMIT)) {
			const remaining = await orm(c).select({ emailId: att.emailId }).from(att)
				.where(inArray(att.emailId, chunk))
				.all();
			remaining.forEach(r => remainSet.add(r.emailId));
		}

		const delEmailIds = ids.filter(id => !remainSet.has(id));
		if (delEmailIds.length === 0) {
			return [];
		}

		for (const chunk of chunkArray(delEmailIds, SQL_BIND_LIMIT)) {
			await orm(c).delete(email).where(inArray(email.emailId, chunk)).run();
			await starService.removeByEmailIds(c, chunk);
		}

		return delEmailIds;
	},

	// 彻底删除垃圾桶附件（仅超级管理员）：删 DB 记录 + 删 COS 文件
	async manageTrashDelete(c, params, currentUserId, isAdmin) {

		if (!isAdmin) {
			throw new BizError(t('unauthorized'), 403);
		}

		const { attIds } = params;
		const idList = String(attIds || '').split(',').map(Number).filter(Boolean);
		if (idList.length === 0) {
			return;
		}

		// 入参上限：超过单条 D1 语句绑定参数上限时要求分批，避免执行期报错
		if (idList.length > SQL_BIND_LIMIT) {
			throw new BizError(TOO_MANY_ATT_IDS);
		}

		const rows = await orm(c).select().from(att)
			.where(and(inArray(att.attId, idList), eq(att.trash, 1)))
			.all();

		if (rows.length === 0) {
			return;
		}

		// 先删行、再按剩余引用删对象（只有引用计数归零的 key 才真正删除文件）
		await this.purgeAttRows(c, rows);

		// 彻底删除判定统一：只有该邮件已无任何附件记录时才物理删除邮件（防止误删仍有附件的邮件）
		await this.deleteEmailsWithoutAtt(c, [...new Set(rows.map(r => r.emailId).filter(Boolean))]);
	},

	// 定时清理：垃圾桶中超过 7 天的附件彻底删除
	// D1 单条语句最多 100 个绑定参数：所有批量查询按 ≤90 分片循环；单次 cron 最多处理 CLEAR_TRASH_MAX_BATCHES 批，防超时
	async clearTrash(c) {

		const sevenDaysAgo = dayjs().subtract(7, 'day').format('YYYY-MM-DD HH:mm:ss');

		// 附件清理：首查询加 LIMIT 循环处理，直到无过期附件或达到单次 cron 批次数护栏
		for (let batch = 0; batch < CLEAR_TRASH_MAX_BATCHES; batch++) {

			const rows = await orm(c).select().from(att)
				.where(and(eq(att.trash, 1), lt(att.trashTime, sevenDaysAgo)))
				.limit(SQL_BIND_LIMIT)
				.all();

			if (rows.length === 0) {
				break;
			}

			// 先删行、再按剩余引用删对象
			await this.purgeAttRows(c, rows);

			// 物理删除关联邮件：只删"删除后没有任何剩余附件记录"的邮件
			await this.deleteEmailsWithoutAtt(c, [...new Set(rows.map(r => r.emailId).filter(Boolean))]);

			if (rows.length < SQL_BIND_LIMIT) {
				break;
			}
		}

		// 7 天邮件清理：垃圾桶中超过 7 天的邮件物理删除，连带删除其仍处垃圾桶的附件（引用计数删 COS）
		const delEmailRows = await orm(c).select({ emailId: email.emailId }).from(email)
			.where(and(eq(email.trash, 1), lt(email.trashTime, sevenDaysAgo)))
			.limit(SQL_BIND_LIMIT)
			.all();

		if (delEmailRows.length > 0) {

			const delEmailIds = delEmailRows.map(r => r.emailId);

			const trashAttRows = [];
			for (const chunk of chunkArray(delEmailIds, SQL_BIND_LIMIT)) {
				const part = await orm(c).select().from(att)
					.where(and(inArray(att.emailId, chunk), eq(att.trash, 1)))
					.all();
				trashAttRows.push(...part);
			}

			if (trashAttRows.length > 0) {
				await this.purgeAttRows(c, trashAttRows);
			}

			for (const chunk of chunkArray(delEmailIds, SQL_BIND_LIMIT)) {
				await orm(c).delete(email).where(inArray(email.emailId, chunk)).run();
				await starService.removeByEmailIds(c, chunk);
			}
		}
	},

	// 恢复垃圾桶附件：普通用户只能恢复自己的，管理员可恢复任意用户的；连带恢复原邮件
	async manageRestore(c, params, currentUserId, isAdmin) {

		const { attIds } = params;
		const idList = Array.isArray(attIds) ? attIds : String(attIds || '').split(',').map(Number);
		const validIds = idList.map(Number).filter(Boolean);
		if (validIds.length === 0) {
			return;
		}

		// 入参上限：超过单条 D1 语句绑定参数上限时要求分批，避免执行期报错
		if (validIds.length > SQL_BIND_LIMIT) {
			throw new BizError(TOO_MANY_ATT_IDS);
		}

		const rows = await orm(c).select().from(att)
			.where(and(inArray(att.attId, validIds), eq(att.trash, 1)))
			.all();

		const allowed = isAdmin ? rows : rows.filter(r => r.userId === currentUserId);
		if (allowed.length === 0) {
			// 请求了附件但没有权限：拒绝而非静默成功
			if (rows.length > 0) {
				throw new BizError(t('unauthorized'), 403);
			}
			return;
		}

		const ids = allowed.map(r => r.attId);
		await orm(c).update(att).set({ trash: 0, trashTime: null }).where(inArray(att.attId, ids)).run();

		// 连带恢复原邮件 + 该邮件的全部垃圾桶附件（is_del=0 + trash=0，保持状态一致，重新可见）
		const emailIds = [...new Set(allowed.map(r => r.emailId).filter(Boolean))];
		if (emailIds.length > 0) {
			await orm(c).update(email).set({ isDel: isDel.NORMAL, trash: 0, trashTime: null }).where(inArray(email.emailId, emailIds)).run();
			await orm(c).update(att).set({ trash: 0, trashTime: null }).where(and(inArray(att.emailId, emailIds), eq(att.trash, 1))).run();
		}
	},

	// 附件使用量统计：数据库附件记录 + COS 实际存储量 + 总容量配置
	async getUsage(c) {

		const setting = await settingService.query(c);

		const stats = await orm(c).select({
			count: count(),
			totalSize: sql`COALESCE(SUM(${att.size}), 0)`
		}).from(att).get();

		let cos = { count: 0, totalSize: 0 };
		try {
			const storageType = await r2Service.storageType(c);
			if (storageType === 'S3') {
				cos = await s3Service.getBucketUsage(c);
			}
		} catch (e) {
			console.error('COS usage error:', e);
			// COS 不可用时同样标记故障，让后续附件读写自动回退 KV
			r2Service.markS3Failed();
		}

		return {
			attCount: stats.count,
			attSize: stats.totalSize,
			cosCount: cos.count,
			cosSize: cos.totalSize,
			// COS 扫描达到页数上限时为不完整统计，透传给前端提示
			cosIncomplete: !!cos.incomplete,
			cosQuota: Number(setting.cosQuota) || 0,
			s3Expire: setting.s3Expire || ''
		};
	}
};

export default attService;
