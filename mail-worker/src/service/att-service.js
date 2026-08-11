import orm from '../entity/orm';
import { att } from '../entity/att';
import { and, eq, isNull, inArray, desc, or, count, sql, lt } from 'drizzle-orm';
import user from '../entity/user';
import email from '../entity/email';
import role from '../entity/role';
import r2Service from './r2-service';
import constant from '../const/constant';
import fileUtils from '../utils/file-utils';
import { attConst } from '../const/entity-const';
import { parseHTML } from 'linkedom';
import { v4 as uuidv4 } from 'uuid';
import domainUtils from '../utils/domain-uitls';
import settingService from "./setting-service";
import signUtils from '../utils/sign-utils';
import BizError from '../error/biz-error';
import { t } from '../i18n/i18n';
import dayjs from 'dayjs';

const attService = {

	async addAtt(c, attachments) {

		for (let attachment of attachments) {

			let metadate = {
				contentType: attachment.mimeType,
			}

			if (!attachment.contentId) {
				metadate.contentDisposition = `attachment;filename=${attachment.filename}`
			} else {
				metadate.contentDisposition = `inline;filename=${attachment.filename}`
				metadate.cacheControl = `max-age=259200`
			}

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
			att.buff = fileUtils.base64ToUint8Array(att.content);
			att.key = constant.ATTACHMENT_PREFIX + await fileUtils.getBuffHash(att.buff) + fileUtils.getExtFileName(att.filename);
			const attData = { userId, accountId, emailId };
			attData.key = att.key;
			attData.size = att.buff.length;
			attData.filename = att.filename;
			attData.mimeType = att.type;
			attData.type = attConst.type.ATT;
			attDataList.push(attData);
		}

		await orm(c).insert(att).values(attDataList).run();

		for (let att of attList) {
			await r2Service.putObj(c, att.key, att.buff, {
				contentType: att.type,
				contentDisposition: `attachment;filename=${att.filename}`
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
			await r2Service.putObj(c, attData.key, attData.buff, {
				contentType: attData.mimeType,
				cacheControl: `max-age=259200`,
				contentDisposition: `inline;filename=${attData.filename}`
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
			await this.batchDelete(c, delKeyList);
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

	// 删除附件（软删除）：移入垃圾桶，不删数据库记录、不删 COS 文件
	async manageDelete(c, params, currentUserId, isAdmin) {

		const { attIds } = params;
		const idList = String(attIds || '').split(',').map(Number).filter(Boolean);
		if (idList.length === 0) {
			return;
		}

		const rows = await orm(c).select().from(att).where(inArray(att.attId, idList)).all();

		// 权限：管理员可删任意，普通用户只能删自己的
		const allowed = isAdmin ? rows : rows.filter(r => r.userId === currentUserId);
		if (allowed.length === 0) {
			return;
		}

		const ids = allowed.map(r => r.attId);
		const now = dayjs().format('YYYY-MM-DD HH:mm:ss');

		await orm(c).update(att).set({ trash: 1, trashTime: now }).where(inArray(att.attId, ids)).run();
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

		const rows = await orm(c).select().from(att)
			.where(and(inArray(att.attId, idList), eq(att.trash, 1)))
			.all();

		if (rows.length === 0) {
			return;
		}

		const ids = rows.map(r => r.attId);
		const keys = [...new Set(rows.map(r => r.key).filter(Boolean))];

		// 删 COS 文件：只有引用计数归零的 key 才真正删除文件
		if (keys.length > 0) {
			const refRows = await orm(c).select({ key: att.key, cnt: count(att.attId) }).from(att)
				.where(inArray(att.key, keys))
				.groupBy(att.key)
				.all();

			const refMap = {};
			refRows.forEach(r => { refMap[r.key] = r.cnt; });

			const delKeys = [];
			for (const k of keys) {
				const delCnt = rows.filter(r => r.key === k).length;
				if ((refMap[k] || 0) <= delCnt) {
					delKeys.push(k);
				}
			}

			if (delKeys.length > 0) {
				await this.batchDelete(c, delKeys);
			}
		}

		await orm(c).delete(att).where(inArray(att.attId, ids)).run();
	},

	// 定时清理：垃圾桶中超过 7 天的附件彻底删除
	async clearTrash(c) {

		const sevenDaysAgo = dayjs().subtract(7, 'day').format('YYYY-MM-DD HH:mm:ss');

		const rows = await orm(c).select().from(att)
			.where(and(eq(att.trash, 1), lt(att.trashTime, sevenDaysAgo)))
			.all();

		if (rows.length === 0) {
			return;
		}

		const ids = rows.map(r => r.attId);
		const keys = [...new Set(rows.map(r => r.key).filter(Boolean))];

		if (keys.length > 0) {
			const refRows = await orm(c).select({ key: att.key, cnt: count(att.attId) }).from(att)
				.where(inArray(att.key, keys))
				.groupBy(att.key)
				.all();

			const refMap = {};
			refRows.forEach(r => { refMap[r.key] = r.cnt; });

			const delKeys = [];
			for (const k of keys) {
				const delCnt = rows.filter(r => r.key === k).length;
				if ((refMap[k] || 0) <= delCnt) {
					delKeys.push(k);
				}
			}

			if (delKeys.length > 0) {
				await this.batchDelete(c, delKeys);
			}
		}

		await orm(c).delete(att).where(inArray(att.attId, ids)).run();
	},

	// 恢复垃圾桶附件：普通用户只能恢复自己的，管理员可恢复任意用户的
	async manageRestore(c, params, currentUserId, isAdmin) {

		const { attIds } = params;
		const idList = Array.isArray(attIds) ? attIds : String(attIds || '').split(',').map(Number);
		const validIds = idList.map(Number).filter(Boolean);
		if (validIds.length === 0) {
			return;
		}

		const rows = await orm(c).select().from(att)
			.where(and(inArray(att.attId, validIds), eq(att.trash, 1)))
			.all();

		const allowed = isAdmin ? rows : rows.filter(r => r.userId === currentUserId);
		if (allowed.length === 0) {
			return;
		}

		const ids = allowed.map(r => r.attId);
		await orm(c).update(att).set({ trash: 0, trashTime: null }).where(inArray(att.attId, ids)).run();
	}
};

export default attService;
