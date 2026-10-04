import orm from '../entity/orm';
import { star } from '../entity/star';
import emailService from './email-service';
import BizError from '../error/biz-error';
import { and, desc, eq, lt, sql, inArray } from 'drizzle-orm';
import email from '../entity/email';
import { emailListColumns, emailBriefColumns } from '../lib/email-list-columns';
import { isDel } from '../const/entity-const';
import attService from "./att-service";
import { t } from '../i18n/i18n'

// D1 单条语句最多 100 个绑定参数，inArray 统一按 90 分片，留安全余量
const SQL_BIND_LIMIT = 90;

const chunkArray = (list, size) => {
	const chunks = [];
	for (let i = 0; i < list.length; i += size) {
		chunks.push(list.slice(i, i + size));
	}
	return chunks;
};

const starService = {

	async add(c, params, userId) {
		const { emailId } = params;
		const email = await emailService.selectById(c, emailId);
		if (!email) {
			throw new BizError(t('starNotExistEmail'));
		}
		if (email.userId !== userId) {
			throw new BizError(t('starNotExistEmail'));
		}
		const exist = await orm(c).select().from(star).where(
			and(
				eq(star.userId, userId),
				eq(star.emailId, emailId)))
			.get()

		if (exist) {
			return
		}

		await orm(c).insert(star).values({ userId, emailId }).run();
	},

	async cancel(c, params, userId) {
		const { emailId } = params;
		await orm(c).delete(star).where(
			and(
				eq(star.userId, userId),
				eq(star.emailId, emailId)))
			.run();
	},

	async list(c, params, userId) {
		let { emailId, size, full } = params;
		emailId = Number(emailId) || 0;
		size = Number(size);
		full = Number(full) === 1;
		const columns = full ? emailListColumns : emailBriefColumns;

		const list = await orm(c).select({
			isStar: sql`1`.as('isStar'),
			starId: star.starId,
			...columns
		}).from(star)
			.leftJoin(email, eq(email.emailId, star.emailId))
			.where(
				and(
					eq(star.userId, userId),
					eq(email.isDel, isDel.NORMAL),
					emailId ? lt(star.emailId, emailId) : undefined))
			.orderBy(desc(star.emailId))
			.limit(size)
			.all();

		if (full) {
			const emailIds = list.map(item => item.emailId);
			const attsList = await attService.selectByEmailIds(c, emailIds);
			list.forEach(emailRow => {
				emailRow.attList = attsList.filter(attsRow => attsRow.emailId === emailRow.emailId);
			});
		} else {
			list.forEach(emailRow => {
				emailRow.listText = emailService.toListText(emailRow);
				delete emailRow.text;
				delete emailRow.content;
			});
		}

		return { list };
	},
	// 数组来自调用方（邮件/用户批量删除），可能超过 D1 绑定参数上限，按 90 分片逐批删除
	async removeByEmailIds(c, emailIds) {
		for (const chunk of chunkArray(emailIds, SQL_BIND_LIMIT)) {
			await orm(c).delete(star).where(inArray(star.emailId, chunk)).run();
		}
	},

	async removeByUserIds(c, userIds) {
		for (const chunk of chunkArray(userIds, SQL_BIND_LIMIT)) {
			await orm(c).delete(star).where(inArray(star.userId, chunk)).run();
		}
	}
};

export default starService;
