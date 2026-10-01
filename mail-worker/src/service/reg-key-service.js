import orm from '../entity/orm';
import regKey from '../entity/reg-key';
import { inArray, like, eq, desc, sql, or } from 'drizzle-orm';
import roleService from './role-service';
import BizError from '../error/biz-error';
import { formatDetailDate, toUtc } from '../utils/date-uitil';
import userService from './user-service';
import { t } from '../i18n/i18n.js';

// D1 单条语句最多 100 个绑定参数，inArray 统一按 90 分片，留安全余量
const SQL_BIND_LIMIT = 90;

const chunkArray = (list, size) => {
	const chunks = [];
	for (let i = 0; i < list.length; i += size) {
		chunks.push(list.slice(i, i + size));
	}
	return chunks;
};

const regKeyService = {

	async add(c, params, userId) {

		let {code,roleId,count,expireTime} = params;

		if (!code) {
			throw new BizError(t('emptyRegKey'));
		}

		if (!count) {
			throw new BizError(t('emptyRegKey'));
		}

		if (!expireTime) {
			throw new BizError(t('emptyRegKeyExpire'));
		}

		const regKeyRow = await orm(c).select().from(regKey).where(eq(regKey.code, code)).get();

		if (regKeyRow) {
			throw new BizError(t('isExistRegKye'));
		}

		const roleRow = roleService.selectById(c, roleId);
		if (!roleRow) {
			throw new BizError(t('roleNotExist'));
		}

		expireTime = formatDetailDate(expireTime)

		await orm(c).insert(regKey).values({code,roleId,count,userId,expireTime}).run();
	},

	async delete(c, params) {
		let {regKeyIds} = params;
		regKeyIds = regKeyIds.split(',').map(id => Number(id));
		// 入参 regKeyIds 数量不限，按 D1 绑定参数上限分片删除
		for (const chunk of chunkArray(regKeyIds, SQL_BIND_LIMIT)) {
			await orm(c).delete(regKey).where(inArray(regKey.regKeyId, chunk)).run();
		}
	},

	async clearNotUse(c) {
		let now = formatDetailDate(toUtc().tz('Asia/Shanghai').startOf('day'))
		await orm(c).delete(regKey).where(or(eq(regKey.count, 0),sql`datetime(${regKey.expireTime}, '+8 hours') < datetime(${now})`)).run();
	},

	selectByCode(c, code) {
		return orm(c).select().from(regKey).where(eq(regKey.code, code)).get();
	},

	async list(c, params) {

		const {code} = params
		let query = orm(c).select().from(regKey)

		if (code) {
			query = query.where(like(regKey.code, `${code}%`))
		}

		const regKeyList = await query.orderBy(desc(regKey.regKeyId)).all();
		const roleList = await roleService.roleSelectUse(c);

		const today = toUtc().tz('Asia/Shanghai').startOf('day')

		regKeyList.forEach(regKeyRow => {

			const index = roleList.findIndex(roleRow => roleRow.roleId === regKeyRow.roleId)
			regKeyRow.roleName = index > -1 ? roleList[index].name : ''

			const expireTime = toUtc(regKeyRow.expireTime).tz('Asia/Shanghai').startOf('day');

			if (expireTime.isBefore(today)) {
				regKeyRow.expireTime = null
			}
		})

		return regKeyList;
	},

	async reduceCount(c, code, count) {
		await orm(c).update(regKey).set({
			count: sql`${regKey.count}
	  -
	  ${count}`
		}).where(eq(regKey.code, code)).run();
	},

	async history(c, params) {
		const { regKeyId } = params;
		return userService.listByRegKeyId(c, regKeyId);
	}
}

export default regKeyService;
