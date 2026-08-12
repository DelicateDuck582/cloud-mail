import app from '../hono/hono';
import attService from '../service/att-service';
import result from '../model/result';
import userContext from '../security/user-context';
import permService from '../service/perm-service';
import BizError from '../error/biz-error';
import { t } from '../i18n/i18n';

// 附件管理权限：
//   canViewAll   —— 超管 或 拥有 all-email:query 权限的角色（可查看/恢复全部用户的附件）
//   canViewUsage —— 超管 或 拥有 att:usage 权限的角色（可查看使用量）
//   isSuperAdmin —— 仅 c.env.admin（唯一可彻底删除垃圾桶附件）
async function getAttPerm(c) {
	const user = c.get('user');
	const isSuperAdmin = user.email === c.env.admin;
	const permKeys = isSuperAdmin ? ['*'] : await permService.userPermKeys(c, user.userId);
	const canViewAll = isSuperAdmin || permKeys.includes('all-email:query');
	const canViewUsage = isSuperAdmin || permKeys.includes('att:usage');
	return { isSuperAdmin, canViewAll, canViewUsage };
}

// 附件管理列表：有全站查看权限可看全部/按用户筛选，否则只能看自己的
app.get('/att/list', async (c) => {
	const { canViewAll } = await getAttPerm(c);
	const data = await attService.manageList(c, c.req.query(), userContext.getUserId(c), canViewAll);
	return c.json(result.ok(data));
});

// 删除附件（软删除）：移入垃圾桶；有全站查看权限可删任意，否则只能删自己的
app.delete('/att/delete', async (c) => {
	const { canViewAll } = await getAttPerm(c);
	await attService.manageDelete(c, c.req.query(), userContext.getUserId(c), canViewAll);
	return c.json(result.ok());
});

// 彻底删除垃圾桶附件（仅超级管理员）
app.delete('/att/trash', async (c) => {
	const { isSuperAdmin } = await getAttPerm(c);
	await attService.manageTrashDelete(c, c.req.query(), userContext.getUserId(c), isSuperAdmin);
	return c.json(result.ok());
});

// 恢复垃圾桶附件：有全站查看权限可恢复任意，否则只能恢复自己的
app.post('/att/restore', async (c) => {
	const { canViewAll } = await getAttPerm(c);
	await attService.manageRestore(c, await c.req.json(), userContext.getUserId(c), canViewAll);
	return c.json(result.ok());
});

// 附件使用量（COS 实际存储量 + 数据库附件统计）：需 att:usage 权限或超管
app.get('/att/usage', async (c) => {
	const { canViewUsage } = await getAttPerm(c);
	if (!canViewUsage) {
		throw new BizError(t('unauthorized'), 403);
	}
	const data = await attService.getUsage(c);
	return c.json(result.ok(data));
});
