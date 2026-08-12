import app from '../hono/hono';
import emailService from '../service/email-service';
import result from '../model/result';
import userContext from '../security/user-context';
import attService from '../service/att-service';
import permService from '../service/perm-service';
import BizError from '../error/biz-error';
import { t } from '../i18n/i18n';

app.get('/email/list', async (c) => {
	const data = await emailService.list(c, c.req.query(), userContext.getUserId(c));
	return c.json(result.ok(data));
});

// 邮件详情（附件管理"定位到目标邮件"用）：超管/有 all-email:query 权限可查任意，否则只能查自己的
app.get('/email/detail', async (c) => {
	const { emailId } = c.req.query();
	const userId = userContext.getUserId(c);
	const user = c.get('user');
	const isSuperAdmin = user.email === c.env.admin;
	const permKeys = isSuperAdmin ? ['*'] : await permService.userPermKeys(c, userId);
	const canViewAll = isSuperAdmin || permKeys.includes('all-email:query');

	const emailRow = await emailService.selectById(c, Number(emailId));
	if (!emailRow) {
		throw new BizError('邮件不存在 Email not found', 404);
	}
	if (!canViewAll && emailRow.userId !== userId) {
		throw new BizError(t('unauthorized'), 403);
	}

	emailRow.attList = await attService.selectByEmailIds(c, [emailRow.emailId]);
	await emailService.signEmailList(c, [emailRow]);

	return c.json(result.ok(emailRow));
});

app.get('/email/latest', async (c) => {
	const list = await emailService.latest(c, c.req.query(), userContext.getUserId(c));
	return c.json(result.ok(list));
});

app.delete('/email/delete', async (c) => {
	await emailService.delete(c, c.req.query(), userContext.getUserId(c));
	return c.json(result.ok());
});

// 恢复垃圾桶邮件：恢复邮件 + 连带恢复关联附件
app.post('/email/restore', async (c) => {
	await emailService.restore(c, await c.req.json(), userContext.getUserId(c));
	return c.json(result.ok());
});

app.get('/email/attList', async (c) => {
	const attList = await attService.list(c, c.req.query(), userContext.getUserId(c));
	return c.json(result.ok(attList));
});

app.post('/email/send', async (c) => {
	const email = await emailService.send(c, await c.req.json(), userContext.getUserId(c));
	return c.json(result.ok(email));
});

app.put('/email/read', async (c) => {
	await emailService.read(c, await c.req.json(), userContext.getUserId(c));
	return c.json(result.ok());
})

