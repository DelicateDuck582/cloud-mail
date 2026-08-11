import app from '../hono/hono';
import attService from '../service/att-service';
import result from '../model/result';
import userContext from '../security/user-context';

// 附件管理：管理员可看全部/按用户筛选，普通用户只能看自己的
app.get('/att/list', async (c) => {
	const user = c.get('user');
	const isAdmin = user.email === c.env.admin;
	const data = await attService.manageList(c, c.req.query(), userContext.getUserId(c), isAdmin);
	return c.json(result.ok(data));
});

// 删除附件：管理员可删任意，普通用户只能删自己的
app.delete('/att/delete', async (c) => {
	const user = c.get('user');
	const isAdmin = user.email === c.env.admin;
	await attService.manageDelete(c, c.req.query(), userContext.getUserId(c), isAdmin);
	return c.json(result.ok());
});
