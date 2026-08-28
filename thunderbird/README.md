# CloudMail Reader（Thunderbird 插件 · 只读）

在 Thunderbird 中手动刷新查看 CloudMail（`mail.duckgame-play.top`）的收件箱。**只读**（当前版本仅拉取邮件），无实时推送，无发信。

## 原理

- 复用 CloudMail Web 端**完全相同的认证链**：`POST /api/login`（邮箱+密码）→ JWT（HS256，`jwt_secret` 签名）→ 服务端 KV 会话（30 天 TTL）。
- 每次请求带 `Authorization` 头，后端 `security.js` 验 JWT 签名 + KV 会话（吊销检查）→ 与 Web 端同等安全。
- 附件走后端签名的 `att.url`（HMAC 签名，15 分钟有效，COS 私有桶防盗链/防刷）。

## 安装（临时加载，无需签名）

1. 打开 Thunderbird → 右上角「☰」→ **附加组件与主题** → 齿轮 ⚙ → **调试附加组件**。
2. 点 **临时载入附加组件** → 选择本目录下的 `manifest.json`。
3. 工具栏出现 CloudMail 图标 → 点击打开。
4. 输入邮箱密码登录 → 点「刷新」手动拉取。

> 重启 Thunderbird 后需重新临时加载。正式安装需打包 `.xpi` 并（可选）签名。

## 目录

```
thunderbird/
├── manifest.json    # MV2 + gecko.id（雷鸟不支持 MV3）
├── background.js    # token 存储 + API 调用（token 不进页面）
├── mail.html        # 登录 / 列表 / 详情 UI
├── mail.js          # 页面逻辑
├── mail.css
└── icons/icon.svg
```

## 安全设计

| 项 | 说明 |
|---|---|
| Token 存储 | 仅 `browser.storage.local`，后台脚本持有；页面通过 `runtime.sendMessage` 间接取数 |
| 会话过期 | 响应 `code:401` → 清 token → 弹回登录框 |
| 正文渲染 | `sandbox` iframe（无 `allow-scripts`），邮件脚本不执行 |
| 附件 | 用签名的 `att.url` 下载，不接触 COS 密钥 |
| 权限最小化 | `host_permissions` 仅 `mail.duckgame-play.top` 与 `cos.duckgame-play.top` |
| 登出 | 调 `/api/logout` 服务端吊销 + 清本地 |

## 待办（后续版本）

- [ ] 分页游标加载更早邮件（当前「加载更多」已有基础实现）
- [ ] 已读标记（`PUT /api/email/read`）
- [ ] 发信（`POST /api/email/send`）
- [ ] 星标 / 搜索 / 文件夹
