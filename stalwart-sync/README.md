# CloudMail → Stalwart 同步（替换最小 IMAP 桥）

把 CloudMail 收件箱镜像到 **Stalwart Mail Server**（标准 IMAP/POP/JMAP 服务器），
雷鸟用原生 IMAP 读取 —— **协议层交给 Stalwart 兜底，不再有自定义 IMAP 桥的 bug 风险**。

**v2 功能**：多账户、已读回写（JMAP）、增量、附件可选。

## 架构
```
Cloudflare Email Routing → CloudMail (D1)  ← 主数据源（网页端 / 发信）
                                ↕ 本脚本（轮询 API → 重建 MIME → 本机 SMTP 投递）
VPS: Stalwart (SQLite) ←── IMAP :993 ── Cloudflare Tunnel ── Thunderbird
```

## 文件
| 文件 | 说明 |
|---|---|
| `sync.js` | 同步脚本 v2（Node 零依赖）：多账户 + 已读回写 |
| `cloudmail-sync.service` | systemd 单元（cloudsync 用户 + 加固） |
| `部署-阿里云CLI助手.md` | VPS 部署文档（Stalwart + 同步 + Tunnel + 防火墙） |

## 同步脚本（v2）

### 多账户
- 自动遍历 CloudMail 全部邮箱账户（`/api/account/list`）
- 投递目标：`STALWART_ACCOUNTS`（JSON 映射 `{"CloudMail账户邮箱":"Stalwart目标邮箱"}`）
  未配置映射时，所有账户用 `STALWART_RCPT_TO` 投到同一个 Stalwart 邮箱

### 已读回写（雷鸟标已读 → CloudMail）
- 通过 Stalwart **JMAP** 读取 `$seen` 状态，按 `Message-ID`（`cloudmail-<emailId>@duckgame-play.top`）匹配
- 匹配到已读且 CloudMail 未读 → `PUT /api/email/read`
- 配置 `STALWART_JMAP_URL` + `STALWART_USERNAME/PASSWORD`（Stalwart 邮箱账户）即启用；
  未配置或失败时自动跳过（不影响同步）

### 增量
- 状态文件 `state.json` 记录 `accountId:emailId`，只拉新邮件；原子写防损坏

## 环境变量（systemd `EnvironmentFile`）
```
CLOUDMAIL_EMAIL=REPLACE_WITH_EMAIL
CLOUDMAIL_PASSWORD=REPLACE_WITH_PASSWORD

# 投递：单账户用 RCPT_TO；多账户用 ACCOUNTS 映射
STALWART_RCPT_TO=cloudmail@local.domain
STALWART_ACCOUNTS={"account1@duckgame-play.top":"cloudmail1@local.domain","account2@duckgame-play.top":"cloudmail2@local.domain"}

STALWART_SMTP_HOST=127.0.0.1
STALWART_SMTP_PORT=25
STATE_FILE=/var/lib/cloudmail-sync/state.json
POLL_INTERVAL=30000

# 已读回写（可选）
STALWART_JMAP_URL=https://127.0.0.1:8080/jmap
STALWART_USERNAME=cloudmail@local.domain
STALWART_PASSWORD=Stalwart邮箱密码

# ATTACHMENTS=1   # 可选：同步附件
```

## 限制（v2）
- 删除/移出：不镜像（雷鸟删邮件不回写 CloudMail，主数据在 CloudMail）
- 只同步收件箱（type=0）；发信走 CloudMail 网页端
- 同步延迟 = 轮询间隔（默认 30s）；已读回写延迟 = 轮询间隔
- Stalwart 是镜像副本

## AGPL 合规
- **不修改 Stalwart 代码**（官方二进制原样部署）。
- 本地参考副本：`E:\DEVE 开发\stalwart`（从 `E:\数据迁移\开发\stalwart` 原样复制，哈希校验一致）。
- 自托管使用不涉及分发，无 AGPL 义务触发。


