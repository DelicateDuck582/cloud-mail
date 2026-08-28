# CloudMail → Stalwart 同步（替换最小 IMAP 桥）

把 CloudMail 收件箱镜像到 **Stalwart Mail Server**（标准 IMAP/POP/JMAP 服务器），
雷鸟用原生 IMAP 读取 —— **协议层交给 Stalwart 兜底，不再有自定义 IMAP 桥的 bug 风险**。

**v3 功能**：多账户、已读回写、**删除回写（雷鸟删除 → CloudMail 垃圾桶）**、
**发信导入（雷鸟发信 → CloudMail 已发送）**、增量、附件可选。

## 架构
```
Cloudflare Email Routing → CloudMail (D1)  ← 主数据源（网页端 / 发信）
                                ↕ 本脚本（下行：轮询→重建 MIME→SMTP 投递；上行：JMAP 反向同步）
VPS: Stalwart (SQLite) ←── IMAP :993 ── Cloudflare Tunnel ── Thunderbird
                         SMTP submission :587（雷鸟发信）
```

## 文件
| 文件 | 说明 |
|---|---|
| `sync.js` | 同步脚本 v3（Node 零依赖）：下行 + 删除/发信/已读 反向同步 |
| `cloudmail-sync.service` | systemd 单元（cloudsync 用户 + 加固） |
| `stalwart部署-阿里云CLI助手.md` | VPS 部署文档（Stalwart + 同步 + Tunnel + 防火墙 + 发信） |

## 同步脚本（v3）

### 下行：CloudMail → Stalwart

### 多账户
- 自动遍历 CloudMail 全部邮箱账户（`/api/account/list`）
- 投递目标：`STALWART_ACCOUNTS`（JSON 映射 `{"CloudMail账户邮箱":"Stalwart目标邮箱"}`）
  未配置映射时，所有账户用 `STALWART_RCPT_TO` 投到同一个 Stalwart 邮箱

### 删除回写（雷鸟删除 → CloudMail 垃圾桶）
- 投递时登记 Stalwart 邮件 ID ↔ CloudMail `accountId:emailId`（按固定 Message-ID 反查）
- 每轮对比收件箱当前 ID：**邮件移出收件箱**（删除/归档/移入垃圾桶）→ `DELETE /api/email/delete`
- CloudMail 端走软删除（垃圾桶）；`SYNC_DELETE=0` 关闭；网页端恢复后自动重新镜像

### 发信导入（雷鸟发信 → CloudMail 已发送）
- 雷鸟 SMTP → Stalwart submission（Stalwart 负责投递收件人）
- 脚本用 JMAP `Email/queryChanges` 增量扫描 Stalwart **Sent** 邮箱 → 导入 CloudMail
  `/api/email/import-sent`（**不触发 Resend，避免重复投递**）
- 发件人必须是 CloudMail 域名邮箱（否则跳过）；`SYNC_SENT=0` 关闭
- 首次启用默认只建基线不追溯历史（`SYNC_SENT_HISTORY=1` 可追溯）
- 注意：`/api/email/import-sent` 是 mail-worker 新增 fork 端点，**需重新部署 mail-worker**

### 已读回写（雷鸟标已读 → CloudMail）
- 通过 Stalwart **JMAP** 读取 `$seen` 状态，按 `Message-ID`（`cloudmail-<emailId>@duckgame-play.top`）匹配
- 匹配到已读且 CloudMail 未读 → `PUT /api/email/read`
- 配置 `STALWART_JMAP_URL` + `STALWART_USERNAME/PASSWORD`（Stalwart 邮箱账户）即启用；
  未配置或失败时自动跳过（不影响同步）

### 增量
- 状态文件 `state.json`：`synced`（下行）+ `stalwartMap`（删除映射）+ `sentDone/sentQueryState`（发信游标）
- 原子写防损坏；上限 `STATE_MAX` 自动裁剪最旧

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

# 反向同步（可选，配置以下三项后自动开启 已读回写/删除/发信）
STALWART_JMAP_URL=https://127.0.0.1:8080/jmap
STALWART_USERNAME=cloudmail@local.domain
STALWART_PASSWORD=Stalwart邮箱密码
# STALWART_SENT_MAILBOX=Sent   # Stalwart 已发送邮箱名（默认 Sent）
# SYNC_DELETE=1                # 删除回写（默认开）
# SYNC_SENT=1                  # 发信导入（默认开）
# SYNC_SENT_HISTORY=0          # 首次启用时追溯历史已发送（默认不追溯）

# ATTACHMENTS=1   # 可选：同步附件（下行）
# ATTACH_MAX_MB=10        # 附件单文件上限，超限跳过（默认 10）
# ATTACH_TOTAL_MAX_MB=25  # 单封附件总量上限，超限跳过（默认 25）
# STATE_MAX=10000         # 状态集上限，超出自动裁剪最旧（默认 10000）
# HTTP_TIMEOUT_MS=20000   # HTTP 请求超时（CloudMail/JMAP/附件，默认 20s）
```

## 限制（v3）
- 删除/发信回写对 **JMAP 登录账户**（`STALWART_USERNAME`）生效；多账户时每个 Stalwart 邮箱需独立实例或单账户多地址
- 发信导入仅匹配 From 为 CloudMail 域名邮箱的邮件；附件只导 `disposition:attachment`，内嵌图跳过
- 只镜像收件箱（type=0）；CloudMail 网页端删除不回删 Stalwart 副本（下行因 `trash=0` 过滤停止拉取，副本由雷鸟侧删除）
- 同步/反向同步延迟 = 轮询间隔（默认 30s）
- Stalwart 是镜像副本；主数据在 CloudMail

## AGPL 合规
- **不修改 Stalwart 代码**（官方二进制原样部署）。
- 本地参考副本：`E:\DEVE 开发\stalwart`（从 `E:\数据迁移\开发\stalwart` 原样复制，哈希校验一致）。
- 自托管使用不涉及分发，无 AGPL 义务触发。


