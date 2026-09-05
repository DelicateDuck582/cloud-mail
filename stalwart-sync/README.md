> ⚠️ **项目搁置（ARCHIVED）**
>
> 暂无时间继续维护，且当时没有可行的"无服务器"落地方案；
> 即便日后拥有服务器，也不会再采用这套方案。本目录仅作代码存档，不再更新。

# CloudMail → Stalwart 同步（替换最小 IMAP 桥）

把 CloudMail 收件箱镜像到 **Stalwart Mail Server**（标准 IMAP/POP/JMAP 服务器），
雷鸟用原生 IMAP 读取 —— **协议层交给 Stalwart 兜底，不再有自定义 IMAP 桥的 bug 风险**。

**v4 功能**：多账户聚合（JMAP 文件夹投递，按收件人区分）、已读回写、
**删除回写 + 垃圾桶恢复（双向）**、发信导入（方案 C Resend）、增量、附件可选。

## 架构
```
Cloudflare Email Routing → CloudMail (D1)  ← 主数据源（网页端 / 发信）
                                ↕ 本脚本（下行 JMAP 文件夹投递；上行 已读/删除/恢复/发信 反向同步）
VPS: Stalwart (SQLite) ←── IMAP :993 ── Cloudflare Tunnel ── Thunderbird
  文件夹聚合 5 号：contact@ciallo.sale / service@ciallo.sale / pgp@ciallo.sale /
                   admin@delicateduck.xyz / noreply@ciallo.sale / Sent / Trash
                          雷鸟发信 = 方案 C（smtp-void 收集 → CloudMail Resend 投递）
```

## 文件
| 文件 | 说明 |
|---|---|
| `sync.js` | 同步脚本 v3（Node 零依赖）：下行 + 删除/发信/已读 反向同步 |
| `smtp-void.js` | 哑 SMTP 收集器（方案 C）：接收 Stalwart relay 即丢弃，供发信走 CloudMail Resend |
| `cloudmail-sync.service` | 同步脚本 systemd 单元（cloudsync 用户 + 加固） |
| `smtp-void.service` | smtp-void 的 systemd 单元 |
| `stalwart部署-阿里云CLI助手.md` | VPS 部署文档（Stalwart + 同步 + Tunnel + 防火墙 + 发信） |

## 同步脚本（v4）

### 下行：CloudMail → Stalwart（JMAP 文件夹投递）

- 用登录用户（如 `admin@delicateduck.xyz`）自动遍历其**全部邮箱账户**（`/api/account/list`，多号模式）
- **投递 = JMAP Email/import 到"按收件人划分的文件夹"**（`SYNC_DELIVERY=jmap` 默认）：
  - 每号一个文件夹（默认文件夹名 = 账户邮箱地址，`STALWART_FOLDERS` 可覆盖）
  - import 直接设置 `$seen`（已读状态）并返回 Stalwart email id（登记 stalwartMap，无需反查）
  - **幂等**：import 前按 Message-ID 查重，已存在（如垃圾桶恢复后）则跳过
- 兼容旧方式：`SYNC_DELIVERY=smtp` 走 SMTP 2525 混流 INBOX（无文件夹区分）
- 5 号示例：contact/service/pgp/noreply@ciallo.sale + admin@delicateduck.xyz → 各自文件夹

### 删除回写 + 垃圾桶恢复（雷鸟 ↔ CloudMail 垃圾桶）
- **删除**：邮件移出"各号文件夹"（删除/移入垃圾桶/归档）→ `DELETE /api/email/delete`（CloudMail 垃圾桶）
- **恢复**：邮件回到各号文件夹（从垃圾桶恢复）→ 按 Message-ID 匹配 → `POST /api/email/restore`
  + 重新登记 stalwartMap（幂等投递保证不重复）
- `SYNC_DELETE=0` 关闭；CloudMail 垃圾桶 7 天自动清理（附件同机制）

### 发信导入（雷鸟发信 → CloudMail 已发送，无 25 方案）
- **无 25**：VPS 出站 25 被封，Stalwart 不直投收件方；两种投递通道（`SYNC_SENT_MODE` 选择）：
  - `import`（默认，方案 A）：投递走**第三方 SMTP 中继（465/587）**，脚本仅镜像记录
    （`/api/email/import-sent`，不重复投递）
  - `send`（**方案 C，零第三方依赖**）：投递走 **CloudMail 自身 Resend API**
    （`POST /api/email/send`，HTTPS 不走 25，多域名 resend token 已配）——Stalwart 只作收集
- **方案 C 链路**：雷鸟 → Stalwart submission(587) → **Stalwart Relay → 本机 smtp-void(2526)**（接受即丢弃，
  邮件留在 Stalwart Sent）→ 脚本检测 Sent 新邮件 → `cloud.send`（Resend 真正投递）→ 已发送落 CloudMail
- **多域名**：发件人按 From 匹配 CloudMail 账户（跨域名均可）；无法匹配的跳过；
  多域名建议绑定到**同一 Stalwart 账户的多个地址**（一套 JMAP 凭据覆盖全部）
- `SYNC_SENT=0` 关闭；首次启用默认只建基线不追溯历史（`SYNC_SENT_HISTORY=1` 可追溯）
- `send` 模式注意：CloudMail send 限附件 ≤10（超限截断）+ 发信次数/角色限制；失败连续 3 轮自动放弃
- ⚠️ `/api/email/import-sent` 是 mail-worker fork 端点，**需重新部署 mail-worker**

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

# 投递：单账户用 RCPT_TO；多号模式用 ACCOUNTS 映射（admin 登录遍历全部号）
STALWART_RCPT_TO=cloudmail@local.domain
STALWART_ACCOUNTS={"contact@ciallo.sale":"cloudmail@local.domain","service@ciallo.sale":"cloudmail@local.domain","pgp@ciallo.sale":"cloudmail@local.domain","admin@delicateduck.xyz":"cloudmail@local.domain","noreply@ciallo.sale":"cloudmail@local.domain"}

STALWART_SMTP_HOST=127.0.0.1
STALWART_SMTP_PORT=2525   # 无 25 方案：本机明文 SMTP（Stalwart 监听 127.0.0.1:2525），云厂商封 25 不影响
STATE_FILE=/var/lib/cloudmail-sync/state.json
# 按需同步（省 Cloudflare Worker 调用）：
#   默认改为「雷鸟打开时触发」+ 低频兜底。触发走 Tunnel HTTP（sync.duckgame-play.top → 本机触发服务）。
#   SYNC_TRIGGER_PORT=9999      触发服务端口（仅回环 127.0.0.1）；0=关闭
#   SYNC_TRIGGER_TOKEN=xxxxx    触发 token（雷鸟插件/手测 URL 需带同值 token，未设置一律 403）
#   IDLE_INTERVAL=3600000       兜底自动轮询毫秒（默认 1h；0=完全只靠触发，永不自动查询）
#   MIN_TRIGGER_GAP_MS=15000    触发防抖（毫秒）
# 旧固定轮询（想恢复 24h 自动高频轮询时用）：
POLL_INTERVAL=30000

# 反向同步（可选，配置以下三项后自动开启 已读回写/删除/发信）
STALWART_JMAP_URL=https://127.0.0.1:8080/jmap
STALWART_USERNAME=cloudmail@local.domain
STALWART_PASSWORD=Stalwart邮箱密码
# STALWART_SENT_MAILBOX=Sent   # Stalwart 已发送邮箱名（默认 Sent）
# SYNC_DELETE=1                # 删除回写（默认开）
# SYNC_SENT=1                  # 发信导入（默认开）
# SYNC_SENT_MODE=send          # send=方案C 走 CloudMail Resend 投递（需 smtp-void + Stalwart Relay）；
#                              # import=默认，第三方 SMTP 中继投递，仅镜像记录
# SYNC_SENT_HISTORY=0          # 首次启用时追溯历史已发送（默认不追溯）
# SYNC_DELIVERY=jmap           # 下行投递：jmap=文件夹投递（默认）；smtp=2525 混流 INBOX（旧）
# STALWART_FOLDERS={"contact@ciallo.sale":"客服","..."}   # 可选：文件夹名覆盖（默认用账户邮箱地址）

# ATTACHMENTS=1   # 可选：同步附件（下行）
# ATTACH_MAX_MB=10        # 附件单文件上限，超限跳过（默认 10）
# ATTACH_TOTAL_MAX_MB=25  # 单封附件总量上限，超限跳过（默认 25）
# STATE_MAX=10000         # 状态集上限，超出自动裁剪最旧（默认 10000）
# HTTP_TIMEOUT_MS=20000   # HTTP 请求超时（CloudMail/JMAP/附件，默认 20s）
```

## 限制（v4）
- 删除/恢复/发信回写对 **JMAP 登录账户**（`STALWART_USERNAME`）生效；多账户建议绑定到同一 Stalwart 账户的多个地址
- **草稿**：CloudMail 网页草稿存**浏览器本地**（IndexedDB，`mail-vue/src/db/db.js`），服务端无 draft；
  Stalwart Drafts 文件夹仅供雷鸟本地草稿，**与 CloudMail 网页草稿互不同步**
- **垃圾邮件**：CloudMail 无 spam/junk 概念；Stalwart Junk 文件夹可自建但仅本地，不回写
- **垃圾桶**：CloudMail 有邮件垃圾桶（trash=1，7 天清理）+ 附件管理垃圾桶（att.trash）；双向同步已实现
- 发信导入仅匹配 From 为 CloudMail 域名邮箱的邮件；附件只导 `disposition:attachment`，内嵌图跳过
- 只镜像收件（type=0 邮件）；同步/反向同步延迟 = 轮询间隔（默认 30s）
- Stalwart 是镜像副本；主数据在 CloudMail

## AGPL 合规
- **不修改 Stalwart 代码**（官方二进制原样部署）。
- 本地参考副本：官方发行版原样复制（哈希校验一致），**代码零修改**。
- 自托管使用不涉及分发，无 AGPL 义务触发。


