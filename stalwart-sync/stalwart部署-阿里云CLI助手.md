# CloudMail → Stalwart 邮件镜像 — VPS 部署（阿里云终端 AI 助手执行版）

> 目标：在 VPS 上安装 **Stalwart Mail Server**（标准 IMAP/POP/JMAP，不修改其代码，遵守 AGPL），
> 部署 CloudMail→Stalwart 同步脚本，通过 **Cloudflare Tunnel** 暴露 `imap.duckgame-play.top:993`（IMAPS）。
> 雷鸟以原生 IMAP 读取 CloudMail 收件箱。**VPS IP 不暴露**（Tunnel 出站，防火墙拒绝入站）。
>
> 代码来源：`https://github.com/DelicateDuck582/cloud-mail` 分支 `thunderbird-client` 的 `stalwart-sync/`。
> Stalwart 本地参考副本：`E:\DEVE 开发\stalwart`（原样复制，哈希校验一致，**代码零修改**）。

## 0. 前置条件（用户需提前在 Cloudflare 控制台准备）

| 项 | 说明 |
|---|---|
| **Tunnel Token** | CF 控制台 → Zero Trust → Networks → Tunnels → 创建隧道 → 复制 `TUNNEL_TOKEN` |
| **Cloudflare API Token** | CF 控制台 → 个人资料 → API 令牌 → 创建：权限 `Zone:DNS:Edit`，区域 `duckgame-play.top` → 复制 `CF_API_TOKEN` |
| **LE 通知邮箱** | Let's Encrypt 通知邮箱 `LE_EMAIL` |
| **域名** | `imap.duckgame-play.top`（CF 托管） |

> ⚠️ token 敏感，勿写入仓库/日志；部署完成后删除 `/root/.secrets/cloudflare.ini`。

## 0.5 CLI 执行总览与占位符清单

> AI 助手：按 §1→§10 **顺序执行**；遇到「需 Web UI 交互」的步骤（§4、§4.5、§9）停下，
> 把浏览器操作交给用户完成后再继续。所有 `REPLACE_WITH_*`/占位符在执行前由用户确认。

### 需填写的占位符（执行前准备）
| 占位符 | 填写值 | 出现位置 |
|---|---|---|
| `CF_API_TOKEN` | **可选**：能手动设置 CF DNS 就用 §3 方式 A（无需 token）；有 token 用方式 B | §3 |
| `LE_EMAIL` | `server@ciallo.sale` | §3 |
| `TUNNEL_TOKEN` | CF → Zero Trust → Networks → Tunnels → 创建隧道 → 安装命令里的 `eyJ...`（隧道详情页 Configuration → Token） | §6 |
| `REPLACE_WITH_PASSWORD` | CloudMail `admin@delicateduck.xyz` 登录密码（部署后手动填进 VPS `/etc/cloudmail-sync.env`，勿给 AI/勿进仓库） | §5 |
| Stalwart 邮箱密码 | §4 创建 `cloudmail@local.domain` 时设置（雷鸟登录用）；**建议独立于 CloudMail 密码**，也可按你的选择复用 admin 密码 | §4 / §5 / §9 |

### 执行检查表（助手逐节打勾，失败即停并回报）
- [ ] §1 系统准备
- [ ] §2 安装 Stalwart（记录 admin token）
- [ ] §3 签发 imap.duckgame-play.top 证书（DNS-01）
- [ ] §4 Web UI 交互（用户：建域/账户/2525/993/587/Trash）
- [ ] §4.5 发信方案确认（推荐 C：smtp-void + Relay）
- [ ] §4.6 文件夹聚合确认（脚本自动建各号文件夹）
- [ ] §5 部署同步脚本 + smtp-void + env（SYNC_DELIVERY=jmap）
- [ ] §6 Cloudflare Tunnel（993 + 587）
- [ ] §7 防火墙（incoming deny）
- [ ] §8 验证（IMAP 握手 + JMAP 文件夹 + 同步日志）
- [ ] §9 雷鸟配置（用户：订阅文件夹 + 多身份）
- [ ] §10 限制确认


## 1. 系统准备

```bash
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl git ca-certificates jq openssl ufw
```

## 2. 安装 Stalwart（官方二进制，原样使用，不改代码）

```bash
# 官方一键安装（下载预编译二进制 + systemd 服务；对应仓库 install.sh 的自动化方式）
curl -fsSL https://stalw.art/install.sh | sh
# 若失败，用仓库内 install.sh：bash <(curl -fsSL ...) 或直接跑本机副本 install.sh

stalwart-mail --version   # 确认安装成功
systemctl enable --now stalwart-mail
sleep 2
systemctl status stalwart-mail --no-pager | head -10
```

> 安装后查看管理令牌（首次启动生成，后续可在 web UI 改）：
> ```bash
> # 管理端口默认 8080；初始令牌会在首次运行日志中输出，或存于配置
> journalctl -u stalwart-mail --no-pager | grep -i -E 'admin|token|password' | head -5
> ```

## 3. 签发 TLS 证书（imap.duckgame-play.top，DNS-01，不暴露端口）

> **方式 A（推荐，无需 CF API Token）—— 手动 DNS 验证**：certbot 给出 TXT 值，
> 用户在 CF 控制台手动添加记录（你已确认可以自己设置 DNS）。
> **方式 B —— CF API Token 自动验证**（若你有 token 则更省事）。

**方式 A：手动 DNS（无 Token）**
```bash
apt-get install -y certbot 2>/dev/null || pip3 install --break-system-packages certbot 2>/dev/null || true

certbot certonly --manual --preferred-challenges dns \
  -d imap.duckgame-play.top \
  --agree-tos -m server@ciallo.sale
# → 交互提示：在 CF 控制台给 _acme-challenge.imap.duckgame-play.top 添加 TXT 记录，
#   值填 certbot 显示的内容；生效后回车继续。签发完成后可删除该 TXT 记录。
```

**方式 B：CF API Token 自动验证（可选）**
```bash
apt-get install -y python3-certbot-dns-cloudflare 2>/dev/null \
  || pip3 install --break-system-packages certbot-dns-cloudflare 2>/dev/null || true
mkdir -p /root/.secrets && chmod 700 /root/.secrets
cat > /root/.secrets/cloudflare.ini <<'EOF'
dns_cloudflare_api_token = 这里填CF_API_TOKEN（可选）
EOF
chmod 600 /root/.secrets/cloudflare.ini

certbot certonly \
  --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cloudflare.ini \
  -d imap.duckgame-play.top \
  --non-interactive --agree-tos -m server@ciallo.sale

ls -l /etc/letsencrypt/live/imap.duckgame-play.top/
```

> 签发完成后：方式 A 删除临时 TXT 记录；方式 B 删除 `/root/.secrets/cloudflare.ini`。
> 证书路径：`/etc/letsencrypt/live/imap.duckgame-play.top/{fullchain.pem,privkey.pem}`。

> Stalwart 的 IMAP/TLS 证书在下面配置（把 fullchain/privkey 路径填给 Stalwart 的
> `server.tls` / listener 配置；详见 §4 交互配置）。

## 4. 配置 Stalwart（交互步骤，需用户在 Web UI 完成一次）

Stalwart 管理 UI 默认监听 **localhost:8080**。先在 VPS 上做一次 SSH 端口转发，浏览器打开：

```bash
# 本地(你的电脑)执行，把 VPS 8080 转发到本机 8081：
# ssh -L 8081:127.0.0.1:8080 root@你的VPS
# 然后浏览器打开 http://127.0.0.1:8081 用 §2 拿到的 admin token 登录
```

在 Web UI 里完成（3 分钟）：
1. **Domains** → 新建一个本地域（避免与 CloudMail 的 duckgame-play.top 冲突），如 `local.domain`
2. **Accounts** → 新建邮箱账户：地址 `cloudmail@local.domain`，设一个密码（稍后给雷鸟用）
3. **Server** → 把 IMAP 监听端口设为 `993`，TLS 证书选择 Let's Encrypt 的
   `fullchain.pem / privkey.pem`（§3 生成）；**SMTP 监听 `127.0.0.1:2525`（明文，仅回环，给同步脚本投递）**
   —— 本机投递不用 25（阿里云封 25），2525 不受影响
4. **SMTP Submission**（雷鸟发信）：见 §4.5 无 25 发信方案（第三方 SMTP 中继）
5. 确认默认已有 **Sent / Trash / INBOX** 邮箱（发信导入与删除回写依赖 Sent/INBOX）
6. 记下：邮箱地址 `cloudmail@local.domain`、密码 → 用于雷鸟

> 若 AI 助手无法打开浏览器，也可尝试 Stalwart **管理 REST API** 创建（路径因版本而异，
> 以 Web UI 为准）：`curl -H "Authorization: Bearer <admin_token>" -X POST http://127.0.0.1:8080/api/domain -d '{"name":"local.domain"}'`
> 以及创建 account；失败就用上面的 Web UI 方式。

## 4.5 无 25 发信方案（第三方 SMTP 中继）+ 多域名说明

> 阿里云/VPS 默认**封禁出站 25**，Stalwart 无法直接中继到收件方 MX。
> 解决方案：雷鸟发信走**第三方 SMTP 中继（465/587，不走 25）**，投递由第三方完成，
> 已发送副本仍保存在 Stalwart **Sent**（发信导入照常镜像进 CloudMail）。

**推荐 A：雷鸟直连第三方 SMTP（配置最少）**
1. 注册一个 SMTP 中继服务并拿凭据（任选）：
   - 腾讯云 SES / 阿里云 DirectMail / Brevo(Sendinblue) / Mailgun / SMTP2GO 等
   - 端口 465（SSL）或 587（STARTTLS），普通密码认证
2. 在第三方控制台**验证发件域名**（DNS 加 SPF/DKIM）——多域名场景**每个发件域名都要验证**，
   否则会被当垃圾邮件拒收
3. 雷鸟发件服务器直接填第三方 SMTP（`smtp.xxx.com:465`），用户名/密码 = 第三方凭据；
   **发件身份（From）= CloudMail 域名邮箱**（如 `duckgame@duckgame-play.top`）
4. 雷鸟「副本与文件夹」→ 发送时把副本保存到 **Stalwart 的已发送(Sent) 文件夹**（IMAP 路径）
5. 同步脚本 `syncSent` 检测 Stalwart Sent 新邮件 → 导入 CloudMail 已发送（`/api/email/import-sent`，
   不触发 Resend，因为投递已由第三方完成）

**推荐 B：Stalwart 作为中继（雷鸟只配 Stalwart）**
1. Stalwart Web UI → Server → 开启 submission 监听 `587`（TLS 证书同 IMAP）
2. **Relay 配置**指向第三方 SMTP：`smtp.xxx.com:465` + SMTP AUTH 凭据（不走 25）
3. 雷鸟发件服务器 = `imap.duckgame-play.top:587`（经 Tunnel），用户名/密码 = Stalwart 账户
4. 其余同 A：已发送在 Stalwart Sent → syncSent 镜像到 CloudMail

> ⚠️ 方案 B 中，Stalwart 的 **MAIL FROM 域名**必须与第三方 SMTP 的验证域名一致，
> 否则第三方拒绝代发。多域名时要么每域一个中继凭据，要么统一用 A。

**可选 C（已实现）：雷鸟 → Stalwart 收集 → CloudMail Resend API 投递（零第三方依赖）**
1. **Stalwart Web UI** → Server → 开启 submission 监听 `587`（TLS 证书同 IMAP）；
   **Relay 配置指向本机哑 SMTP**：`relay.host = 127.0.0.1`、`relay.port = 2526`、
   `relay.auth = none`、`relay.security = none`（明文，仅回环）
2. **部署 smtp-void**（接受 Stalwart relay 即丢弃，邮件副本留在 Sent）：
   ```bash
   cp /tmp/cloud-mail/stalwart-sync/smtp-void.js /opt/cloudmail-sync/
   cp /tmp/cloud-mail/stalwart-sync/smtp-void.service /etc/systemd/system/
   systemctl daemon-reload && systemctl enable --now smtp-void
   ```
3. **同步脚本开启 send 模式**：env 加 `SYNC_SENT_MODE=send`（见 §5）
4. 雷鸟发件 SMTP = `imap.duckgame-play.top:587`（Tunnel 已配，见 §6），凭据 = Stalwart 账户
5. 同步脚本检测 Stalwart Sent 新邮件 → 调 `POST /api/email/send`（**CloudMail Resend API，
   HTTPS 投递不走 25**，多域名 resend token 已配）→ 已发送记录直接落 CloudMail
6. 局限：CloudMail `send` 限附件 ≤10（脚本侧截断）+ 发信次数/角色限制；连续失败 3 轮自动放弃
   （详见 `安全加固-雷鸟镜像.md` §四.5）
- **方案 A/B**（第三方 SMTP 中继）仍可用作备选：`SYNC_SENT_MODE=import`（默认）+ import-sent 镜像

### 多域名注意事项（本部署：delicateduck.xyz + ciallo.sale，共 5 号）
- CloudMail 登录用户 `admin@delicateduck.xyz`（多号模式）下有 5 个邮箱账户：
  `contact@ciallo.sale`、`service@ciallo.sale`、`pgp@ciallo.sale`、`admin@delicateduck.xyz`、`noreply@ciallo.sale`
- **推荐拓扑：单 Stalwart 账户 `cloudmail@local.domain` 承接全部 5 号**
  - 下行：`STALWART_ACCOUNTS` 把 5 号全部映射到 `cloudmail@local.domain`（同一 INBOX 混流）
  - 反向同步：一套 JMAP 凭据覆盖全部 5 号（删除/发信/已读按 `emailId` 全局唯一回写各号）
  - 雷鸟：1 个 IMAP 账户 + 5 个发信身份（From 可选任一 CloudMail 域名邮箱）
- **若要在雷鸟隔离 5 个号（各一个 IMAP 账户）**：需建 5 个 Stalwart 账户（如
  `c1@local.domain`…`c5@local.domain`），`STALWART_ACCOUNTS` 各映射其地址；
  ⚠️ **局限**：当前脚本反向同步只支持一套 JMAP 凭据——仅对 JMAP 登录账户（推荐 `cloudmail@local.domain`
  绑定全部 5 地址）生效；多 Stalwart 账户隔离场景需扩展脚本（多 JMAP 凭据），本期未实现
- 每个发件域名（`ciallo.sale`、`delicateduck.xyz`）都需在第三方 SMTP 中继验证 **SPF/DKIM**，
  否则按该域名 From 发信会被当垃圾邮件


## 4.6 文件夹聚合架构（按收件人区分，JMAP 投递）

> 脚本默认 `SYNC_DELIVERY=jmap`：下行用 **JMAP Email/import** 把每个 CloudMail 账户的邮件
> 投递到**各自文件夹**（文件夹名默认 = 账户邮箱地址，`STALWART_FOLDERS` 可覆盖），
> 雷鸟一个 IMAP 账户即可区分 5 个号。

```
cloudmail@local.domain（IMAP 单账户）
├── contact@ciallo.sale     ← 该号收件
├── service@ciallo.sale
├── pgp@ciallo.sale
├── admin@delicateduck.xyz
├── noreply@ciallo.sale
├── Sent                    已发送（方案 C 发信副本）
├── Trash                   垃圾桶（删除→CloudMail 垃圾桶；恢复→CloudMail restore）
├── Drafts                  草稿（仅雷鸟本地，CloudMail 网页草稿在浏览器 IndexedDB，互不同步）
└── Junk                    垃圾邮件（CloudMail 无此概念，仅本地预留）
```

- 各号文件夹由脚本**自动创建**（首次同步时 `Mailbox/set`），无需手工建
- 雷鸟：订阅各号文件夹 + 建"统一收件箱"（雷鸟统一文件夹）查看全部，或直接分看
- 删除/恢复/已读/发信反向同步按文件夹变化驱动（详见 README v4）


## 5. 部署同步脚本（CloudMail → Stalwart）

```bash
# 运行用户 + 目录
useradd -r -s /usr/sbin/nologin cloudsync || true
mkdir -p /opt/cloudmail-sync /var/lib/cloudmail-sync

# 取代码
cd /tmp
git clone --depth 1 -b thunderbird-client https://github.com/DelicateDuck582/cloud-mail.git
cp /tmp/cloud-mail/stalwart-sync/sync.js /opt/cloudmail-sync/
cp /tmp/cloud-mail/stalwart-sync/cloudmail-sync.service /etc/systemd/system/
cp /tmp/cloud-mail/stalwart-sync/smtp-void.js /opt/cloudmail-sync/
cp /tmp/cloud-mail/stalwart-sync/smtp-void.service /etc/systemd/system/
chown -R cloudsync:cloudsync /opt/cloudmail-sync /var/lib/cloudmail-sync

# 环境变量（单账户最小配置：仅镜像 admin 一个号时用）
cat > /etc/cloudmail-sync.env <<'EOF'
CLOUDMAIL_EMAIL=admin@delicateduck.xyz
CLOUDMAIL_PASSWORD=REPLACE_WITH_PASSWORD
STALWART_RCPT_TO=cloudmail@local.domain
STALWART_SMTP_HOST=127.0.0.1
STALWART_SMTP_PORT=2525
SYNC_DELIVERY=jmap   # 下行投递：jmap=文件夹聚合（默认，见 §4.6）；smtp=2525 混流 INBOX（旧）
STATE_FILE=/var/lib/cloudmail-sync/state.json
POLL_INTERVAL=30000
EOF
chmod 600 /etc/cloudmail-sync.env

# 【多号模式：5 个邮箱全镜像（推荐，v4 文件夹聚合）】admin 登录，遍历 5 账户，
#   下行自动用 JMAP 投递到各自文件夹（默认文件夹名 = 账户邮箱，见 §4.6），无需 STALWART_ACCOUNTS
#   contact@ciallo.sale / service@ciallo.sale / pgp@ciallo.sale / admin@delicateduck.xyz / noreply@ciallo.sale
#   可选覆盖文件夹名：STALWART_FOLDERS={"contact@ciallo.sale":"客服","service@ciallo.sale":"服务"}
#   （旧 smtp 模式才需要：STALWART_ACCOUNTS 映射 {"CloudMail账户":"Stalwart地址"}，混流 INBOX）
# ⚠️ 若想在雷鸟隔离 5 个号（各一个 IMAP 账户）：建 5 个 Stalwart 邮箱账户（如 c1@local.domain … ），
#    映射各自地址；反向同步需为每账户配 JMAP 凭据（当前脚本单套凭据，见 §4.5 局限说明）
# 反向同步（可选）：加上以下三项后自动开启 已读回写 / 删除回写 / 发信导入
#   STALWART_JMAP_URL=https://127.0.0.1:8080/jmap
#   STALWART_USERNAME=cloudmail@local.domain
#   STALWART_PASSWORD=Stalwart邮箱密码（§4 创建 cloudmail@local.domain 时设置；可复用 admin 密码）
#   # STALWART_SENT_MAILBOX=Sent   # 已发送邮箱名（默认 Sent）
#   # SYNC_SENT_HISTORY=0          # 首次启用时追溯历史已发送（默认不追溯）
#   # SYNC_SENT_MODE=send          # 方案 C：走 CloudMail Resend API 投递（需 smtp-void + Stalwart Relay，见 §4.5）
#                                  # 默认 import：第三方 SMTP 中继投递，仅镜像记录
#   # STALWART_FOLDERS={"contact@ciallo.sale":"客服"}   # 可选：文件夹名覆盖（默认用账户邮箱地址）
# ⚠️ 发信导入依赖 mail-worker 新端点 /api/email/import-sent，需先在 Cloudflare 重新部署 mail-worker
# ⚠️ 方案 C（SYNC_SENT_MODE=send）还需部署 smtp-void 服务（见 §4.5），并 `systemctl enable --now smtp-void`

# 启动
systemctl daemon-reload
systemctl enable --now cloudmail-sync
journalctl -u cloudmail-sync -f   # 观察是否开始同步
```

## 6. 配置 Cloudflare Tunnel（出站，不暴露 VPS IP）

```bash
# 用控制台创建的 Tunnel Token 安装为系统服务
cloudflared service install 这里填TUNNEL_TOKEN

# 域名路由：imap.duckgame-play.top → 隧道（代理开橙云）
cloudflared tunnel route dns 隧道名 imap.duckgame-play.top
```

> 若 cloudflared 版本需要显式 ingress，参考：
> ```yaml
> # /etc/cloudflared/config.yml
> tunnel: 隧道名
> credentials-file: /root/.cloudflared/隧道名.json
> ingress:
>   - hostname: imap.duckgame-play.top
>     service: tcp://127.0.0.1:993      # IMAPS
>   - hostname: imap.duckgame-play.top  # 同域名不同端口，Tunnel 按端口分流
>     service: tcp://127.0.0.1:587      # SMTP submission（雷鸟发信）
>   - service: http_status:404
> ```
> 配好后 `systemctl restart cloudflared`。

## 7. 防火墙：拒绝所有入站

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp   # 保留 ssh（按需改端口）
ufw --force enable
ufw status
```

> 993 虽被 Stalwart 监听，但外部包被防火墙丢弃；Tunnel 到 127.0.0.1:993 是本地回环，不受影响。

## 8. 验证

```bash
# Stalwart 状态
systemctl status stalwart-mail --no-pager | head -5
# 同步脚本状态 + 最近同步
systemctl status cloudmail-sync --no-pager | head -5
journalctl -u cloudmail-sync --no-pager -n 20

# 通过公网域名测 IMAPS 握手（应看到 * OK Stalwart ...）
timeout 10 openssl s_client -connect imap.duckgame-play.top:993 -servername imap.duckgame-play.top </dev/null 2>/dev/null | grep -E 'subject=|* OK' | head -5
```

**JMAP 文件夹投递验证**（§4.6 架构；AI 助手执行）：
```bash
# 1. 同步脚本日志：应看到「投递 JMAP 文件夹」+ 各账户「同步 <emailId>」
journalctl -u cloudmail-sync --no-pager -n 50 | grep -E '投递|同步|删除|恢复|发信|已读'

# 2. JMAP 会话 + 各号文件夹存在（用雷鸟密码登录，拿 mail 账户 id）
TOKEN=$(curl -s -u "cloudmail@local.domain:Stalwart邮箱密码" http://127.0.0.1:8080/jmap -X POST \
  -H 'Content-Type: application/json' \
  -d '{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo",{},"c0"]]}' | jq -r '.accountId // "check-session"')

# 3. 列文件夹，应包含 5 个号 + Sent + Trash
curl -s -u "cloudmail@local.domain:Stalwart邮箱密码" http://127.0.0.1:8080/jmap -X POST \
  -H 'Content-Type: application/json' \
  -d "{\"using\":[\"urn:ietf:params:jmap:core\",\"urn:ietf:params:jmap:mail\"],\"methodCalls\":[[\"Mailbox/query\",{\"accountId\":\"\$TOKEN\"},\"m0\"]]}" \
  | jq -r '.methodResponses[0][1].ids[0] as $x | "Mailbox/query OK"' 2>/dev/null || echo '按需用 jq 解析文件夹列表'
```

## 9. Thunderbird 添加账户

1. 雷鸟 → 添加邮件账户 → 手动配置
2. 用户名/密码 = Stalwart 里建的 `cloudmail@local.domain` + 密码（§4）
3. 收件服务器：`imap.duckgame-play.top`，端口 `993`，SSL/TLS，普通密码
4. **文件夹（聚合 5 号）**：账户创建后订阅 §4.6 的各号文件夹（contact/service/pgp/admin/noreply），
   可选建「统一收件箱」虚拟文件夹聚合查看；删除/恢复 = 移入/移出 Trash 文件夹
5. **发件服务器（可选，开启发信同步时，无 25 方案）**：
   - 方案 A：第三方 SMTP（如 `smtp.xxx.com:465`，SSL/TLS），凭据 = 第三方中继的，见 §4.5
   - 方案 C：`imap.duckgame-play.top:587`（STARTTLS），凭据 = Stalwart 账户，见 §4.5
   - **已发送副本保存到 Stalwart 的 Sent 文件夹**（雷鸟「副本与文件夹」设置），否则发信无法镜像
6. **多身份发信切换**：雷鸟账户设置 → 管理身份 → 为每个 CloudMail 域名邮箱加一个身份，
   发信时下拉选择（From 必须是 CloudMail 域名邮箱，发信才镜像）
5. 收件箱应显示 CloudMail 收件；点「获取新邮件」手动刷新（最迟 30s 内看到新邮件）
6. ⚠️ 发信时**发件人必须选 CloudMail 域名邮箱**（如 `duckgame@duckgame-play.top`），
   已发送才会镜像到 CloudMail；`local.domain` 地址发信不镜像
7. 删除邮件 = 移入垃圾桶/移除收件箱 → 30s 内同步为 CloudMail 垃圾桶

## 10. 限制与说明

| 项 | 说明 |
|---|---|
| 反向同步 | 雷鸟已读→CloudMail、删除→CloudMail 垃圾桶、发信→CloudMail 已发送（需配置 JMAP） |
| 同步 | 仅收件箱、轮询 30s、增量（state.json）；删除/发信回写延迟同为 30s |
| 附件 | 默认不同步（CloudMail 网页看）；`ATTACHMENTS=1` 可开启 |
| 发信 | 无 25 方案：第三方 SMTP 中继（465/587）投递，已发送副本存 Stalwart Sent 后镜像进 CloudMail（需重新部署 mail-worker） |
| AGPL | Stalwart 未修改、未分发，自托管合规；本地副本哈希校验一致 |
| 安全 | 见 `安全加固-雷鸟镜像.md`（COS 签名/COS 前置代理/传输层/数据丢失场景分析） |

---
*部署完成后：删除 `/root/.secrets/cloudflare.ini`（或留作续期）；确认 `stalwart-mail`、`cloudmail-sync`、`cloudflared` 均 running；`ufw status` 为 incoming deny。*


