# CloudMail → Stalwart 同步（替换最小 IMAP 桥）

把 CloudMail 收件箱镜像到 **Stalwart Mail Server**（标准 IMAP/POP/JMAP 服务器），
雷鸟用原生 IMAP 读取 —— **协议层交给 Stalwart 兜底，不再有自定义 IMAP 桥的 bug 风险**。

## 架构
```
Cloudflare Email Routing → CloudMail (D1)  ← 主数据源（网页端 / 发信）
                                ↕ 本脚本（轮询 API → 重建 MIME → 本机 SMTP 投递）
VPS: Stalwart (SQLite) ←── IMAP :993 ── Cloudflare Tunnel ── Thunderbird
```

## 文件
| 文件 | 说明 |
|---|---|
| `sync.js` | 同步脚本（Node 零依赖）：拉 CloudMail API → 重建 MIME → 投 Stalwart 本机 SMTP |
| `cloudmail-sync.service` | systemd 单元（cloudsync 用户 + 加固） |
| `部署-阿里云CLI助手.md` | VPS 部署文档（Stalwart + 同步 + Tunnel + 防火墙） |

## 同步脚本
- **增量**：状态文件 `state.json` 记录已同步 emailId，只拉新邮件。
- **正文**：`multipart/alternative`（text/plain + text/html），HTML 为 CloudMail 清洗后的内容。
- **附件**（`ATTACHMENTS=1` 时）：从签名 `att.url` 拉取 base64 拼入 `multipart/mixed`；默认关闭（附件在 CloudMail 网页查看）。
- **投递**：经 Stalwart 本机 SMTP（127.0.0.1:25），`RCPT TO` 为 Stalwart 里建好的目标邮箱。

## 环境变量（systemd `EnvironmentFile`）
```
CLOUDMAIL_EMAIL=你的CloudMail邮箱
CLOUDMAIL_PASSWORD=你的CloudMail密码
STALWART_RCPT_TO=cloudmail@local.domain   # Stalwart 里建的目标邮箱
STALWART_SMTP_HOST=127.0.0.1
STALWART_SMTP_PORT=25
STATE_FILE=/var/lib/cloudmail-sync/state.json
POLL_INTERVAL=30000
# ATTACHMENTS=1   # 可选：同步附件
```

## 限制（v1）
- 只读镜像：雷鸟里标已读/删除不会回写 CloudMail（主数据在 CloudMail）。
- 只同步收件箱（type=0）。
- 同步延迟 = 轮询间隔（默认 30s）。
- Stalwart 是镜像副本；如需"发信"，仍用 CloudMail 网页端。

## AGPL 合规
- **不修改 Stalwart 代码**（用官方二进制/镜像原样部署）。
- 本地参考副本：`E:\DEVE 开发\stalwart`（从 `E:\数据迁移\开发\stalwart` 原样复制，哈希校验一致）。
- 自托管使用不涉及分发，无 AGPL 义务触发。
