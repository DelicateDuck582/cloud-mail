# Thunderbird 接入指南（EWS）

> 本文档自 README 迁出（2026-10-01），为 CloudMail EWS 端点的完整接入说明，持续在此维护。

CloudMail 内置 EWS（Exchange Web Services）兼容端点，**Thunderbird 145+** 可直接以「Exchange」账号接入收发邮件，无需插件、无需额外开启 IMAP/SMTP。端点地址为 `https://<你的mail域名>/EWS/Exchange.asmx`（大小写不敏感）。

## 一、升级后先执行数据库迁移

EWS 依赖 v4_4DB 迁移（`ews_sync_state` 同步水位表 + `email.update_time` 增量列 + `ews_tombstone` 物理删除事件表），部署新版 Worker 后调用一次初始化接口即可（幂等，可重复执行）：

```
POST https://<你的Worker域名>/api/init
Body: {"secret":"<你的 INIT_SECRET>"}
```

## 二、Thunderbird 配置步骤

1. Thunderbird →「账户设置」→「账户操作」→「添加邮件账户」；
2. 输入姓名、CloudMail 登录邮箱、密码，点击「继续」，若自动探测失败选择「手动配置（Manual config）」；
3. 传入协议选择 **Exchange**（不要选 IMAP/POP）；
4. **服务器 URL** 填 `https://<你的mail域名>/EWS/Exchange.asmx`；
5. 用户名 = CloudMail 登录邮箱，密码 = 登录密码，认证方式为「普通密码 / Normal password」（即 HTTP Basic）；
6. 完成后可见 Inbox / Sent Items / Deleted Items / Drafts / Outbox 五个文件夹；**首次获取消息（同步）后**还会出现该用户名下每个收件地址的独立文件夹（DisplayName = 账号邮箱地址）。

> **文件夹与邮件范围**：**收件箱（Inbox）= 该用户名下全部收件账号的邮件聚合**（已发送 / 已删除同样按用户聚合，信息不丢）；同时，名下**每个收件地址（account）会作为独立自定义文件夹出现**（FolderId 形如 `acct-<accountId>`，DisplayName = 账号邮箱），内容为该地址自己的可见收件（未删除、不在垃圾桶），从而**按地址分文件夹访问各自的邮件**。这些账号文件夹在 Thunderbird **首次获取消息 / 同步文件夹**时随层级一次下发（之后仅回空变更；新增/删除收件账号需重建账户或重新全量同步才会反映）。发信默认使用与登录邮箱同名的收件账号（无同名账号时按 From 指定的本人账号、登录邮箱主账号依次回退）。

> 本实现**不提供 Autodiscover**（`/autodiscover/autodiscover.xml`），必须手动填写 EWS 服务器 URL。

## 三、Free 计划限制

- **附件大小**：经 EWS 收发/读取的单个附件（含内嵌图）默认上限 **1MB**，可用环境变量 `EWS_MAX_ATT_BYTES`（字节）放大，付费计划（CPU 更宽裕）建议放宽；超过上限的附件在 Web 端正常收发，仅 EWS 通道受限：
  - 发送：超过上限直接报错 `Attachment is too large for EWS ... Please send it from the CloudMail web client.`；
  - 收取：重建 MIME 时超限附件会被跳过（正文与其它附件正常显示）；`GetAttachment` 超限返回 Fault 提示改用 Web 端下载。
- **同步分页**：单次 `SyncFolderItems` 最多返回 50 封邮件的变更，邮件很多时 Thunderbird 会自动翻页拉取，首轮同步稍慢。
- **批量上限**：单次 `GetItem` / `GetAttachment` 最多 200 个 Id（超出返回 `ErrorMaxBatchSizeExceeded`），`DeleteItem` 无此限制（分片执行）；其中**请求 `MimeContent`（`IncludeMimeContent`）时单次最多重建 20 封**（其余只回元数据，客户端可按需再取），且一次响应内重建的附件总量受 `EWS_MAX_TOTAL_ATT_BYTES`（默认 `2 ×` `EWS_MAX_ATT_BYTES`）限制，超出的附件被跳过。
- **请求体上限**：单次 POST 的 XML 请求体上限 40MB；服务端在读体前按 `Content-Length` 预检、缺失长度时按流式累计字节，超限直接返回 `413`。
- **认证缓存**：EWS 认证结果在 KV 缓存 5 分钟（缓存键为带 `jwt_secret` 加盐的 SHA-256，`jwt_secret` 未配置时退化为不加盐并打日志，生产必配），修改密码后最多 5 分钟内旧密码仍可通过 EWS 认证（Web/JWT 侧不受影响）。
- **无推送通知**：未实现 `Subscribe/GetEvents/StreamingSubscription`，Thunderbird 会自动降级为定时轮询（`SyncFolderItems`），不消耗长连接。

## 四、不支持的功能

以下操作统一返回 `ErrorNotImplemented` SOAP Fault（Thunderbird 会容忍并降级）：

- 推送通知与事件订阅（Subscribe / Unsubscribe / GetEvents / StreamingSubscription）；
- 草稿写入（`CreateItem MessageDisposition="SaveOnly"`，收发信正常，但草稿箱只读/为空）；
- 服务器端搜索与查找（FindItem / FindFolder / SearchMailboxes）、移动/复制邮件（MoveItem / CopyItem）；
- 日历、会议、联系人、自动回复（OOF）、`GetUserAvailability`、`ConvertId` 等非邮件操作（`ResolveNames` / `GetMailTips` / `GetServerTimeZones` 已实现，供 Thunderbird 账号配置阶段校验地址用时区）；
- 附件直读签名与 COS 回退逻辑不受影响：EWS 侧复用了 Web 端同一套存储读取（r2-service），COS 故障期间回退 KV。

> **物理删除的同步已被 tombstone 机制覆盖**：附件彻底删除、自动清理等**服务器主动物理删除**的邮件，会在 **30 天内**通过增量同步（`SyncFolderItems`）以 `Delete` 事件下发给 Thunderbird，客户端不会残留「幽灵邮件」；`ews_tombstone` 表由每日定时任务清理 30 天前的记录（超过 30 天未同步过的客户端需重新同步）。该机制覆盖 Inbox / Sent Items / Deleted Items；**账号文件夹（`acct-<id>`）不产出 tombstone 的 Delete 事件**（`ews_tombstone` 不记录账号归属），其中的物理删除残留需由客户端重新全量同步消化。

## 五、排错

- `401 Unauthorized`：邮箱或密码错误（用户名必须是 CloudMail 登录邮箱，不是别名账户）；同 IP 连续 10 次失败会被锁 5 分钟，凭据错误的响应带约 1 秒失败延迟（防爆破）。锁定计时以最后一次失败起算，重试会续期——被锁后请等待而不是连续重试。
- `413`：请求体超过 40MB（服务端在读体前就拒绝，不会把整个 body 读进内存）。
- `ErrorInternalServerError ... v4_4DB`：数据库未执行升级，见「一、升级后先执行数据库迁移」。
- `ErrorFolderNotFound`：请求了不存在的文件夹（支持 Inbox / Sent Items / Deleted Items / Drafts / Outbox，以及**当前用户名下**的账号文件夹 `acct-<accountId>`；请求他人账号的 `acct-<id>` 同样返回此错误）。
- 邮件正文/附件缺失：多为附件超过 `EWS_MAX_ATT_BYTES`（见「三、Free 计划限制」）。
