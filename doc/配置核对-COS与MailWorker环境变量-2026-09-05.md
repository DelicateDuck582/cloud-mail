# COS-exchange / mail-worker 环境变量配置核对（2026-09-05）

> 依据：Cloudflare 面板实际配置 + 代码（mail-worker=attachment-manager 3770547；cos=doc/cos-proxy-worker.js）
> 目标：核对配置与代码要求是否一致，标出风险项

---

## 1. cos-exchange（cos.<域名>）

| 变量 | 你的值 | 类型 | 代码要求 | 核对 |
|---|---|---|---|---|
| `ATT_SIGN_SECRET` | 加密 | 密钥 | 与 mail-worker 同值 | ✅（需人工确两侧一致） |
| `ATT_SIGN_MAX_TTL` | `3600` | 文本 | 数字；非法回退 3600 | ✅ |
| `AWS_ACCESS_KEY_ID` | 加密 | 密钥 | COS 只读子账号 | ✅ |
| `AWS_SECRET_ACCESS_KEY` | 加密 | 密钥 | 同上 | ✅ |
| `BROWSE_ALLOW_COUNTRY` | `CN,JP` | 文本 | 逗号分隔地区码 | ✅（注意：除 CN/JP 外**全部拒绝**） |
| `BROWSE_PASS` | 加密 | 密钥 | 必填 | ✅ |
| `REGION` | `ap-osaka` | 文本 | S3 签名 region | ⚠️ 见下 |
| `S3_ENDPOINT` | 加密 | 密钥 | 桶访问域名 | ✅（需以 `https://` 开头） |
| `TURNSTILE_SECRET` | 加密 | 密钥 | 可选 | ✅ |
| `TURNSTILE_SITEKEY` | 加密 | 密钥 | 可选 | ⚠️ 见下 |

### ⚠️ cos-exchange 两个注意点

1. **`TURNSTILE_SITEKEY` 用「密钥」类型**：sitekey 是**公开值**（会直接出现在登录页 HTML 的 `data-sitekey` 与前端脚本里），
   放「密钥」类型不影响读取，但属于类型误用——它最终必然暴露给浏览器，设为 secret 无保密收益。
   建议改「文本」类型，便于排障；`TURNSTILE_SECRET` 保持「密钥」正确。
   （不影响当前功能，仅运维建议。）

2. **`REGION=ap-osaka` + `S3_ENDPOINT`（日本桶）**：
   - 与代码无冲突；S3 V4 签名 `Credential=…/ap-osaka/s3/…`，只要 S3_ENDPOINT 是同一 ap-osaka 桶即可。
   - ⚠️ `BROWSE_ALLOW_COUNTRY=CN,JP` 是**访问者 IP 国家白名单**，与桶地域无关，配置本身正确；
     但需注意：你在日本访问会过，但若用其它地区代理/服务器测试会被 403——排障时容易误判。

3. **COS 健康探测**：探测走 `browseList`（需 `GetBucket` 权限）。若只读子账号策略缺 `GetBucket`，
   `/browse` 首页会 503「COS对象存储错误」，与列表权限相关，建议确认策略含 `GetObject + GetBucket`。

---

## 2. mail-worker（mail.<域名>）

| 变量 | 你的值 | 类型 | 代码要求 | 核对 |
|---|---|---|---|---|
| `admin` | `admin@moeq.moe` | 文本 | 管理员邮箱 | ⚠️ 见下（**关键**） |
| `ATT_SIGN_SECRET` | 加密 | 密钥 | 与 cos-exchange 同值 | ✅ 需两侧一致 |
| `ATT_SIGN_TTL` | `900` | 文本 | 60~86400，默认 900 | ✅ |
| `domain` | `["duckgame-play.top","delicateduck.xyz","ciallo…` | JSON | 数组 | ⚠️ 见下 |
| `INIT_SECRET` | 加密 | 密钥 | 必填（/init） | ✅ |
| `jwt_secret` | 加密 | 密钥 | 签名密钥 | ✅ |
| `RESEND_SIGNING_SECRET` | 加密 | 密钥 | Resend webhook 验签 | ✅ |

### 🚩 关键核对结果：admin 域必须在 domain 白名单内

代码事实（已逐行确认）：
- **注册**（`login-service.js` L86）：`if (!c.env.domain.includes(emailUtils.getDomain(email))) throw 'notEmailDomain'`
- **新增账户**（`account-service.js` L38）：同样校验 domain
- **登录**（`login-service.js` L224+）：**不校验 domain**（只查用户存在 + 密码）

含义：
- `admin@moeq.moe` **若已存在于 DB**：登录正常（登录不走 domain 校验）。
- 但**新建/注册任何 `@moeq.moe` 账号都会被拒**，除非 `domain` 数组包含 `"moeq.moe"`。
- 你的截图 domain 值被截断（`ciallo…`），**请确认数组完整内容是否包含 `"moeq.moe"`**；
  若不含，admin 邮箱所属域在「域名管理」里也无法加号使用。

**检查方法（无凭证视角）**：登录后台 → 设置/域名列表里应能看到 moeq.moe 被列入；或后续在 VPS/控制台核 `wrangler secret`（面板 vars 是明文 JSON，直接在面板看完整值）。

### ⚠️ mail-worker 补充

1. `domain` 里出现 `ciallo…`（如 ciallo.sale）与 `delicateduck.xyz`：与 thunderbird/stalwart 文档中
   收件域一致（contact/service/pgp/noreply@ciallo.sale、admin@delicateduck.xyz），属预期。
2. `admin=admin@moeq.moe` 与历史文档示例（`admin@delicateduck.xyz`）不同——若这是新管理员邮箱，
   需保证其账号已被创建（初始化/注册）；且角色/权限按 `user.email === c.env.admin` 判断，
   只认这一个地址为超管。
3. `ATT_SIGN_TTL=900` + cos 侧 `ATT_SIGN_MAX_TTL=3600`：**配对正确**（900<3600），无超长签名被拒风险。

---

## 3. 安全提示汇总

| # | 项 | 级别 | 建议 |
|---|---|---|---|
| 1 | `admin@moeq.moe` 域不在 domain 白名单则无法新建该域账号 | **高** | 确认 domain 数组含 moeq.moe |
| 2 | `ATT_SIGN_SECRET` 两侧一致性 | 高 | 面板两侧均「加密」无法目检；可用同一随机串重新 set 两侧 |
| 3 | `TURNSTILE_SITEKEY` 应为文本类型 | 低 | 改文本（值本就公开） |
| 4 | COS 只读子账号需 `GetObject+GetBucket` | 中 | 确认策略，否则 /browse 503 |
| 5 | `BROWSE_ALLOW_COUNTRY=CN,JP` | 低 | 排障时注意非中/日 IP 一律 403 |
| 6 | `domain` 与 `admin` 邮箱域 | 中 | 完整值务必核对（截图截断处） |

> 无凭证探测已在 2026-08-29 做过（行为正常）；本次为配置↔代码静态核对。
