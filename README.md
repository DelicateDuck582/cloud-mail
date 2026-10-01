<p align="center">
    <img src="doc/demo/logo.png" width="80px" />
    <h1 align="center">Cloud Mail</h1>
    <p align="center">基于 Cloudflare 的简约响应式邮箱服务，支持邮件发送、附件收发 🎉</p> 
    <p align="center">
        简体中文 | <a href="/README-en.md" style="margin-left: 5px">English </a>
    </p>
    <p align="center">
        <a href="https://github.com/maillab/cloud-mail/tree/main?tab=MIT-1-ov-file" target="_blank" >
            <img src="https://img.shields.io/badge/license-MIT-green" />
        </a>    
        <a href="https://github.com/maillab/cloud-mail/releases" target="_blank" >
            <img src="https://img.shields.io/github/v/release/maillab/cloud-mail" alt="releases" />
        </a>  
        <a href="https://github.com/maillab/cloud-mail/issues" >
            <img src="https://img.shields.io/github/issues/maillab/cloud-mail" alt="issues" />
        </a>  
        <a href="https://github.com/maillab/cloud-mail/stargazers" target="_blank">
            <img src="https://img.shields.io/github/stars/maillab/cloud-mail" alt="stargazers" />
        </a>  
        <a href="https://github.com/maillab/cloud-mail/forks" target="_blank" >
            <img src="https://img.shields.io/github/forks/maillab/cloud-mail" alt="forks" />
        </a>
    </p>
    <p align="center">
        <a href="https://trendshift.io/repositories/20459" target="_blank" >
            <img src="https://trendshift.io/api/badge/repositories/20459" alt="trendshift" >
        </a>
    </p>
</p>

## 项目简介

只需要一个域名，就可以创建多个不同的邮箱，类似各大邮箱平台，本项目支持署到 Cloudflare Workers ，降低服务器成本，搭建自己的邮箱服务

## 项目展示

- [在线演示](https://skymail.ink)<br>
- [部署文档](https://doc.skymail.ink)<br>

| ![](/doc/demo/demo1.png) | ![](/doc/demo/demo2.png) |
|-----------------------|-----------------------|
| ![](/doc/demo/demo3.png) | ![](/doc/demo/demo4.png) |

## 功能介绍

- **💰 低成本使用**： 可部署到 Cloudflare Workers 降低服务器成本
- **💻 响应式设计**：响应式布局自动适配PC和大部分手机端浏览器
- **📧 邮件发送**：集成Resend发送邮件，支持群发，内嵌图片和附件发送，发送状态查看
- **🛡️ 管理员功能**：可以对用户，邮件进行管理，RABC权限控制对功能及使用资源限制
- **📦 附件收发**：支持收发附件，使用R2对象存储保存和下载文件
- **🔔 邮件推送**：接收邮件后可以转发到TG机器人或其他服务商邮箱
- **📡 开放API**：支持使用API批量生成用户，多条件查询邮件
- **🔢 验证码识别**：使用Workers AI，自动识别邮件验证码
- **📈 数据可视化**：使用ECharts对系统数据详情，用户邮件增长可视化显示
- **🎨 个性化设置**：可以自定义网站标题，登录背景，透明度
- **🤖 人机验证**：集成Turnstile人机验证，防止人机批量注册
- **📜 更多功能**：正在开发中...

## 本项目新增功能（Fork 增强）

> 这是按照个人使用需求、由 AI 编写的增强功能。安全加固与安全审计的完整说明见 [doc/](doc/)。

- **🔐 附件签名防伪造**：COS/S3 私有桶 + 后端签发的短期 HMAC 签名 + Referer/Sec-Fetch 双层校验 + 代理 Worker（cos-exchange）验签与按内容哈希缓存，防盗链防伪造（详见 [doc/签名防伪造改造说明.md](doc/签名防伪造改造说明.md)）
- **📁 附件管理器**：按文件内容哈希分组展示，支持预览 / 下载 / 删除 / 恢复 / 彻底删除与管理员按用户筛选
- **🗑️ 垃圾桶机制**：邮件与附件删除均进垃圾桶（软删除，7 天后自动彻底清理），支持恢复；仅超级管理员可彻底删除
- **📊 COS 使用量统计**：附件占用 / COS 实际存储 / 剩余容量可视化，可配置总容量（GB）与到期红色提醒
- **👥 权限组（安全组）**：`all-email:query` 角色可查看 / 管理全部用户邮件与附件，彻底删除仅限超级管理员
- **✍️ HTML 签名**：个人设置中配置 HTML 个性签名，新建邮件时自动插入编辑器
- **📏 附件大小限制**：发送时附件超过 28MB 前端直接提示超限（适配 Resend 40MB 上限）
- **🛡️ 安全加固**：邮件 HTML 入库白名单清洗 + 前端渲染兜底、附件直读端点强制 HMAC 签名校验、权限中间件与归属校验、Svix Webhook 恒定时间验签、登录 / 附件直读限流、边缘缓存防绕过等（完整清单见 [doc/安全审计修复记录-2026-08-29.md](doc/安全审计修复记录-2026-08-29.md) 与 [doc/审计报告-COS-EWS-2026-10.md](doc/审计报告-COS-EWS-2026-10.md)）
- **📥 Thunderbird 接入（EWS）**：内置 EWS 兼容端点，Thunderbird 145+ 可直接以「Exchange」账号收发邮件，支持按收件地址分文件夹（详见 [doc/EWS-Thunderbird.md](doc/EWS-Thunderbird.md)）

## 技术栈

- **平台**：[Cloudflare Workers](https://developers.cloudflare.com/workers/)
- **Web框架**：[Hono](https://hono.dev/)
- **ORM：**[Drizzle](https://orm.drizzle.team/)
- **前端框架**：[Vue3](https://vuejs.org/)
- **UI框架**：[Element Plus](https://element-plus.org/)
- **邮件推送：** [Resend](https://resend.com/)
- **缓存**：[Cloudflare KV](https://developers.cloudflare.com/kv/)
- **数据库**：[Cloudflare D1](https://developers.cloudflare.com/d1/)
- **文件存储**：[Cloudflare R2](https://developers.cloudflare.com/r2/)

## 目录结构

```
cloud-mail
├── mail-worker				    # worker后端项目
│   ├── src                  
│   │   ├── api	 			    # api接口层			
│   │   ├── const  			    # 项目常量
│   │   ├── dao                 # 数据访问层
│   │   ├── email			    # 邮件处理接收
│   │   ├── entity			    # 数据库实体
│   │   ├── error			    # 自定义异常
│   │   ├── hono			    # web框架配置、拦截器、全局异常等
│   │   ├── i18n			    # 语言国际化
│   │   ├── init			    # 数据库缓存初始化
│   │   ├── model			    # 响应体数据封装
│   │   ├── security			# 身份权限认证
│   │   ├── service			    # 业务服务层
│   │   ├── template			# 消息模板
│   │   ├── utils			    # 工具类
│   │   └── index.js			# 入口文件
│   ├── pageckge.json			# 项目依赖
│   └── wrangler.toml			# 项目配置
│
├── mail-vue				    # vue前端项目
│   ├── src
│   │   ├── axios 			    # axios配置
│   │   ├── components			# 自定义组件
│   │   ├── echarts			    # echarts组件导入
│   │   ├── i18n			    # 语言国际化
│   │   ├── init			    # 入站初始化
│   │   ├── layout			    # 主体布局组件
│   │   ├── perm			    # 权限认证
│   │   ├── request			    # api接口
│   │   ├── router			    # 路由配置
│   │   ├── store			    # 全局状态管理
│   │   ├── utils			    # 工具类
│   │   ├── views			    # 页面组件
│   │   ├── app.vue			    # 入口组件
│   │   ├── main.js			    # 入口js
│   │   └── style.css			# 全局css
│   ├── package.json			# 项目依赖
└── └── env.release				# 项目配置
```

## 赞助（支持它一下吧maillab/cloud-mail）

<a href="https://doc.skymail.ink/support.html" >
<img width="170px" src="./doc/images/support.png" alt="">
</a>

## 许可证

本项目采用 [MIT](LICENSE) 许可证

## 交流

[Telegram](https://t.me/cloud_mail_tg)

## Thunderbird 接入（EWS）

CloudMail 内置 EWS（Exchange Web Services）兼容端点，**Thunderbird 145+** 可直接以「Exchange」账号接入收发邮件，无需插件、无需额外开启 IMAP/SMTP。端点地址为 `https://<你的mail域名>/EWS/Exchange.asmx`（大小写不敏感）。

部署新版 Worker 后需调用一次初始化接口完成数据库迁移（幂等，可重复执行）：

```
POST https://<你的Worker域名>/api/init
Body: {"secret":"<你的 INIT_SECRET>"}
```

已知限制（Free 计划单请求 10ms CPU 约束）：

- 经 EWS（MIME 重建）读取邮件时，单个内嵌图/附件超过 `EWS_MAX_ATT_BYTES`（默认 **1MB**，可用环境变量调大）不会随 MIME 下发：内嵌图在 Thunderbird 正文里显示为「图片过大（>1MB）…请使用网页版查看」的文字占位，附件则直接不显示（邮件本体与其余附件正常）。Workers Paid 计划 CPU 更宽裕，可调大 `EWS_MAX_ATT_BYTES` 放宽该限制。

配置步骤、账号文件夹机制、Free 计划限制、不支持的功能与排错，详见 [doc/EWS-Thunderbird.md](doc/EWS-Thunderbird.md)。
