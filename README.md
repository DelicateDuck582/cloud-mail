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

#### **这是由AI编写的增强功能。本人只是小白，按照自己的想法与实际用到的功能让AI编写的**

本仓库在 upstream 基础上增加了以下自定义功能：

- **🔐 附件签名防伪造**：COS/S3 私有桶存储，附件访问使用后端签发的短期 HMAC 签名（默认 15 分钟有效）+ Referer/Sec-Fetch 双层校验，防止盗链与伪造访问；直读代理 Worker（cos-exchange）验签通过后用 Cache API 按文件缓存（附件 key 为内容哈希，缓存 7 天，文件不变即最多每 7 天回源一次）。改造说明见 [doc/签名防伪造改造说明.md](doc/签名防伪造改造说明.md)，代理 Worker 代码见 [doc/cos-proxy-worker.js](doc/cos-proxy-worker.js)
- **📁 附件管理器**：独立的附件管理页面
  
  - 「全部 / 垃圾桶」双选项卡
  - **按文件（内容哈希）分组展示**，可展开二级表格查看每个用户的引用明细，支持单用户操作（定位邮件 / 删除 / 恢复）
  - 类型自动识别显示（`附件-图片` / `附件-Word文档` / `附件-PDF` / `附件-压缩包` 等，按扩展名）
  - 工具栏操作按钮常驻（预览 / 下载 / 删除 / 恢复 / 彻底删除），未选择附件时给出提示
  - 管理员可按用户筛选，显示所属用户与权限组
  - 点击文件名可直接预览（移动端友好）
  - 响应式布局，表格在容器内滚动不溢出
- **🗑️ 邮件与附件垃圾桶机制**：删除 = 移入垃圾桶（软删除，原文件不受影响），记录删除时间，7 天后系统自动彻底清理；删除附件会连带邮件一起进垃圾桶，恢复附件也会连带恢复邮件；邮件删除同样进垃圾桶并支持恢复；**仅超级管理员可彻底删除**
- **📊 COS 使用量统计**：附件管理页展示附件占用 / COS 实际存储 / 已用 / 总量 / 剩余，可配置总容量（GB）与 S3 到期时间（过期红色提醒）
- **👥 权限组（安全组）**：被授予 `all-email:query` 权限的角色可查看全部用户的邮件与附件，可管理（软删 / 恢复）任意附件，但**不能彻底删除垃圾桶**（该操作仅限超级管理员）
- **✍️ HTML 签名**：个人设置中配置 HTML 个性签名（如 QQ 邮箱签名卡），新建邮件时自动插入编辑器
- **📏 附件大小限制**：发送时附件超过 28MB 前端直接提示超限（适配 Resend 整封邮件 40MB、base64 后的实际上限）
- **🛡️ 安全加固**：
  - 修复默认角色被误授 `all-email:query`（全站邮件/附件查看）权限的问题
  - 附件直读端点（`/api/oss`、`/attachments`）强制 HMAC 签名校验，防止绕过签名防伪系统
  - 无权限的删除 / 恢复操作明确返回 403（不再静默成功）
  - 邮件删除 / 恢复接口纳入权限中间件与归属校验
  - COS 用量遍历增加页数上限，错误响应不泄露内部信息
  - 附件直读代理 Worker（cos-exchange）修复含空格 / Unicode 文件名的签名校验，并对已签名请求放宽 Referer / Sec-Fetch 校验（兼容邮件客户端）
  - **邮件内容 XSS 防护**：邮件 HTML 在入库时用白名单清洗（linkedom）：移除 `script` / `iframe` / `object` / `embed` / `svg` / `math` / 表单控件、所有 `on*` 事件属性、`javascript:` / `vbscript:` / `data:text/html` 等危险 URL 与危险 CSS；前端渲染（ShadowHtml 详情、回复/转发注入、TG 预览页、签名预览）再做一次同规则清洗兜底旧数据

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


