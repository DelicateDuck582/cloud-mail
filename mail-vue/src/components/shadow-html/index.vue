<template>
  <div class="content-box" ref="contentBox">
    <div ref="container" class="content-html"></div>
  </div>
</template>

<script setup>
import { ref, onMounted, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { useI18n } from 'vue-i18n'
import { sanitizeHtml, sanitizeCss } from '@/utils/sanitize-html'

const { t } = useI18n()

const props = defineProps({
  html: {
    type: String,
    required: true
  }
})

const container = ref(null)
const contentBox = ref(null)
let shadowRoot = null

// 附件图片加载失败（如 COS 故障回退导致历史附件 503）→ 透明占位防反复请求 + toast 提示（防刷屏）
let cosToastShown = false
function bindAttachmentImgError(root) {
  const imgs = root ? root.querySelectorAll('img') : []
  for (const img of imgs) {
    const src = img.getAttribute('src') || ''
    if (!src.includes('/attachments/')) continue
    img.onerror = () => {
      img.onerror = null
      img.src = 'data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=='
      if (cosToastShown) return
      cosToastShown = true
      ElMessage.error(t('attCosDown'))
      setTimeout(() => { cosToastShown = false }, 3000)
    }
  }
}

function updateContent() {
  if (!shadowRoot) return;

  // 0. 白名单清洗邮件 HTML（纵深防御：Shadow DOM 不隔离脚本，事件属性等必须移除）
  const safeHtml = sanitizeHtml(props.html);

  // 1. 提取 <body> 的 style 属性（如果存在），并过滤危险 CSS
  const bodyStyleRegex = /<body[^>]*style="([^"]*)"[^>]*>/i;
  const bodyStyleMatch = props.html.match(bodyStyleRegex);
  const bodyStyle = bodyStyleMatch
    ? sanitizeCss(bodyStyleMatch[1]).replace(/[<>]/g, '')
    : '';

  // 2. 移除 <body> 标签（保留内容）
  const cleanedHtml = safeHtml.replace(/<\/?body[^>]*>/gi, '');

  // 3. 将 body 的 style 应用到 .shadow-content
  shadowRoot.innerHTML = `
    <style>
      :host {
        all: initial;
        width: 100%;
        height: 100%;
        font-family: Inter, 'Helvetica Neue', Helvetica, 'PingFang SC',
                    'Hiragino Sans GB', 'Microsoft YaHei', '微软雅黑', Arial, sans-serif;
        font-size: 14px;
        line-height: 1.5;
        color: #13181D;
        word-break: break-word;
      }

      h1, h2, h3, h4 {
          font-size: 18px;
          font-weight: 700;
      }

      p {
        margin: 0;
      }

      a {
        text-decoration: none;
        color: #0E70DF;
      }

      .shadow-content {
        background: #FFFFFF;
        width: fit-content;
        height: fit-content;
        min-width: 100%;
        ${bodyStyle ? bodyStyle : ''} /* 注入 body 的 style */
      }

      img:not(table img) {
        max-width: 100%;
        height: auto !important;
      }

    </style>
    <div class="shadow-content">
      ${cleanedHtml}
    </div>
  `;

  // 附件图片加载失败（COS 故障等）→ 透明占位 + toast 提示
  bindAttachmentImgError(shadowRoot);
}

function autoScale() {
  if (!shadowRoot || !contentBox.value) return

  const parent = contentBox.value
  const shadowContent = shadowRoot.querySelector('.shadow-content')

  if (!shadowContent) return

  const parentWidth = parent.offsetWidth
  const childWidth = shadowContent.scrollWidth

  if (childWidth === 0) return

  const scale = parentWidth / childWidth

  const hostElement = shadowRoot.host
  hostElement.style.zoom = scale
}

onMounted(() => {
  shadowRoot = container.value.attachShadow({ mode: 'open' })
  updateContent()
  autoScale()
})

watch(() => props.html, () => {
  updateContent()
  autoScale()
})
</script>

<style scoped>
.content-box {
  width: 100%;
  height: 100%;
  overflow: hidden;
  font-family: Inter, "Helvetica Neue", Helvetica, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", "微软雅黑", Arial, sans-serif;
}

.content-html {
  width: 100%;
  height: 100%;
}
</style>
