<template>
  <div class="pgp-read">
    <!-- 扩展不可用：安装/授权引导 -->
    <div v-if="phase === 'noext'" class="pgp-state">
      <div class="pgp-state-ic">
        <Icon icon="mdi:shield-lock-outline" width="44" height="44"/>
      </div>
      <div class="pgp-state-title">{{ t('pgpNoExtTitle') }}</div>
      <div class="pgp-state-desc">{{ t('pgpNoExtDesc') }}</div>
      <div class="pgp-state-ops">
        <el-button type="primary" plain size="small" @click="openStore('chrome')">
          <Icon icon="fa-brands:chrome" width="15" height="15"/> {{ t('pgpInstallChrome') }}
        </el-button>
        <el-button type="primary" plain size="small" @click="openStore('firefox')">
          <Icon icon="fa-brands:firefox" width="15" height="15"/> {{ t('pgpInstallFirefox') }}
        </el-button>
        <el-button size="small" @click="authorize">{{ t('pgpAuthorizeBtn') }}</el-button>
      </div>
      <div class="pgp-state-hint">{{ t('pgpAuthorizeHint') }}</div>
    </div>

    <!-- 扩展更新中：连接断开 -->
    <div v-else-if="disconnected" class="pgp-state">
      <div class="pgp-state-ic"><Icon icon="mdi:connection" width="44" height="44"/></div>
      <div class="pgp-state-title">{{ t('pgpDisconnected') }}</div>
      <div class="pgp-state-ops">
        <el-button type="primary" size="small" @click="reload">{{ t('refresh') }}</el-button>
      </div>
    </div>

    <!-- 解密中 -->
    <div v-else-if="phase === 'loading'" class="pgp-state">
      <div class="pgp-spinner"></div>
      <div class="pgp-state-title">{{ t('pgpDecrypting') }}</div>
    </div>

    <!-- 解密失败 -->
    <div v-else-if="phase === 'fail'" class="pgp-state">
      <div class="pgp-state-ic fail"><Icon icon="mdi:alert-octagon-outline" width="40" height="40"/></div>
      <div class="pgp-state-title">{{ t('pgpFailedTitle') }}</div>
      <div class="pgp-state-desc err">{{ errMsg }}</div>
      <div class="pgp-state-ops">
        <el-button type="primary" size="small" @click="retry">{{ t('pgpRetry') }}</el-button>
        <el-button v-if="keyringReady" size="small" @click="openKeys">{{ t('pgpKeyManager') }}</el-button>
      </div>
    </div>

    <!-- 公钥块：提供导入 -->
    <div v-else-if="phase === 'pubkey'" class="pgp-state">
      <div class="pgp-state-ic"><Icon icon="mdi:key-outline" width="44" height="44"/></div>
      <div class="pgp-state-title">{{ t('pgpPubKeyFound') }}</div>
      <div class="pgp-state-desc">{{ t('pgpPubKeyDesc') }}</div>
      <div class="pgp-state-ops">
        <el-button type="primary" size="small" :loading="importing" @click="importKey">{{ t('pgpImportKey') }}</el-button>
        <el-button v-if="keyringReady" size="small" @click="openKeys">{{ t('pgpKeyManager') }}</el-button>
      </div>
    </div>

    <!-- 解密结果 / 验签结果（Mailvelope iframe），容器始终在 DOM 供扩展注入 -->
    <div ref="displayBox" class="pgp-display" :class="{on: phase === 'ready'}"></div>
  </div>
</template>

<script setup>
import {ref, onMounted, onBeforeUnmount} from 'vue'
import {useI18n} from 'vue-i18n'
import {Icon} from '@iconify/vue'
import {
  MAILVELOPE_STORES,
  waitMailvelope,
  getOrCreateKeyring,
  openKeyringSettings,
  openMailvelopeAuthorize,
  pgpErrorHint,
} from '@/utils/pgp-utils.js'

const props = defineProps({
  armored: {type: String, default: ''},
  kind: {type: String, default: 'message'},
  senderAddress: {type: String, default: ''},
  keyringId: {type: String, default: ''},
})

const {t} = useI18n()
const phase = ref('loading')
const disconnected = ref(false)
const errMsg = ref('')
const keyringReady = ref(false)
const importing = ref(false)
const displayBox = ref(null)
let mvel = null
let keyring = null
let disposed = false

onMounted(() => {
  window.addEventListener('mailvelope-disconnect', onDisconnect)
  init()
})

onBeforeUnmount(() => {
  disposed = true
  window.removeEventListener('mailvelope-disconnect', onDisconnect)
  if (displayBox.value) displayBox.value.innerHTML = ''
})

function onDisconnect() {
  disconnected.value = true
}

function reload() {
  window.location.reload()
}

function openStore(key) {
  const store = MAILVELOPE_STORES[key]
  if (store) window.open(store.url, '_blank', 'noopener')
}

function authorize() {
  openMailvelopeAuthorize()
}

function openKeys() {
  if (mvel && keyring) {
    keyring.openSettings().catch(() => {})
  } else if (mvel) {
    openKeyringSettings(mvel, props.keyringId).catch(() => {})
  }
}

async function importKey() {
  if (!mvel || !keyring) return
  importing.value = true
  try {
    const status = await keyring.importPublicKey(props.armored)
    ElMessage({
      message: status === 'IMPORTED' ? t('pgpImportDone') : t('pgpImportExist'),
      type: status === 'IMPORTED' ? 'success' : 'info',
      plain: true,
    })
  } catch (e) {
    ElMessage({
      message: describeError(e),
      type: 'error',
      plain: true,
    })
  } finally {
    importing.value = false
  }
}

async function retry() {
  phase.value = 'loading'
  await init()
}

async function init() {
  if (disposed) return
  phase.value = 'loading'
  errMsg.value = ''
  keyringReady.value = false
  mvel = await waitMailvelope(1500)
  if (disposed) return
  if (!mvel) {
    phase.value = 'noext'
    return
  }
  try {
    keyring = await getOrCreateKeyring(mvel, props.keyringId)
  } catch (e) {
    phase.value = 'fail'
    errMsg.value = describeError(e)
    return
  }
  keyringReady.value = true

  // 公钥块：提供导入面板；其余类型（私钥/纯签名等）不在正文内嵌处理
  if (props.kind === 'pubkey') {
    phase.value = 'pubkey'
    return
  }
  if (props.kind !== 'message' && props.kind !== 'signed-message') {
    phase.value = 'fail'
    errMsg.value = t('pgpErrType')
    return
  }

  if (!props.armored) {
    phase.value = 'fail'
    errMsg.value = t('pgpErrParse')
    return
  }

  if (displayBox.value) displayBox.value.innerHTML = ''
  try {
    // message / signed-message：Mailvelope 在容器 iframe 内解密并显示签名状态
    const options = {}
    if (props.senderAddress) options.senderAddress = props.senderAddress
    await mvel.createDisplayContainer(displayBox.value, props.armored, keyring, options)
    if (disposed) return
    phase.value = 'ready'
  } catch (e) {
    if (disposed) return
    phase.value = 'fail'
    errMsg.value = describeError(e)
  }
}

function describeError(e) {
  const code = e && (e.code || e.name)
  const prefix = code ? t(pgpErrorHint(code)) : t('pgpErrGeneric')
  const detail = e && e.message ? String(e.message).slice(0, 300) : ''
  return detail ? `${prefix}（${detail}）` : prefix
}
</script>

<style scoped lang="scss">
.pgp-read {
  width: 100%;
}

.pgp-display {
  width: 100%;
  overflow: hidden;

  &.on {
    min-height: 180px;
  }
}

.pgp-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
  padding: 28px 16px;
  text-align: center;

  .pgp-state-ic {
    color: var(--el-color-primary);
    &.fail {
      color: var(--el-color-danger);
    }
  }

  .pgp-state-title {
    font-size: 15px;
    font-weight: 600;
    color: var(--el-text-color-primary);
  }

  .pgp-state-desc {
    font-size: 13px;
    color: var(--el-text-color-secondary);
    max-width: 520px;
    word-break: break-word;
    line-height: 1.7;

    &.err {
      color: var(--el-color-danger);
      font-size: 12px;
      max-width: 640px;
    }
  }

  .pgp-state-ops {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    justify-content: center;
    align-items: center;
  }

  .pgp-state-hint {
    font-size: 12px;
    color: var(--el-text-color-placeholder);
  }
}

.pgp-spinner {
  width: 28px;
  height: 28px;
  border: 3px solid var(--el-border-color);
  border-top-color: var(--el-color-primary);
  border-radius: 50%;
  animation: pgp-spin 0.8s linear infinite;
}

@keyframes pgp-spin {
  to {
    transform: rotate(360deg);
  }
}
</style>
