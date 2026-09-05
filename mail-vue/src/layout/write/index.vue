<template>
  <div class="send" v-show="show">
    <div class="write-box">
      <div class="title">
        <div class="title-left">
          <span class="title-text">
            <Icon icon="hugeicons:quill-write-01" width="28" height="28"/>
          </span>
          <span class="sender">{{ $t('sender') }}:</span>
          <span class="sender-name">{{ form.name }}</span>
          <span class="send-email"><{{ form.sendEmail }}></span>
        </div>
        <div @click="close" style="cursor: pointer;">
          <Icon icon="material-symbols-light:close-rounded" width="22" height="22"/>
        </div>
      </div>
      <div class="container">
        <el-input-tag  @add-tag="addTagChange" tag-type="primary" @input="inputChange" size="default" v-model="form.receiveEmail" >
          <template #prefix>
            <div class="item-title" >{{ $t('recipient') }}</div>
            <el-select
                ref="mySelect"
                class="write-select"
                popper-class="write-select"
                :show-arrow="false"
                :no-match-text="' '"
                :no-data-text="' '"
                @visible-change="selectStatusChange"
                @change="selectChange"
            >
              <el-option
                  v-for="item in selectRecipientList"
                  :key="item"
                  :label="item"
                  :value="item"
                  style="color: #999896;"
              />
            </el-select>
          </template>
          <template #suffix>
            <div style="display: flex;margin-right: 3px;">
              <Icon icon="fa7-solid:user-plus" width="20" height="20" class="add-contact" @click.stop="openContacts" />
            </div>
          </template>
        </el-input-tag>
        <el-input v-model="form.subject" :placeholder="t('subject')">
          <template #suffix>
            <span class="pgp-lock" :class="{'pgp-on': pgpOn}" :title="pgpOn ? t('pgpExit') : t('pgpEnter')" @click.stop="togglePgp">
              <Icon :icon="pgpOn ? 'material-symbols:enhanced-encryption' : 'mdi:shield-lock-outline'" width="18" height="18"/>
            </span>
          </template>
        </el-input>
        <div class="editor-area">
          <div v-if="pgpReplyHintVisible" class="pgp-reply-hint">
            <Icon icon="mdi:shield-key-outline" width="15" height="15"/>
            <span>{{ t('pgpReplyHint') }}</span>
          </div>
          <div v-if="pgpOn" class="pgp-toolbar">
            <span class="pgp-toolbar-hint">
              <Icon icon="material-symbols:enhanced-encryption-rounded" width="16" height="16"/>
              <span>{{ t('pgpEditingMode') }}</span>
            </span>
            <span v-if="form.attachments.length" class="pgp-toolbar-warn">
              <Icon icon="mdi:attachment-off" width="15" height="15"/>
              <span>{{ t('pgpNoAttachment') }}</span>
            </span>
            <span class="pgp-toolbar-link" @click="openPgpKeys">{{ t('pgpKeyManager') }}</span>
            <span class="pgp-toolbar-link exit" @click="togglePgp">{{ t('pgpExit') }}</span>
          </div>
          <div class="editor-flex">
            <tinyEditor v-show="!pgpOn" :def-value="defValue" ref="editor" @change="change" @focus="focusChange" />
            <div v-show="pgpOn" ref="pgpBox" class="pgp-box"></div>
          </div>
        </div>
        <div class="button-item">
          <div v-if="!pgpOn" class="att-add" @click="chooseFile">
            <Icon icon="iconamoon:attachment-fill" width="24" height="24"/>
          </div>
          <div v-if="!pgpOn" class="att-clear" @click="clearContent">
            <Icon icon="icon-park-outline:clear-format" width="24" height="24 "/>
          </div>
          <div class="att-list">
            <div class="att-item" v-for="(item,index) in form.attachments" :key="index">
              <Icon v-bind="getIconByName(item.filename)"/>
              <span class="att-filename">{{ item.filename }}</span>
              <span class="att-size">{{ formatBytes(item.size) }}</span>
              <Icon style="cursor: pointer;" icon="material-symbols-light:close-rounded" @click="delAtt(index)"
                    width="22" height="22"/>
            </div>
          </div>
          <div>
            <el-button type="primary" @click="sendEmail" v-if="form.sendType === 'reply'">{{ $t('reply') }}</el-button>
            <el-button type="primary" @click="sendEmail" v-else-if="form.sendType === 'forward'">{{ $t('forward') }}</el-button>
            <el-button type="primary" @click="sendEmail" v-else>{{ $t('send') }}</el-button>
          </div>
        </div>
      </div>
    </div>
    <el-dialog top="10vh" v-model="showContacts" @closed="clearSelectContact" :title="t('recentContacts')">
      <el-table ref="contactsTabRef" row-key="email" :data="contacts" style="height: 445px">
        <el-table-column type="selection" width="32" />
        <el-table-column property="email" :label="t('emailAccount')" >
          <template #default="props">
            <div class="email-row">{{ props.row.email }}</div>
          </template>
        </el-table-column>
        <el-table-column width="55" label="" >
          <template #default>
            <div style="display: flex;">
              <Icon icon="mage:user" style="color: var(--el-text-color-primary)" width="22" height="22" color="#606266" />
            </div>
          </template>
        </el-table-column>
      </el-table>
      <div class="contacts-bottom">
        <el-button type="default" @click="deleteContact">{{t('clear')}}</el-button>
        <el-button type="primary" @click="chooseContact">{{t('selectContacts')}}</el-button>
      </div>
    </el-dialog>
  </div>
</template>
<script setup>
import tinyEditor from '@/components/tiny-editor/index.vue'
import {h, nextTick, onMounted, onUnmounted, reactive, ref, toRaw, computed} from "vue";
import {Icon} from "@iconify/vue";
import {useUserStore} from "@/store/user.js";
import {emailSend} from "@/request/email.js";
import {isEmail} from "@/utils/verify-utils.js";
import {useAccountStore} from "@/store/account.js";
import {useEmailStore} from "@/store/email.js";
import {fileToBase64, formatBytes} from "@/utils/file-utils.js";
import {getIconByName} from "@/utils/icon-utils.js";
import sendPercent from "@/components/send-percent/index.vue"
import {toOssDomain} from "@/utils/convert.js";
import {formatDetailDate} from "@/utils/day.js";
import {sanitizeHtml} from "@/utils/sanitize-html.js";
import {useSettingStore} from "@/store/setting.js";
import {userDraftStore} from "@/store/draft.js";
import {useWriterStore} from "@/store/writer.js";
import db from "@/db/db.js";
import dayjs from "dayjs";
import {useI18n} from "vue-i18n";
import router from "@/router/index.js";
import {ElMessageBox} from "element-plus";
import {
  MAILVELOPE_STORES,
  waitMailvelope,
  getOrCreateKeyring,
  armorToHtml,
  htmlToPlain,
  extractArmor,
  pgpErrorHint,
  openMailvelopeAuthorize,
} from "@/utils/pgp-utils.js";

defineExpose({
  open,
  openReply,
  openForward,
  openDraft
})

const {t} = useI18n()
const writerStore = useWriterStore();
const draftStore = userDraftStore()
const settingStore = useSettingStore()
const emailStore = useEmailStore();
const accountStore = useAccountStore()
const editor = ref({})
const userStore = useUserStore();
const show = ref(false);
const percent = ref(0)
let percentMessage = null
let sending = false
// 附件发送上限：Resend 整封邮件 40MB（base64 后）的稳妥原始文件上限
const MAX_ATT_SIZE = 28 * 1024 * 1024 // 28MB
const defValue = ref('')
const contactsTabRef = ref({})
const showContacts = ref(false)
const mySelect = ref()
let selectStatus = false
const backReply = reactive({
  receiveEmail: [],
  subject: '',
  content: '',
  sendType: ''
})
const form = reactive({
  sendEmail: '',
  receiveEmail: [],
  accountId: -1,
  name: '',
  subject: '',
  content: '',
  sendType: '',
  text: '',
  emailId: 0,
  attachments: [],
  draftId: null,
})

// ---------- Mailvelope PGP 加密写信 ----------
const pgpOn = ref(false)          // 是否处于 PGP 加密编辑模式
const pgpBusy = ref(false)        // 进入/退出切换中
const pgpReady = ref(false)       // Mailvelope 编辑器容器已挂载
const pgpKeyring = ref(null)
const pgpEditor = ref(null)       // createEditorContainer 返回的编辑器句柄
const pgpSign = ref(true)         // 默认加密并签名
const pgpReplyArmor = ref('')     // 回复 PGP 加密原邮件时：原密文（做引用）
const pgpReplyHeader = ref('')    // 引用头
const pgpBox = ref(null)

const pgpReplyHintVisible = computed(() => !!pgpReplyArmor.value && !pgpOn.value)

const selectRecipientList = ref([])

const contacts = computed(() => writerStore.sendRecipientRecord.map(item => ({email: item})))

function openContacts() {
  showContacts.value = true
  nextTick(() => {
    form.receiveEmail.forEach(item => {
      if (writerStore.sendRecipientRecord.includes(item)) {
        contactsTabRef.value.toggleRowSelection({email: item});
      }
    })
  })
}

function deleteContact() {
  ElMessageBox.confirm(t('confirmDeletionOfContacts'), {
    confirmButtonText: t('confirm'),
    cancelButtonText: t('cancel'),
    type: 'warning'
  }).then(() => {
    const contactList = contactsTabRef.value.getSelectionRows().map(item => item.email);
    form.receiveEmail = form.receiveEmail.filter(item => !contactList.includes(item));
    writerStore.sendRecipientRecord = writerStore.sendRecipientRecord.filter(item => !contactList.includes(item));
  })
}

function chooseContact() {

  const contactList = contactsTabRef.value.getSelectionRows().map(item => item.email);
  contactList.forEach(item => {
    if (!form.receiveEmail.includes(item)) {
      form.receiveEmail.push(item);
    }
  })

  form.receiveEmail = form.receiveEmail.filter(item => {
    return contactList.includes(item) || !writerStore.sendRecipientRecord.includes(item);
  });

  showContacts.value = false
}

function clearSelectContact() {
  contactsTabRef.value.clearSelection();
}

function selectChange(value) {
  form.receiveEmail.push(value)
}

function selectStatusChange(status) {
  selectStatus = status
}

const openSelect = () => {
  mySelect.value.toggleMenu()
}

function inputChange(value) {

  selectRecipientList.value = writerStore.sendRecipientRecord.filter(item => value && !form.receiveEmail.includes(item) && item.startsWith(value)).slice(0, 10);

  if (!selectStatus && selectRecipientList.value.length > 0) {
    openSelect()
  }

  if (selectStatus && selectRecipientList.value.length === 0) {
    openSelect()
  }

}

function addTagChange(val) {

  const emails = Array.from(new Set(
      val.split(/[,，]/).map(item => item.trim()).filter(item => item)
  ));

  form.receiveEmail.splice(form.receiveEmail.length - 1, 1)

  let has = false
  emails.forEach(email => {
    if (isEmail(email) && !form.receiveEmail.includes(email)) {
      form.receiveEmail.push(email)
      has = true
    }
  })
  if (selectStatus && has) openSelect()
}

function clearContent() {
  ElMessageBox.confirm(t('clearContentConfirm'), {
    confirmButtonText: t('confirm'),
    cancelButtonText: t('cancel'),
    type: 'warning'
  }).then(() => {
    resetForm()
  })

}

function delAtt(index) {
  form.attachments.splice(index, 1);
}

function chooseFile() {
  if (pgpOn.value) {
    ElMessage({message: t('pgpNoAttachment'), type: 'warning', plain: true})
    return
  }
  const doc = document.createElement("input")
  doc.setAttribute("type", "file")
  doc.multiple = true;
  doc.click()
  doc.onchange = async (e) => {

    const fileList = e.target.files;

    for (const file of fileList) {

      const size = file.size
      const filename = file.name
      const contentType = file.type

      // 附件超过 28MB（Resend 40MB base64 后的稳妥上限）无法发送，直接提示并跳过
      if (size > MAX_ATT_SIZE) {
        ElMessage({
          message: t('attTooLargeMsg', { name: filename, size: '28MB' }),
          type: 'warning',
          plain: true,
        })
        continue
      }

      const content = await fileToBase64(file)
      form.attachments.push({content, filename, size, contentType})

    }

  }
}

async function sendEmail() {
  if (pgpOn.value) {
    pgpEncryptSend()
    return
  }

  // 兜底检查：防止草稿恢复等绕过选择时的校验（单个附件超 28MB 直接拦截）
  const overSizedAtt = form.attachments.find(att => att.size > MAX_ATT_SIZE)
  if (overSizedAtt) {
    ElMessage({
      message: t('attTooLargeMsg', { name: overSizedAtt.filename, size: '28MB' }),
      type: 'warning',
      plain: true,
    })
    return
  }

  if (form.receiveEmail.length === 0) {
    ElMessage({
      message: t('emptyRecipientMsg'),
      type: 'error',
      plain: true,
    })
    return
  }

  if (!form.subject) {
    ElMessage({
      message: t('emptySubjectMsg'),
      type: 'error',
      plain: true,
    })
    return
  }

  if (!form.content) {
    form.content = editor.value.getContent();
  }

  if (!form.content) {
    ElMessage({
      message: t('emptyContentMsg'),
      type: 'error',
      plain: true,
    })
    return
  }

  if (form.manyType === 'divide' && form.attachments.length > 0) {
    ElMessage({
      message: t('noSeparateSendMsg'),
      type: 'error',
      plain: true,
    })
    return
  }

  if (sending) {
    ElMessage({
      message: t('sendingErrorMsg'),
      type: 'error',
      plain: true,
    })
    return
  }

  fireEmailSend()
}

async function fireEmailSend() {
  percentMessage = ElMessage({
    message: () => h(sendPercent, {value: percent.value, desc: t('sending')}),
    dangerouslyUseHTMLString: true,
    plain: true,
    duration: 0,
    customClass: 'message-bottom'
  })

  sending = true

  show.value = false

  emailSend(form, (e) => {
    percent.value = Math.round((e.loaded * 98) / e.total)
  }).then(emailList => {
    const email = emailList[0]
    emailList.forEach(item => {
      emailStore.sendScroll?.addItem(item)
    })

    ElNotification({
      title: t('sendSuccessMsg'),
      type: "success",
      message: h('span', {style: 'color: teal'}, email.subject),
      position: 'bottom-right'
    })

    userStore.refreshUserInfo();

    addRecipientRecord();

    if (form.draftId) {
      form.subject = ''
      form.content = ''
      form.receiveEmail = []
      draftStore.setDraft = {...toRaw(form)}
    }

    show.value = false
    resetForm();
  }).catch((e) => {
    ElNotification({
      title: t('sendFailMsg'),
      type: e.code === 403 ? 'warning' : 'error',
      message: h('span', {style: 'color: teal'}, e.message),
      position: 'bottom-right'
    })
    if (e.code === 401) {
      localStorage.removeItem('token');
      router.replace('/login');
    }
    show.value = true
    addRecipientRecord();
  }).finally(() => {
    percentMessage.close()
    percent.value = 0
    sending = false
  })
}

// ---- Mailvelope PGP 支持 ----

function showPgpInstallDialog() {
  ElMessageBox({
    title: t('pgpUnavailableTitle'),
    message: h('div', {class: 'pgp-install-dialog'}, [
      h('p', {class: 'pgp-install-desc'}, t('pgpUnavailableDesc')),
      h('div', {class: 'pgp-install-links'}, [
        h('a', {href: MAILVELOPE_STORES.chrome.url, target: '_blank', rel: 'noopener'}, t('pgpInstallChrome')),
        h('span', {class: 'pgp-install-sep'}, ' · '),
        h('a', {href: MAILVELOPE_STORES.firefox.url, target: '_blank', rel: 'noopener'}, t('pgpInstallFirefox')),
      ]),
      h('div', {class: 'pgp-install-auth', onClick: () => openMailvelopeAuthorize()}, t('pgpAuthorizeBtn')),
    ]),
    showCancelButton: false,
    confirmButtonText: t('pgpGotIt'),
  })
}

function pgpReport(e) {
  const code = e && (e.code || e.name)
  const base = code ? t(pgpErrorHint(code)) : t('pgpErrGeneric')
  const detail = e && e.message ? String(e.message).slice(0, 200) : ''
  ElMessage({
    message: detail ? `${base}：${detail}` : base,
    type: 'error',
    plain: true,
  })
  if (code === 'NO_KEY_FOR_ADDRESS' || code === 'NO_KEY_FOUND') {
    openPgpKeys().catch(() => {})
  }
}

async function togglePgp() {
  if (pgpOn.value) {
    pgpExit()
    return
  }
  await pgpEnter()
}

async function pgpEnter() {
  if (pgpBusy.value || pgpOn.value) return
  if (!form.sendEmail) {
    ElMessage({message: t('pgpErrAccount'), type: 'warning', plain: true})
    return
  }
  pgpBusy.value = true
  try {
    const mvel = await waitMailvelope(1200)
    if (!mvel) {
      showPgpInstallDialog()
      return
    }
    const keyring = await getOrCreateKeyring(mvel, form.sendEmail)
    pgpKeyring.value = keyring

    const opts = {quota: 20 * 1024, signMsg: pgpSign.value}
    // 把 TinyMCE 里已输入的内容带进 Mailvelope 编辑器（明文，HTML 转纯文本）
    let plain = ''
    try {
      if (editor.value && typeof editor.value.getContent === 'function') {
        plain = htmlToPlain(editor.value.getContent())
      }
    } catch (e) {
      plain = ''
    }
    if (!plain && form.text && !/^-{5}BEGIN PGP/.test(form.text)) plain = form.text
    if (!plain && defValue.value) plain = htmlToPlain(defValue.value)
    if (plain) opts.predefinedText = plain
    if (pgpReplyArmor.value) {
      opts.quotedMail = pgpReplyArmor.value
      if (pgpReplyHeader.value) opts.quotedMailHeader = pgpReplyHeader.value
    }

    pgpOn.value = true
    await nextTick()
    if (pgpBox.value) pgpBox.value.innerHTML = ''
    const editorObj = await mvel.createEditorContainer(pgpBox.value, keyring, opts)
    pgpEditor.value = editorObj
    pgpReady.value = true
    pgpReplyArmor.value = ''
    pgpReplyHeader.value = ''
  } catch (e) {
    pgpOn.value = false
    pgpReport(e)
  } finally {
    pgpBusy.value = false
  }
}

function pgpExit() {
  if (!pgpOn.value) return
  ElMessageBox.confirm(t('pgpExitConfirm'), {
    confirmButtonText: t('confirm'),
    cancelButtonText: t('cancel'),
    type: 'warning',
  }).then(() => {
    teardownPgp()
  }).catch(() => {
  })
}

function teardownPgp() {
  pgpOn.value = false
  pgpBusy.value = false
  pgpReady.value = false
  pgpEditor.value = null
  pgpReplyArmor.value = ''
  pgpReplyHeader.value = ''
  if (pgpBox.value) pgpBox.value.innerHTML = ''
}

async function openPgpKeys() {
  const mvel = await waitMailvelope(1200)
  if (!mvel) {
    showPgpInstallDialog()
    return
  }
  try {
    const id = form.sendEmail || userStore.user.email || ''
    const keyring = await getOrCreateKeyring(mvel, id)
    await keyring.openSettings()
  } catch (e) {
    pgpReport(e)
  }
}

async function pgpEncryptSend() {
  if (pgpBusy.value || sending) {
    ElMessage({message: t('sendingErrorMsg'), type: 'error', plain: true})
    return
  }
  if (form.receiveEmail.length === 0) {
    ElMessage({message: t('emptyRecipientMsg'), type: 'error', plain: true})
    return
  }
  if (!form.subject) {
    ElMessage({message: t('emptySubjectMsg'), type: 'error', plain: true})
    return
  }
  if (form.attachments.length > 0) {
    ElMessage({message: t('pgpNoAttachment'), type: 'warning', plain: true})
    return
  }
  if (!pgpReady.value || !pgpEditor.value) {
    ElMessage({message: t('pgpLoading'), type: 'warning', plain: true})
    return
  }

  pgpBusy.value = true
  percentMessage = ElMessage({
    message: () => h(sendPercent, {value: percent.value, desc: t('pgpEncrypting')}),
    dangerouslyUseHTMLString: true,
    plain: true,
    duration: 0,
    customClass: 'message-bottom'
  })

  try {
    const recipients = form.receiveEmail.filter(item => isEmail(item))
    if (recipients.length === 0) {
      ElMessage({message: t('emptyRecipientMsg'), type: 'error', plain: true})
      return
    }
    const armored = await pgpEditor.value.encrypt(recipients)
    // 密文以内嵌 armor 文本块发送（content 与 text 双份，兼容无扩展收件方）
    form.content = armorToHtml(armored, escapeHtml)
    form.text = armored
  } catch (e) {
    pgpReport(e)
    return
  } finally {
    pgpBusy.value = false
    percentMessage.close()
    percent.value = 0
  }

  await fireEmailSend()
}

function addRecipientRecord() {
  writerStore.sendRecipientRecord = writerStore.sendRecipientRecord.filter(
      email => !form.receiveEmail.includes(email)
  );

  writerStore.sendRecipientRecord.unshift(...form.receiveEmail);
  writerStore.sendRecipientRecord = writerStore.sendRecipientRecord.slice(0, 500);
}

function resetForm() {
  form.receiveEmail = []
  form.subject = ''
  form.content = ''
  form.manyType = null
  form.attachments = []
  form.sendType = ''
  form.emailId = 0
  form.draftId = null
  backReply.content = ''
  backReply.subject = ''
  backReply.receiveEmail = []
  backReply.sendType = ''
  editor.value.clearEditor()
  teardownPgp()
}

function change(content, text) {
  form.content = content;
  form.text = text
}

function focusChange() {
  if (selectStatus) openSelect()
}

function openForward(email) {
  resetForm();

  email.subject = email.subject || ''

  form.subject = email.subject
  form.sendType = 'forward'

  defValue.value = ''

  setTimeout(() => {
    defValue.value = `
      ${sanitizeHtml(formatImage(email.content)) || `<pre style="font-family: inherit;word-break: break-word;white-space: pre-wrap;margin: 0">${escapeHtml(email.text)}</pre>`}
    `
    open()

    nextTick(() => {
      backReply.content = editor.value.getContent()
      backReply.subject = form.subject
      backReply.receiveEmail = form.receiveEmail
      backReply.sendType = form.sendType
    })

  });
}

function openReply(email) {

  resetForm();

  email.subject = email.subject || ''

  form.receiveEmail.push(email.sendEmail)
  form.subject = (
      email.subject.startsWith('Re:') ||
      email.subject.startsWith('Re：') ||
      email.subject.startsWith('回复：') ||
      email.subject.startsWith('回复:')) ? email.subject : 'Re: ' + email.subject
  form.sendType = 'reply'
  form.emailId = email.emailId

  defValue.value = ''

  // 原邮件是 PGP 加密邮件：切到 Mailvelope 加密回复，由扩展在本机解密原密文并作引用
  const origArmor = extractArmor(email.content) || extractArmor(email.text)
  if (origArmor && (origArmor.kind === 'message' || origArmor.kind === 'signed-message')) {
    pgpReplyArmor.value = origArmor.armored
    pgpReplyHeader.value = `${formatDetailDate(email.createTime)} ${email.name} &lt;${email.sendEmail}&gt; ${t('wrote')}:`
    open()
    waitMailvelope(800).then(m => {
      if (m && !pgpOn.value) pgpEnter()
    }).catch(() => {
    })
    return
  }

  setTimeout(() => {
    defValue.value = `
    <div></div>
    <div>
    <br>
        ${formatDetailDate(email.createTime)} ${escapeHtml(email.name)} &lt${escapeHtml(email.sendEmail)}&gt ${t('wrote')}:
    </div>
    <blockquote class="mceNonEditable" style="margin: 0 0 0 0.8ex;border-left: 1px solid rgb(204,204,204);padding-left: 1ex;">
      <articl>
          ${sanitizeHtml(formatImage(email.content)) || `<pre style="font-family: inherit;word-break: break-word;white-space: pre-wrap;margin: 0">${escapeHtml(email.text)}</pre>`}
      </article>
    </blockquote>`
    open()

    nextTick(() => {
      backReply.content = editor.value.getContent()
      backReply.subject = form.subject
      backReply.receiveEmail = form.receiveEmail
      backReply.sendType = form.sendType
    })
  })

}

function formatImage(content) {
  content = content || '';
  const domain = settingStore.settings.r2Domain;
  return content.replace(/{{domain}}/g, toOssDomain(domain) + '/');
}

// 纯文本/发件人信息注入 HTML 前的转义（防 text 内容中的标签执行）
function escapeHtml(str) {
  return String(str ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
}

function open() {
  if (!accountStore.currentAccount.email) {
    form.sendEmail = userStore.user.email;
    form.accountId = userStore.user.account.accountId;
    form.name = userStore.user.name;
  } else {
    form.sendEmail = accountStore.currentAccount.email;
    form.accountId = accountStore.currentAccount.accountId;
    form.name = accountStore.currentAccount.name;
  }

  // 新建邮件（非回复/转发/草稿）时自动插入个人设置里的 HTML 签名
  if (!form.sendType) {
    defValue.value = ''
    if (userStore.user.htmlSignature) {
      setTimeout(() => {
        defValue.value = userStore.user.htmlSignature
      })
    }
  }

  show.value = true;
  editor.value.focus()
}

function openDraft(draft) {
  Object.assign(form, {...draft})
  defValue.value = ''
  setTimeout(() => defValue.value = form.content)
  show.value = true;
  editor.value.focus()
}

const handleKeyDown = (event) => {
  if (event.key === 'Escape') {
    close()
  }
};

onMounted(() => {
  window.addEventListener('keydown', handleKeyDown);
});

onUnmounted(() => {
  window.removeEventListener('keydown', handleKeyDown);
});

function close() {
  // PGP 编辑模式先退出（Mailvelope 编辑器内容无法在退出后保留）
  if (pgpOn.value) {
    ElMessageBox.confirm(t('pgpExitConfirm'), {
      confirmButtonText: t('confirm'),
      cancelButtonText: t('cancel'),
      type: 'warning',
    }).then(() => {
      teardownPgp()
      closeInner()
    }).catch(() => {
    })
    return
  }
  closeInner()
}

function closeInner() {

  if (selectStatus) openSelect();

  if (!form.content) {
    form.content = editor.value.getContent();
  }

  if (form.draftId) {
    draftStore.setDraft = {...toRaw(form)}
    show.value = false
    resetForm()
    return;
  }

  if (!(form.content || form.subject || form.receiveEmail.length > 0)) {
    show.value = false
    resetForm()
    return;
  }

  if (backReply.sendType === 'reply' || backReply.sendType === 'forward') {
    let subjectFlag = form.subject === backReply.subject
    let contentFlag = editor.value.getContent() === backReply.content
    let receiveFlag = form.receiveEmail.length === 1 && form.receiveEmail[0] === backReply.receiveEmail[0]
    if (backReply.sendType === 'forward' && form.receiveEmail.length === 0) {
      receiveFlag = true;
    }
    if (subjectFlag && contentFlag && receiveFlag) {
      resetForm();
      close()
      return;
    }
  }

  ElMessageBox.confirm(t('saveDraftConfirm'), {
    confirmButtonText: t('confirm'),
    cancelButtonText: t('cancel'),
    type: 'warning',
    distinguishCancelAndClose: true
  }).then(async () => {
    const formData = {...toRaw(form)};
    delete formData.draftId
    delete formData.attachments
    formData.createTime = dayjs().utc().format('YYYY-MM-DD HH:mm:ss');
    const draftId = await db.value.draft.add({...formData})
    db.value.att.add({draftId, attachments: toRaw(form.attachments)})
    draftStore.refreshList++
    show.value = false
    await nextTick(() => {
      resetForm()
    })
  }).catch((action) => {
    if (action === 'cancel') {
      show.value = false
      resetForm()
    }
  })

}

</script>
<style>
.write-select .el-select-dropdown__list {
  padding: 4px 4px !important;
}
.write-select .el-select-dropdown__item {
  padding: 0 10px 0 10px;
}

.write-select .el-select-dropdown {
  min-width: 0 !important;
}

.pgp-install-dialog {
  text-align: center;
  padding: 4px 2px;

  .pgp-install-desc {
    font-size: 13px;
    line-height: 1.8;
    color: var(--el-text-color-regular);
    margin: 0 0 14px;
  }

  .pgp-install-links {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 12px;

    a {
      color: var(--el-color-primary);
      font-weight: 600;
      text-decoration: none;

      &:hover {
        text-decoration: underline;
      }
    }

    .pgp-install-sep {
      color: var(--el-text-color-placeholder);
    }
  }

  .pgp-install-auth {
    margin-top: 16px;
    padding: 9px 10px;
    border: 1px dashed var(--el-color-primary-light-5);
    border-radius: 8px;
    color: var(--el-color-primary);
    font-size: 13px;
    cursor: pointer;

    &:hover {
      background: var(--el-color-primary-light-9);
    }
  }
}
</style>
<style scoped lang="scss">
.send {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;

  .write-box {
    background: var(--el-bg-color);
    width: min(1367px, calc(100% - 80px));
    box-shadow: var(--el-box-shadow-light);
    border: 1px solid var(--el-border-color-light);
    transition: var(--el-transition-duration);
    padding: 15px;
    border-radius: 8px;
    display: grid;
    grid-template-rows: auto 1fr;
    overflow: hidden;
    @media (max-width: 1024px) {
      width: 100%;
      height: 100%;
      border-radius: 0;
      border: 0;
      padding-top: 10px;
    }

    @media (min-width: 1025px) {
      height: min(800px, calc(100vh - 60px));
    }

    .title {
      display: flex;
      justify-content: space-between;
      margin-bottom: 10px;

      .title-left {
        align-items: center;
        display: grid;
        grid-template-columns: auto auto auto 1fr;
      }

      .title-text {
      }

      .sender {
        margin-left: 8px;
      }

      .sender-name {
        margin-left: 8px;
        font-weight: bold;
      }

      .send-email {
        color: #999896;
        margin-left: 5px;
        white-space: nowrap;
        text-overflow: ellipsis;
        overflow: hidden;
      }


      div {
        display: flex;
        align-items: center;
      }
    }

    .container {
      height: 100%;
      display: grid;
      grid-template-rows: auto auto 1fr auto;
      gap: 15px;

      .item-title {
      }

      .button-item {
        display: grid;
        grid-template-columns: auto auto 1fr auto;

        .att-add {
          cursor: pointer;
        }

        .att-clear {
          cursor: pointer;
          margin-left: 10px;
        }

        .att-list {
          display: grid;
          gap: 5px;
          grid-template-columns: repeat(auto-fill, minmax(230px, 1fr));
          padding-left: 10px;
          padding-right: 10px;
          max-height: 110px;
          overflow-y: auto;
          @media (max-width: 450px) {
            grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
          }

          .att-item {
            display: grid;
            grid-template-columns: auto 1fr auto auto;
            gap: 5px;
            height: 32px;
            font-size: 14px;
            padding: 4px 5px;
            background: var(--light-ill);
            border-radius: 4px;
            .att-filename {
              white-space: nowrap;
              text-overflow: ellipsis;
              overflow: hidden;
            }
          }
        }
      }
    }
  }

}

.email-row {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

:deep(.el-dialog) {
  width: 420px !important;
  @media (max-width: 460px) {
    width: calc(100% - 40px) !important;
    margin-right: 20px !important;
    margin-left: 20px !important;
  }
}

.contacts-bottom {
  display: flex;
  justify-content: end;
  margin-top: 10px;
}

.add-contact {
  color: var(--regular-text-color)
}

.write-select {
  position: absolute;
  width: 300px;
  left: 60px;
  z-index: 0;
  opacity: 0;
  pointer-events: none;
}

:deep(.el-input-tag__suffix) {
  padding-right: 4px;
}

.icon {
  cursor: pointer;
}

.pgp-lock {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 24px;
  border-radius: 5px;
  cursor: pointer;
  color: var(--regular-text-color);
  transition: color .15s, background .15s;

  &:hover {
    background: var(--el-fill-color-light);
  }

  &.pgp-on {
    color: var(--el-color-primary);
    background: var(--el-color-primary-light-9);
  }
}

.editor-area {
  height: 100%;
  min-height: 0;
  display: flex;
  flex-direction: column;
  gap: 6px;

  .pgp-reply-hint {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--el-color-warning);
    background: var(--el-color-warning-light-9);
    border: 1px dashed var(--el-color-warning-light-5);
    border-radius: 6px;
    padding: 5px 10px;
  }

  .pgp-toolbar {
    display: flex;
    align-items: center;
    gap: 14px;
    flex-wrap: wrap;
    padding: 4px 10px;
    border: 1px solid var(--el-color-primary-light-7);
    border-radius: 6px;
    background: var(--el-color-primary-light-9);
    font-size: 13px;
    color: var(--el-color-primary);

    .pgp-toolbar-hint {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-weight: 600;
    }

    .pgp-toolbar-warn {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      color: var(--el-color-warning);
      font-size: 12px;
    }

    .pgp-toolbar-link {
      cursor: pointer;
      color: var(--el-color-primary);
      margin-left: auto;

      &.exit {
        color: var(--el-color-danger);
      }

      &:hover {
        text-decoration: underline;
      }
    }
  }

  .editor-flex {
    flex: 1;
    min-height: 0;
    position: relative;
  }

  :deep(.editor-box) {
    height: 100%;
  }

  .pgp-box {
    width: 100%;
    height: 100%;
    overflow: hidden;
    background: var(--el-bg-color);
    border: 1px solid var(--el-border-color-light);
    border-radius: 4px;
  }
}
</style>
