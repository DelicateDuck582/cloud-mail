<template>
  <div class="box">
    <div class="att-manage">
      <div class="toolbar">
        <el-tabs v-model="activeTab" class="att-tabs" @tab-change="tabChange">
          <el-tab-pane :label="$t('attAll')" name="0" />
          <el-tab-pane :label="$t('attTrash')" name="1" />
        </el-tabs>
        <el-select
            v-if="canViewAll"
            v-model="params.userId"
            :placeholder="$t('selectUser')"
            clearable
            filterable
            class="user-select"
            @change="search"
        >
          <el-option v-for="u in userListData" :key="u.userId" :label="u.email" :value="u.userId" />
        </el-select>
        <el-input
            v-model="params.keyword"
            :placeholder="$t('attKeyword')"
            class="search-input"
            clearable
            @keyup.enter="search"
            @clear="search"
        />
        <el-button type="primary" @click="search">{{ $t('search') }}</el-button>
        <el-button type="primary" @click="search">{{ $t('search') }}</el-button>
        <el-divider direction="vertical" />
        <el-button size="small" :disabled="selected.length === 0" @click="previewSelected">{{ $t('attPreview') }}</el-button>
        <el-button size="small" :disabled="selected.length === 0" @click="downloadSelected">{{ $t('attDownload') }}</el-button>
        <el-button v-if="activeTab === '1'" size="small" type="success" @click="restoreSelected">{{ $t('attRestore') }}</el-button>
        <el-button v-if="activeTab === '1' && isAdmin" size="small" type="danger" @click="trashDeleteSelected">{{ $t('attTrashDelete') }}</el-button>
        <el-button v-else-if="activeTab === '0'" size="small" type="danger" @click="batchDelete">{{ $t('attDelete') }}</el-button>
        <el-tooltip effect="dark" placement="top">
          <template #content>
            <div>{{ $t('attOpHint1') }}</div>
            <div>{{ $t('attOpHint2') }}</div>
          </template>
          <Icon class="op-hint" icon="fe:help-circle" width="16" height="16" />
        </el-tooltip>
      </div>
      <div v-if="canViewUsage" class="usage-bar">
        <span class="usage-title">{{ $t('attUsageTitle') }}</span>
        <span>{{ $t('attUsageFiles') }}: {{ usage.attCount }}</span>
        <span>{{ $t('attUsageSize') }}: {{ formatBytes(usage.attSize) }}</span>
        <template v-if="usage.cosCount > 0">
          <span class="sep">|</span>
          <span>{{ $t('attCosFiles') }}: {{ usage.cosCount }}</span>
          <span>{{ $t('attCosSize') }}: {{ formatBytes(usage.cosSize) }}</span>
        </template>
        <template v-if="usage.cosQuota > 0">
          <span class="sep">|</span>
          <span>{{ $t('attQuotaUsed') }}: {{ formatBytes(usage.cosSize) }} / {{ $t('attQuotaTotal') }} {{ formatBytes(usage.cosQuota * 1024 * 1024 * 1024) }}</span>
          <span>{{ $t('attQuotaRemain') }}: {{ formatBytes(Math.max(0, usage.cosQuota * 1024 * 1024 * 1024 - usage.cosSize)) }}</span>
        </template>
        <template v-if="usage.s3Expire">
          <span class="sep">|</span>
          <span :class="['usage-expire', {danger: isS3Expired}]">{{ $t('attS3Expire') }}: {{ usage.s3Expire }}</span>
        </template>
      </div>
      <div class="table-wrap">
        <el-table :data="groupedList" v-loading="loading" @selection-change="selectionChange" row-key="key">
          <el-table-column type="expand" width="36">
            <template #default="scope">
              <div class="expand-panel">
                <el-table :data="scope.row.records" size="small" row-key="attId"
                          class="sub-table" @selection-change="(rows) => subSelectionChange(scope.row.key, rows)">
                  <el-table-column type="selection" width="50" />
                  <el-table-column prop="userEmail" :label="$t('attUser')" min-width="170" show-overflow-tooltip />
                  <el-table-column prop="userRole" :label="$t('attUserRole')" width="120" show-overflow-tooltip />
                  <el-table-column prop="subject" :label="$t('attEmailSubject')" min-width="180" show-overflow-tooltip />
                  <el-table-column :label="$t('attTime')" width="160">
                    <template #default="r">{{ activeTab === '1' ? (r.row.trashTime || '-') : r.row.createTime }}</template>
                  </el-table-column>
                  <el-table-column :label="$t('action')" width="130" align="center">
                    <template #default="r">
                      <el-button link type="primary" size="small" @click="locateEmail(r.row)">{{ $t('attLocate') }}</el-button>
                      <el-button v-if="activeTab === '0'" link type="danger" size="small" @click="perUserDelete(r.row)">
                        {{ $t('attDelete') }}
                      </el-button>
                      <el-button v-else link type="success" size="small" @click="perUserRestore(r.row)">
                        {{ $t('attRestore') }}
                      </el-button>
                    </template>
                  </el-table-column>
                </el-table>
              </div>
            </template>
          </el-table-column>
          <el-table-column type="selection" width="45" />
          <el-table-column :label="$t('attFilename')" min-width="180" show-overflow-tooltip>
            <template #default="scope">
              <span class="att-name" @click="preview(scope.row.url)">{{ scope.row.filename }}</span>
            </template>
          </el-table-column>
          <el-table-column prop="size" :label="$t('attSize')" width="90">
            <template #default="scope">{{ formatBytes(scope.row.size) }}</template>
          </el-table-column>
          <el-table-column :label="$t('attType')" width="120">
            <template #default="scope">{{ attTypeLabel(scope.row) }}</template>
          </el-table-column>
          <el-table-column :label="$t('attUser')" min-width="150" show-overflow-tooltip v-if="canViewAll">
            <template #default="scope">{{ userSummary(scope.row) }}</template>
          </el-table-column>
          <el-table-column :label="$t('attEmailSubject')" min-width="140" show-overflow-tooltip>
            <template #default="scope">{{ subjectLabel(scope.row) }}</template>
          </el-table-column>
          <el-table-column :label="$t('attTime')" width="160">
            <template #default="scope">{{ activeTab === '1' ? (scope.row.trashTime || '-') : scope.row.createTime }}</template>
          </el-table-column>
          <el-table-column v-if="activeTab === '1'" :label="$t('attClearTime')" width="160">
            <template #default="scope">{{ clearTime(scope.row) }}</template>
          </el-table-column>
        </el-table>
      </div>
      <el-pagination
          class="pagination"
          background
          layout="total, prev, pager, next"
          :total="total"
          :page-size="params.size"
          :current-page="params.num"
          @current-change="pageChange"
      />
      <el-image-viewer v-if="previewShow" :url-list="previewList" show-progress @close="previewShow = false" />
    </div>
  </div>
</template>

<script setup>
import {computed, defineOptions, onMounted, reactive, ref} from "vue";
import {useRouter} from 'vue-router'
import {useI18n} from 'vue-i18n'
import {attList, attDelete, attTrashDelete, attRestore, attUsage} from "@/request/att.js";
import {emailDetail} from "@/request/email.js";
import {userList} from "@/request/user.js";
import {useUserStore} from "@/store/user.js";
import {useEmailStore} from "@/store/email.js";
import {formatBytes, getExtName} from "@/utils/file-utils.js";
import dayjs from 'dayjs';

defineOptions({
  name: 'att'
})

const {t} = useI18n()
const router = useRouter()
const userStore = useUserStore()
const emailStore = useEmailStore()
const permKeys = computed(() => userStore.user.permKeys || [])
// 仅超管可彻底删除垃圾桶
const isAdmin = computed(() => permKeys.value.includes('*'))
// 超管 / all-email:query（如安全组）/ att:all（全部附件权限）：可查看/管理全部用户的附件
const canViewAll = computed(() => permKeys.value.includes('*') || permKeys.value.includes('all-email:query') || permKeys.value.includes('att:all'))
// 超管 或 有 att:usage：可查看使用量
const canViewUsage = computed(() => permKeys.value.includes('*') || permKeys.value.includes('att:usage'))
// S3 到期时间是否已过期（未设置视为未过期）
const isS3Expired = computed(() => {
  if (!usage.value.s3Expire) return false
  return dayjs(usage.value.s3Expire + ' 00:00:00').isBefore(dayjs())
})

const activeTab = ref('0')
const params = reactive({
  userId: '',
  keyword: '',
  size: 20,
  num: 1,
  trash: 0,
})

const list = ref([])
const total = ref(0)
const loading = ref(false)
const userListData = ref([])
const selected = ref([])
const previewShow = ref(false)
const previewList = ref([])
const usage = ref({attCount: 0, attSize: 0, cosCount: 0, cosSize: 0, cosQuota: 0, s3Expire: ''})

const IMG_EXTS = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'svg', 'ico', 'tif', 'tiff']
const DOC_EXTS = ['doc', 'docx', 'odt', 'rtf']
const PDF_EXTS = ['pdf']
const XLS_EXTS = ['xls', 'xlsx', 'csv']
const PPT_EXTS = ['ppt', 'pptx']
const ZIP_EXTS = ['zip', 'rar', '7z', 'tar', 'gz', 'bz2']
const VID_EXTS = ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm']
const AUD_EXTS = ['mp3', 'wav', 'flac', 'aac', 'ogg', 'm4a']

// 按 COS 文件（key）分组：同一文件被多个用户引用时合并为一行，展开显示每个用户的明细
const groupedList = computed(() => {
  const map = new Map()
  for (const row of list.value) {
    if (!map.has(row.key)) {
      map.set(row.key, {...row, records: [row]})
    } else {
      map.get(row.key).records.push(row)
    }
  }
  return [...map.values()]
})

// 一级"所属用户"摘要：去重后的用户列表，超 2 个显示"等 N 个"
function userSummary(row) {
  const users = [...new Set((row.records || [row]).map(r => r.userEmail).filter(Boolean))]
  if (users.length === 0) return '-'
  if (users.length <= 2) return users.join('、')
  return users.slice(0, 2).join('、') + ' 等' + users.length + '个'
}

// 一级主题展示：多个不同主题时显示"等 N 封"
function subjectLabel(row) {
  if (row.records && row.records.length > 1) {
    const subs = new Set(row.records.map(r => r.subject).filter(Boolean))
    if (subs.size > 1) return (row.subject || '') + ' 等' + row.records.length + '封'
  }
  return row.subject || ''
}

// 分组行对应的全部附件记录 id
function rowAttIds(row) {
  return [...new Set((row.records || [row]).map(r => r.attId).filter(Boolean))]
}

// 当前选中（一级文件 + 二级用户记录）展开后的全部附件记录 id
function selectedAttIds() {
  const set = new Set()
  selected.value.forEach(row => (row.records || [row]).forEach(r => r.attId && set.add(r.attId)))
  Object.keys(subSelectedMap).forEach(k => (subSelectedMap[k] || []).forEach(r => r.attId && set.add(r.attId)))
  return [...set]
}

// 二级表格选择变化：按文件 key 分别记录选中的单条用户记录（避免多个展开行互相覆盖）
const subSelectedMap = reactive({})
function subSelectionChange(key, rows) {
  subSelectedMap[key] = rows
}

// 二级表格操作：删除某条用户记录（进垃圾桶，不影响其他用户引用同一文件）
function perUserDelete(rec) {
  ElMessageBox.confirm(t('attDeleteUserConfirm', {user: rec.userEmail, file: rec.filename}), {
    confirmButtonText: t('confirm'),
    cancelButtonText: t('cancel'),
    type: 'warning'
  }).then(() => {
    attDelete([rec.attId]).then(() => {
      ElMessage({message: t('attDeleteToTrash'), type: 'success', plain: true})
      getList()
    })
  })
}

// 二级表格操作：恢复某条垃圾桶记录
function perUserRestore(rec) {
  attRestore([rec.attId]).then(() => {
    ElMessage({message: t('attRestoreSuccess'), type: 'success', plain: true})
    getList()
  })
}

function attTypeLabel(row) {
  const ext = getExtName(row.filename || '')
  const prefix = row.type === 1 ? '内嵌图' : '附件'
  let label
  if (IMG_EXTS.includes(ext)) label = '图片'
  else if (DOC_EXTS.includes(ext)) label = 'Word文档'
  else if (PDF_EXTS.includes(ext)) label = 'PDF'
  else if (XLS_EXTS.includes(ext)) label = 'Excel'
  else if (PPT_EXTS.includes(ext)) label = 'PPT'
  else if (ZIP_EXTS.includes(ext)) label = '压缩包'
  else if (VID_EXTS.includes(ext)) label = '视频'
  else if (AUD_EXTS.includes(ext)) label = '音频'
  else if (ext) label = ext + '文件'
  else label = '未知'
  return prefix + '-' + label
}

function getList() {
  loading.value = true
  attList({...params}).then(data => {
    list.value = data.list
    total.value = data.total
  }).finally(() => {
    loading.value = false
  })
}

function search() {
  params.num = 1
  getList()
}

function pageChange(num) {
  params.num = num
  getList()
}

function tabChange(name) {
  params.trash = Number(name)
  params.num = 1
  getList()
}

function selectionChange(rows) {
  selected.value = rows
}

function isImage(filename) {
  return IMG_EXTS.includes(getExtName(filename || ''))
}

// 垃圾桶附件自动清空日期 = 删除时间 + 7 天
function clearTime(row) {
  if (!row.trashTime) return '-'
  return dayjs(row.trashTime).add(7, 'day').format('YYYY-MM-DD HH:mm')
}

function preview(url) {
  if (!url) return
  previewList.value = [url]
  previewShow.value = true
}

// 未选中任何附件时提示（工具栏按钮常显，点击无选中则提醒）
function requireSelection() {
  if (selectedAttIds().length === 0) {
    ElMessage({message: t('attSelectFirst'), type: 'warning', plain: true})
    return false
  }
  return true
}

function previewSelected() {
  if (selected.value.length === 0) {
    ElMessage({message: t('attSelectFileFirst'), type: 'warning', plain: true})
    return
  }
  const rec = selected.value.flatMap(r => r.records || [r]).find(r => isImage(r.filename))
  if (rec) preview(rec.url)
}

// 下载文件名：原始名没有正常扩展名时，按 MIME 类型补扩展名（如内嵌图 2C415AD4@... 补 .png）
function friendlyFilename(row) {
  const name = row.filename || 'attachment'
  const ext = getExtName(name)
  const imgExts = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp']
  if (imgExts.includes(ext)) return name

  const mime = (row.mimeType || '').toLowerCase()
  let mapExt = ''
  if (mime.includes('png')) mapExt = 'png'
  else if (mime.includes('jpeg') || mime.includes('jpg')) mapExt = 'jpg'
  else if (mime.includes('gif')) mapExt = 'gif'
  else if (mime.includes('webp')) mapExt = 'webp'
  else if (mime.includes('bmp')) mapExt = 'bmp'
  if (mapExt) return name + '.' + mapExt
  return name
}

function downloadSelected() {
  if (selected.value.length === 0) {
    ElMessage({message: t('attSelectFileFirst'), type: 'warning', plain: true})
    return
  }
  selected.value.flatMap(r => r.records || [r]).forEach(row => {
    const a = document.createElement('a')
    a.href = row.url
    a.download = friendlyFilename(row)
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
  })
}

function delAtt(row) {
  ElMessageBox.confirm(t('attDeleteConfirm'), {
    confirmButtonText: t('confirm'),
    cancelButtonText: t('cancel'),
    type: 'warning'
  }).then(() => {
    attDelete(rowAttIds(row)).then(() => {
      ElMessage({message: t('attDeleteToTrash'), type: 'success', plain: true})
      getList()
    })
  })
}

function batchDelete() {
  if (!requireSelection()) return
  const ids = selectedAttIds()
  if (!ids.length) return
  ElMessageBox.confirm(t('attDeleteBatchConfirm', {count: ids.length}), {
    confirmButtonText: t('confirm'),
    cancelButtonText: t('cancel'),
    type: 'warning'
  }).then(() => {
    attDelete(ids).then(() => {
      ElMessage({message: t('attDeleteToTrash'), type: 'success', plain: true})
      getList()
    })
  })
}

function trashDeleteAtt(row) {
  ElMessageBox.confirm(t('attTrashConfirm'), {
    confirmButtonText: t('confirm'),
    cancelButtonText: t('cancel'),
    type: 'warning'
  }).then(() => {
    attTrashDelete(rowAttIds(row)).then(() => {
      ElMessage({message: t('delSuccessMsg'), type: 'success', plain: true})
      getList()
    })
  })
}

function trashDeleteSelected() {
  if (!requireSelection()) return
  const ids = selectedAttIds()
  if (!ids.length) return
  ElMessageBox.confirm(t('attTrashBatchConfirm', {count: ids.length}), {
    confirmButtonText: t('confirm'),
    cancelButtonText: t('cancel'),
    type: 'warning'
  }).then(() => {
    attTrashDelete(ids).then(() => {
      ElMessage({message: t('delSuccessMsg'), type: 'success', plain: true})
      getList()
    })
  })
}

// 恢复选中的垃圾桶附件
function restoreSelected() {
  if (!requireSelection()) return
  const ids = selectedAttIds()
  if (!ids.length) return
  attRestore(ids).then(() => {
    ElMessage({message: t('attRestoreSuccess'), type: 'success', plain: true})
    getList()
  })
}

// 定位到目标邮件
function locateEmail(row) {
  if (!row.emailId) {
    ElMessage({message: t('attLocateFail'), type: 'warning', plain: true})
    return
  }
  emailDetail(row.emailId).then(email => {
    emailStore.contentData.email = email
    emailStore.contentData.delType = 'logic'
    emailStore.contentData.showUnread = false
    emailStore.contentData.showStar = true
    emailStore.contentData.showReply = true
    router.push('/message')
  }).catch(() => {
    ElMessage({message: t('attLocateFail'), type: 'warning', plain: true})
  })
}

// 加载附件使用量（COS 实际存储量 + 数据库统计）
function loadUsage() {
  if (!canViewUsage.value) return
  attUsage().then(u => {
    usage.value = u
  }).catch(() => {})
}

onMounted(() => {
  getList()
  loadUsage()
  if (canViewAll.value) {
    userList({size: 1000}).then(data => {
      userListData.value = data.list
    })
  }
})
</script>

<style scoped lang="scss">
.box {
  height: 100%;
  overflow: hidden;
  box-sizing: border-box;
  padding: 14px 20px;

  .att-manage {
    height: 100%;
    display: flex;
    flex-direction: column;
    gap: 12px;

    .toolbar {
      flex-shrink: 0;
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: nowrap;
      overflow-x: auto;
      min-height: 40px;

      .att-tabs {
        flex-shrink: 0;
        :deep(.el-tabs__header) {
          margin: 0;
        }
      }

      .user-select {
        width: 200px;
        flex-shrink: 0;
      }

      .search-input {
        width: 220px;
        flex-shrink: 0;
      }

      .el-button {
        flex-shrink: 0;
      }
    }

    .usage-bar {
      flex-shrink: 0;
      display: flex;
      align-items: center;
      gap: 14px;
      font-size: 13px;
      color: var(--regular-text-color);
      padding: 6px 2px;

      .usage-title {
        font-weight: 600;
        color: var(--el-text-color-primary);
      }

      .sep {
        color: var(--el-border-color);
      }

      .usage-expire {
        &.danger {
          color: var(--el-color-danger);
          font-weight: 600;
        }
      }

      .expand-panel {
        padding: 8px 0 8px 26px;

        .sub-table {
          max-width: 100%;
        }
      }

      .op-hint {
        color: var(--el-text-color-secondary);
        cursor: help;
      }
    }

    .table-wrap {
      flex: 1;
      overflow: auto;
      min-height: 0;

      .att-name {
        color: #4dabff;
        cursor: pointer;
        &:hover {
          text-decoration: underline;
        }
      }
    }

    .pagination {
      flex-shrink: 0;
      display: flex;
      justify-content: center;
      padding-top: 8px;
    }
  }
}
</style>
