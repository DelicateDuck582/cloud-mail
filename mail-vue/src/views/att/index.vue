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
        <template v-if="selected.length">
          <el-divider direction="vertical" />
          <el-button size="small" @click="previewSelected">{{ $t('attPreview') }}</el-button>
          <el-button size="small" @click="downloadSelected">{{ $t('attDownload') }}</el-button>
          <el-button size="small" @click="locateSelected">{{ $t('attLocate') }}</el-button>
          <el-button v-if="activeTab === '1'" size="small" type="success" @click="restoreSelected">{{ $t('attRestore') }}</el-button>
          <el-button v-if="activeTab === '1' && isAdmin" size="small" type="danger" @click="trashDeleteSelected">{{ $t('attTrashDelete') }}</el-button>
          <el-button v-else-if="activeTab === '0'" size="small" type="danger" @click="batchDelete">{{ $t('attDelete') }}</el-button>
        </template>
      </div>
      <div class="table-wrap">
        <el-table :data="list" v-loading="loading" @selection-change="selectionChange">
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
          <el-table-column prop="userEmail" :label="$t('attUser')" width="180" show-overflow-tooltip v-if="canViewAll" />
          <el-table-column prop="userRole" :label="$t('attUserRole')" width="110" show-overflow-tooltip v-if="canViewAll" />
          <el-table-column prop="subject" :label="$t('attEmailSubject')" min-width="140" show-overflow-tooltip />
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
import {attList, attDelete, attTrashDelete, attRestore} from "@/request/att.js";
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
// 超管 或 有 all-email:query（如安全组）：可查看/管理全部用户的附件
const canViewAll = computed(() => permKeys.value.includes('*') || permKeys.value.includes('all-email:query'))

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

const IMG_EXTS = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'svg', 'ico', 'tif', 'tiff']
const DOC_EXTS = ['doc', 'docx', 'odt', 'rtf']
const PDF_EXTS = ['pdf']
const XLS_EXTS = ['xls', 'xlsx', 'csv']
const PPT_EXTS = ['ppt', 'pptx']
const ZIP_EXTS = ['zip', 'rar', '7z', 'tar', 'gz', 'bz2']
const VID_EXTS = ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm']
const AUD_EXTS = ['mp3', 'wav', 'flac', 'aac', 'ogg', 'm4a']

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

function previewSelected() {
  const img = selected.value.find(r => isImage(r.filename))
  if (img) preview(img.url)
}

function downloadSelected() {
  selected.value.forEach(row => {
    const a = document.createElement('a')
    a.href = row.url
    a.download = row.filename
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
    attDelete([row.attId]).then(() => {
      ElMessage({message: t('attDeleteToTrash'), type: 'success', plain: true})
      getList()
    })
  })
}

function batchDelete() {
  const ids = selected.value.map(r => r.attId)
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
    attTrashDelete([row.attId]).then(() => {
      ElMessage({message: t('delSuccessMsg'), type: 'success', plain: true})
      getList()
    })
  })
}

function trashDeleteSelected() {
  const ids = selected.value.map(r => r.attId)
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
  const ids = selected.value.map(r => r.attId)
  if (!ids.length) return
  attRestore(ids).then(() => {
    ElMessage({message: t('attRestoreSuccess'), type: 'success', plain: true})
    getList()
  })
}

// 定位到选中的第一个附件对应的邮件
function locateSelected() {
  if (selected.value.length) locateEmail(selected.value[0])
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

onMounted(() => {
  getList()
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
