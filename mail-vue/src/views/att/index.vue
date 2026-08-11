<template>
  <div class="box">
    <div class="att-manage">
      <div class="toolbar">
        <el-select
            v-if="isAdmin"
            v-model="params.userId"
            :placeholder="$t('selectUser')"
            clearable
            filterable
            class="user-select"
            @change="search"
        >
          <el-option v-for="u in userList" :key="u.userId" :label="u.email" :value="u.userId" />
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
        <el-button v-if="selected.length" type="danger" plain @click="batchDelete">{{ $t('batchDelete') }}</el-button>
      </div>
      <el-table :data="list" v-loading="loading" @selection-change="selectionChange">
        <el-table-column type="selection" width="45" />
        <el-table-column prop="filename" :label="$t('attFilename')" min-width="220" show-overflow-tooltip />
        <el-table-column prop="size" :label="$t('attSize')" width="90">
          <template #default="scope">{{ formatBytes(scope.row.size) }}</template>
        </el-table-column>
        <el-table-column :label="$t('attType')" width="90">
          <template #default="scope">
            <el-tag :type="scope.row.type === 1 ? 'success' : 'primary'" size="small">
              {{ scope.row.type === 1 ? $t('attTypeEmbed') : $t('attTypeAtt') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="userEmail" :label="$t('attUser')" width="200" show-overflow-tooltip v-if="isAdmin" />
        <el-table-column prop="subject" :label="$t('attEmailSubject')" min-width="160" show-overflow-tooltip />
        <el-table-column prop="createTime" :label="$t('attTime')" width="165" />
        <el-table-column :label="$t('action')" width="190" fixed="right">
          <template #default="scope">
            <el-button v-if="isImage(scope.row.filename)" size="small" @click="preview(scope.row.url)">{{ $t('attPreview') }}</el-button>
            <a :href="scope.row.url" download>
              <el-button size="small">{{ $t('attDownload') }}</el-button>
            </a>
            <el-button size="small" type="danger" @click="delAtt(scope.row)">{{ $t('attDelete') }}</el-button>
          </template>
        </el-table-column>
      </el-table>
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
import {useI18n} from 'vue-i18n'
import {attList, attDelete} from "@/request/att.js";
import {userList} from "@/request/user.js";
import {useUserStore} from "@/store/user.js";
import {formatBytes, getExtName} from "@/utils/file-utils.js";

defineOptions({
  name: 'att'
})

const {t} = useI18n()
const userStore = useUserStore()
const isAdmin = computed(() => (userStore.user.permKeys || []).includes('*'))

const params = reactive({
  userId: '',
  keyword: '',
  size: 20,
  num: 1,
})

const list = ref([])
const total = ref(0)
const loading = ref(false)
const userListData = ref([])
const selected = ref([])
const previewShow = ref(false)
const previewList = ref([])

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

function selectionChange(rows) {
  selected.value = rows
}

function delAtt(row) {
  ElMessageBox.confirm(t('attDeleteConfirm'), {
    confirmButtonText: t('confirm'),
    cancelButtonText: t('cancel'),
    type: 'warning'
  }).then(() => {
    attDelete([row.attId]).then(() => {
      ElMessage({message: t('delSuccessMsg'), type: 'success', plain: true})
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
      ElMessage({message: t('delSuccessMsg'), type: 'success', plain: true})
      getList()
    })
  })
}

function preview(url) {
  previewList.value = [url]
  previewShow.value = true
}

function isImage(filename) {
  return ['png', 'jpg', 'jpeg', 'bmp', 'gif', 'jfif', 'webp'].includes(getExtName(filename))
}

onMounted(() => {
  getList()
  if (isAdmin.value) {
    userList({size: 1000}).then(data => {
      userListData.value = data.list
    })
  }
})
</script>

<style scoped lang="scss">
.box {
  padding: 20px;

  .att-manage {
    display: flex;
    flex-direction: column;
    gap: 15px;

    .toolbar {
      display: flex;
      gap: 10px;
      align-items: center;

      .user-select {
        width: 220px;
      }

      .search-input {
        width: 260px;
      }
    }

    .pagination {
      justify-content: center;
    }
  }
}
</style>
