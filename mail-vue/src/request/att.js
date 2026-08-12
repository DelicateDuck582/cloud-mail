import http from '@/axios/index.js';

export function attList(params) {
    return http.get('/att/list', {params: {...params}})
}

export function attDelete(attIds) {
    return http.delete('/att/delete', {params: {attIds: attIds.join(',')}})
}

export function attTrashDelete(attIds) {
    return http.delete('/att/trash', {params: {attIds: attIds.join(',')}})
}

export function attRestore(attIds) {
    return http.post('/att/restore', {attIds})
}

export function attUsage() {
    return http.get('/att/usage', {noMsg: true})
}
