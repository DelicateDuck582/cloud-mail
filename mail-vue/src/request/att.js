import http from '@/axios/index.js';

export function attList(params) {
    return http.get('/att/list', {params: {...params}})
}

export function attDelete(attIds) {
    return http.delete('/att/delete', {params: {attIds: attIds.join(',')}})
}
