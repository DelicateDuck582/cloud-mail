import s3Service from './s3-service';
import settingService from './setting-service';
import kvObjService from './kv-obj-service';

// KV 删除批次：Workers 单次请求子请求数量有限，批量删除按 ≤10 一批串行执行，避免批量删除打爆上限
const KV_DELETE_BATCH_SIZE = 10;

const r2Service = {

	// KV 批量删除：按 KV_DELETE_BATCH_SIZE 串行小批，并发受控（幂等，重复删除无副作用）
	async deleteKvBatch(c, keys) {
		const list = (typeof keys === 'string' ? [keys] : (keys || [])).filter(Boolean);
		for (let i = 0; i < list.length; i += KV_DELETE_BATCH_SIZE) {
			await kvObjService.deleteObj(c, list.slice(i, i + KV_DELETE_BATCH_SIZE));
		}
	},

	async storageType(c) {

		const setting = await settingService.query(c);
		const { bucket, endpoint, s3AccessKey, s3SecretKey } = setting;

		if (!!(bucket && endpoint && s3AccessKey && s3SecretKey)) {
			return 'S3';
		}

		if (c.env.r2) {
			return 'R2';
		}

		return 'KV';
	},

	async putObj(c, key, content, metadata) {

		const storageType = await this.storageType(c);

		if (storageType === 'KV') {
			await kvObjService.putObj(c, key, content, metadata);
		}

		if (storageType === 'R2') {
			await c.env.r2.put(key, content, {
				httpMetadata: { ...metadata }
			});
		}

		if (storageType === 'S3') {
			await s3Service.putObj(c, key, content, metadata);
		}

	},

	async getObj(c, key) {
		const storageType = await this.storageType(c);

		if (storageType === 'KV') {
			return await kvObjService.getObj(c, key);
		}

		if (storageType === 'R2') {
			return await c.env.r2.get(key);
		}

		if (storageType === 'S3') {
			return await s3Service.getObj(c, key);
		}
	},

	async delete(c, key) {

		const storageType = await this.storageType(c);

		if (storageType === 'KV') {
			await this.deleteKvBatch(c, key);
		}

		if (storageType === 'R2') {
			await c.env.r2.delete(key);
		}

		if (storageType === 'S3'){
			await s3Service.deleteObj(c, key);
		}

	}

};
export default r2Service;
