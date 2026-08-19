import s3Service from './s3-service';
import settingService from './setting-service';
import kvObjService from './kv-obj-service';

// COS(S3) 故障自动回退 KV：
//   - 配置了 S3 但 API 不可用（密钥失效/验证失败/endpoint 不可达/被拒）→ 标记故障，读写自动回退 KV
//   - 故障窗口内直接走 KV，避免每次请求都重试失败的 S3
//   - 窗口过后自动重新探测 S3，COS 恢复后自动切回（无需重启/改配置）
const S3_FAIL_WINDOW_MS = 5 * 60 * 1000; // 5 分钟
let s3FailUntil = 0;

const r2Service = {

	isS3Healthy() {
		return Date.now() >= s3FailUntil;
	},

	markS3Failed() {
		s3FailUntil = Date.now() + S3_FAIL_WINDOW_MS;
		console.warn(`[storage] COS(S3) 不可用或验证失败，${S3_FAIL_WINDOW_MS / 60000} 分钟内自动回退 KV 存储`);
	},

	// 当前是否处于 COS 故障自动回退状态（用于给历史 COS 附件返回明确提示「文件暂时无法访问--COS错误」）
	async isCosFallback(c) {
		const setting = await settingService.query(c);
		const { bucket, endpoint, s3AccessKey, s3SecretKey } = setting;
		const s3Configured = !!(bucket && endpoint && s3AccessKey && s3SecretKey);
		return s3Configured && !this.isS3Healthy();
	},

	async storageType(c) {

		const setting = await settingService.query(c);
		const { bucket, endpoint, s3AccessKey, s3SecretKey } = setting;

		const s3Configured = !!(bucket && endpoint && s3AccessKey && s3SecretKey);

		if (s3Configured) {
			// 配置了 COS：健康走 S3，故障窗口内回退 KV（不回退到 R2，保证行为可预期）
			return this.isS3Healthy() ? 'S3' : 'KV';
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
			return;
		}

		if (storageType === 'R2') {
			await c.env.r2.put(key, content, {
				httpMetadata: { ...metadata }
			});
			return;
		}

		// S3：失败（COS 关闭/密钥失效/验证失败）→ 标记故障并回退 KV
		try {
			await s3Service.putObj(c, key, content, metadata);
		} catch (e) {
			this.markS3Failed();
			await kvObjService.putObj(c, key, content, metadata);
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

		try {
			return await s3Service.getObj(c, key);
		} catch (e) {
			this.markS3Failed();
			return await kvObjService.getObj(c, key);
		}
	},

	async delete(c, key) {

		const storageType = await this.storageType(c);

		if (storageType === 'KV') {
			await kvObjService.deleteObj(c, key);
			return;
		}

		if (storageType === 'R2') {
			await c.env.r2.delete(key);
			return;
		}

		try {
			await s3Service.deleteObj(c, key);
		} catch (e) {
			this.markS3Failed();
			await kvObjService.deleteObj(c, key);
		}
	}

};
export default r2Service;
