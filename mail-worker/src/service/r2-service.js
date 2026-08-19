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

		// S3：失败（COS 关闭/密钥失效/验证失败）→ 标记故障并回退 KV（打 fallback 标记，便于恢复后回迁）
		try {
			await s3Service.putObj(c, key, content, metadata);
		} catch (e) {
			this.markS3Failed();
			await kvObjService.putObj(c, key, content, { ...metadata, storage: 'fallback' });
		}
	},

	// 从 KV 读取附件（带惰性回迁：COS 恢复时把回退附件写回 COS 并释放 KV 空间）
	async getFromKv(c, key) {
		const obj = await c.env.kv.getWithMetadata(key, { type: 'arrayBuffer' });
		if (!obj.value) {
			return null;
		}
		if (obj.metadata?.storage === 'fallback' && this.isS3Healthy()) {
			try {
				await s3Service.putObj(c, key, obj.value, obj.metadata);
				await c.env.kv.delete(key);
			} catch (e) {
				// COS 仍不可用，回到故障窗口，保留 KV（下次再迁）
				this.markS3Failed();
			}
		}
		return this.buildKvResponse(obj);
	},

	buildKvResponse(obj) {
		return new Response(obj.value, {
			headers: {
				'Content-Type': obj.metadata?.contentType || 'application/octet-stream',
				'Content-Disposition': obj.metadata?.contentDisposition || null,
				'Cache-Control': obj.metadata?.cacheControl || null
			}
		});
	},

	async getObj(c, key) {

		const storageType = await this.storageType(c);

		if (storageType === 'KV') {
			return await this.getFromKv(c, key);
		}

		if (storageType === 'R2') {
			return await c.env.r2.get(key);
		}

		// S3
		try {
			return await s3Service.getObj(c, key);
		} catch (e) {
			// S3 读取失败：先查 KV 里是否有未回迁的回退附件（可能是 COS 恢复过渡期）
			const kvObj = await c.env.kv.getWithMetadata(key, { type: 'arrayBuffer' });
			if (kvObj.value) {
				// 有回退附件：返回 KV 内容，并尝试补迁 COS（不判定 COS 故障）
				if (kvObj.metadata?.storage === 'fallback') {
					try {
						await s3Service.putObj(c, key, kvObj.value, kvObj.metadata);
						await c.env.kv.delete(key);
					} catch (e2) { /* COS 未完全恢复，保留 KV 等下次 */ }
				}
				return this.buildKvResponse(kvObj);
			}
			// KV 也没有 → COS 真的不可用
			this.markS3Failed();
			return null;
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
			return;
		}

		// 双删：清理可能残留的 KV 回退副本（幂等）
		await kvObjService.deleteObj(c, key);
	},

	// cron 批量回迁：COS 恢复后，把回退期间写入 KV 的附件逐批迁回 COS 并删除 KV，释放空间。
	// 每次限 batch 个，剩余由后续 cron 继续；COS 未恢复时直接返回 0。
	// list 用 cursor 分页遍历，确保超过单页(100)的 key 也能被扫描到。
	async migrateFallbackBatch(c, batch = 30) {
		const type = await this.storageType(c);
		if (type !== 'S3') {
			return 0; // COS 未配置或仍在故障窗口，不迁移
		}

		let migrated = 0;
		let cursor;

		do {
			const list = await c.env.kv.list({ prefix: 'attachments/', limit: 100, cursor });
			for (const item of list.keys) {
				if (migrated >= batch) return migrated;
				const obj = await c.env.kv.getWithMetadata(item.name, { type: 'arrayBuffer' });
				if (!obj.value) continue;
				if (obj.metadata?.storage !== 'fallback') continue;
				try {
					await s3Service.putObj(c, item.name, obj.value, obj.metadata);
					await c.env.kv.delete(item.name);
					migrated++;
				} catch (e) {
					this.markS3Failed(); // COS 不可用，本轮停止，下轮再试
					return migrated;
				}
			}
			cursor = list.cursor;
		} while (cursor && migrated < batch);

		if (migrated > 0) {
			console.log(`[storage] COS 恢复，回迁 ${migrated} 个回退附件到 COS`);
		}

		return migrated;
	}

};
export default r2Service;
