// COS(S3) 故障自动回退 KV + 恢复后回迁 逻辑单测
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import r2Service from '../src/service/r2-service';
import s3Service from '../src/service/s3-service';

// 内存 KV mock
function makeKvStore() {
	const store = new Map();
	return {
		store,
		kv: {
			async put(k, v, opts) { store.set(k, { v, opts }); },
			async getWithMetadata(k) {
				const e = store.get(k);
				return e ? { value: e.v, metadata: e.opts?.metadata || null } : { value: null, metadata: null };
			},
			async delete(k) { store.delete(k); },
			async list(opts) {
				const prefix = opts?.prefix || '';
				const all = [...store.keys()].filter(k => k.startsWith(prefix)).sort();
				const limit = opts?.limit || 1000;
				const start = opts?.cursor ? parseInt(opts.cursor, 10) : 0;
				const slice = all.slice(start, start + limit);
				const next = start + limit < all.length ? String(start + limit) : undefined;
				return { keys: slice.map(name => ({ name })), cursor: next };
			}
		}
	};
}

// mock Hono 上下文：直接提供 setting + 内存 KV，避免走真实 KV/DB
function makeC(s3 = true, hasR2 = false) {
	const setting = s3
		? { bucket: 'bkt', endpoint: 'https://cos.example.com', s3AccessKey: 'ak', s3SecretKey: 'sk' }
		: { bucket: '', endpoint: '', s3AccessKey: '', s3SecretKey: '' };
	const ks = makeKvStore();
	return {
		get: (k) => (k === 'setting' ? setting : undefined),
		set: () => {},
		env: { r2: hasR2, kv: ks.kv },
		_kv: ks.store,
	};
}

// 让 COS 进入「健康」状态（越过故障窗口）
function healthy() {
	vi.useFakeTimers();
	r2Service.markS3Failed();
	vi.setSystemTime(Date.now() + 6 * 60 * 1000);
}
// 让 COS 进入「故障」状态
function failed() {
	vi.useFakeTimers();
	r2Service.markS3Failed();
}

beforeEach(() => {
	vi.restoreAllMocks();
	vi.useRealTimers();
});
afterEach(() => {
	vi.restoreAllMocks();
	vi.useRealTimers();
});

describe('r2Service COS 故障自动回退 KV', () => {
	it('配置了 COS 且健康 → S3', async () => {
		healthy();
		expect(await r2Service.storageType(makeC(true))).toBe('S3');
	});

	it('COS 故障（窗口内）→ 回退 KV', async () => {
		failed();
		expect(await r2Service.storageType(makeC(true))).toBe('KV');
	});

	it('COS 故障时即使有 R2 也回退 KV（行为可预期）', async () => {
		failed();
		expect(await r2Service.storageType(makeC(true, true))).toBe('KV');
	});

	it('窗口过期后自动恢复探测 → S3', async () => {
		healthy();
		expect(await r2Service.storageType(makeC(true))).toBe('S3');
	});

	it('无 COS 配置 + 无 R2 → KV（默认）', async () => {
		expect(await r2Service.storageType(makeC(false))).toBe('KV');
	});

	it('无 COS 配置 + 有 R2 → R2（原逻辑）', async () => {
		expect(await r2Service.storageType(makeC(false, true))).toBe('R2');
	});

	it('COS 故障回退期间 isCosFallback = true', async () => {
		failed();
		expect(await r2Service.isCosFallback(makeC(true))).toBe(true);
	});

	it('COS 恢复后 isCosFallback = false', async () => {
		healthy();
		expect(await r2Service.isCosFallback(makeC(true))).toBe(false);
	});

	it('未配置 COS 时 isCosFallback = false', async () => {
		expect(await r2Service.isCosFallback(makeC(false))).toBe(false);
	});
});

describe('回退写入 KV 打标记 + 恢复后回迁', () => {
	it('S3 写入失败回退 KV 时 metadata 带 storage=fallback 标记', async () => {
		healthy(); // storageType 判定 S3，但实际 COS 写入失败 → 触发回退
		vi.spyOn(s3Service, 'putObj').mockRejectedValue(new Error('denied'));
		const c = makeC(true);
		await r2Service.putObj(c, 'attachments/x.png', 'DATA', { contentType: 'image/png' });
		expect(c._kv.get('attachments/x.png').opts.metadata.storage).toBe('fallback');
	});

	it('migrateFallbackBatch：COS 健康时只回迁带标记的附件，返回迁移数', async () => {
		healthy();
		vi.spyOn(s3Service, 'putObj').mockResolvedValue({});
		const c = makeC(true);
		await c.env.kv.put('attachments/fallback1', 'A', { metadata: { contentType: 'image/png', storage: 'fallback' } });
		await c.env.kv.put('attachments/normal1', 'B', { metadata: { contentType: 'image/png' } });
		const migrated = await r2Service.migrateFallbackBatch(c, 30);
		expect(migrated).toBe(1);
		expect(c._kv.has('attachments/fallback1')).toBe(false); // 回退附件已迁出 KV
		expect(c._kv.has('attachments/normal1')).toBe(true);   // 非回退附件保留
	});

	it('migrateFallbackBatch：超过单页(100)key 时用 cursor 分页也能迁到回退附件', async () => {
		healthy();
		vi.spyOn(s3Service, 'putObj').mockResolvedValue({});
		const c = makeC(true);
		// 前 100 个非回退 + 第 101 个是回退附件
		for (let i = 0; i < 100; i++) {
			await c.env.kv.put(`attachments/normal${i}`, 'N', { metadata: { contentType: 'image/png' } });
		}
		await c.env.kv.put('attachments/zz-fallback1', 'A', { metadata: { contentType: 'image/png', storage: 'fallback' } });
		const migrated = await r2Service.migrateFallbackBatch(c, 30);
		expect(migrated).toBe(1);
		expect(c._kv.has('attachments/zz-fallback1')).toBe(false);
	});

	it('migrateFallbackBatch：COS 故障时返回 0 不迁移', async () => {
		failed();
		const c = makeC(true);
		await c.env.kv.put('attachments/fallback1', 'A', { metadata: { storage: 'fallback' } });
		expect(await r2Service.migrateFallbackBatch(c, 30)).toBe(0);
		expect(c._kv.has('attachments/fallback1')).toBe(true);
	});

	it('getFromKv 惰性回迁：COS 健康时访问回退附件即写回 COS 并释放 KV', async () => {
		healthy();
		const putMock = vi.spyOn(s3Service, 'putObj').mockResolvedValue({});
		const c = makeC(true);
		await c.env.kv.put('attachments/fallback1', 'DATA', { metadata: { contentType: 'image/png', storage: 'fallback' } });
		const resp = await r2Service.getFromKv(c, 'attachments/fallback1');
		expect(resp).not.toBeNull();
		expect(putMock).toHaveBeenCalledTimes(1);
		expect(c._kv.has('attachments/fallback1')).toBe(false); // 已释放 KV
	});

	it('getObj S3 失败但 KV 有回退附件：返回 KV 内容并补迁，不误判 COS 故障', async () => {
		healthy();
		vi.spyOn(s3Service, 'getObj').mockRejectedValue(new Error('NoSuchKey'));
		const putMock = vi.spyOn(s3Service, 'putObj').mockResolvedValue({});
		const c = makeC(true);
		await c.env.kv.put('attachments/fallback1', 'DATA', { metadata: { contentType: 'image/png', storage: 'fallback' } });
		const resp = await r2Service.getObj(c, 'attachments/fallback1');
		expect(resp).not.toBeNull();
		expect(putMock).toHaveBeenCalledTimes(1);          // 补迁 COS
		expect(c._kv.has('attachments/fallback1')).toBe(false); // KV 释放
		expect(r2Service.isS3Healthy()).toBe(true);        // 未误判故障
	});
});

