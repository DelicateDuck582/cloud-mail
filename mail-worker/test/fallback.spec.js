// COS(S3) 故障自动回退 KV 逻辑单测
import { describe, it, expect, vi } from 'vitest';
import r2Service from '../src/service/r2-service';

// mock Hono 上下文：直接提供 setting，避免走 KV/DB
function makeC(s3 = true, hasR2 = false) {
	const setting = s3
		? { bucket: 'bkt', endpoint: 'https://cos.example.com', s3AccessKey: 'ak', s3SecretKey: 'sk' }
		: { bucket: '', endpoint: '', s3AccessKey: '', s3SecretKey: '' };
	return {
		get: (k) => (k === 'setting' ? setting : undefined),
		set: () => {},
		env: { r2: hasR2, kv: { get: async () => null } },
	};
}

describe('r2Service COS 故障自动回退 KV', () => {
	it('配置了 COS 且健康 → S3', async () => {
		expect(await r2Service.storageType(makeC(true))).toBe('S3');
	});

	it('COS 故障（窗口内）→ 回退 KV', async () => {
		r2Service.markS3Failed();
		expect(await r2Service.storageType(makeC(true))).toBe('KV');
	});

	it('COS 故障时即使有 R2 也回退 KV（行为可预期）', async () => {
		r2Service.markS3Failed();
		expect(await r2Service.storageType(makeC(true, true))).toBe('KV');
	});

	it('窗口过期后自动恢复探测 → S3', async () => {
		vi.useFakeTimers();
		try {
			r2Service.markS3Failed();
			vi.setSystemTime(Date.now() + 5 * 60 * 1000 + 1000); // 拨快越过 5 分钟窗口
			expect(await r2Service.storageType(makeC(true))).toBe('S3');
		} finally {
			vi.useRealTimers();
		}
	});

	it('无 COS 配置 + 无 R2 → KV（默认）', async () => {
		expect(await r2Service.storageType(makeC(false))).toBe('KV');
	});

	it('无 COS 配置 + 有 R2 → R2（原逻辑）', async () => {
		expect(await r2Service.storageType(makeC(false, true))).toBe('R2');
	});
});
