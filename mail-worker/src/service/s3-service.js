import { S3Client, PutObjectCommand, DeleteObjectsCommand, GetObjectCommand, ListObjectsV2Command } from "@aws-sdk/client-s3";
import settingService from './setting-service';
import domainUtils from '../utils/domain-uitls';
import { settingConst } from '../const/entity-const';

// COS 实际用量 KV 缓存（用量统计允许滞后，避免每次请求都全量扫描 bucket）
const COS_USAGE_CACHE_KEY = 'cos_usage_cache';
const COS_USAGE_CACHE_TTL = 6 * 60 * 60; // 6 小时（秒）
// 单次扫描页数上限（每页 1000 对象，约 5 万对象），防止超大桶拖垮请求
const COS_USAGE_MAX_PAGES = 50;

const s3Service = {

	async putObj(c, key, content, metadata) {

		const client = await this.client(c);

		const { bucket } = await settingService.query(c);

		let obj = { Bucket: bucket, Key: key, Body: content,
			CacheControl: metadata.cacheControl
		}

		if (metadata.cacheControl) {
			obj.CacheControl = metadata.cacheControl
		}

		if (metadata.contentDisposition) {
			obj.ContentDisposition = metadata.contentDisposition
		}

		if (metadata.contentType) {
			obj.ContentType = metadata.contentType
		}

		await client.send(new PutObjectCommand(obj))
	},

	async deleteObj(c, keys) {

		if (typeof keys === 'string') {
			keys = [keys];
		}

		if (keys.length === 0) {
			return;
		}

		const client = await this.client(c);
		const { bucket } = await settingService.query(c);


		client.middlewareStack.add(
			(next) => async (args) => {

				const body = args.request.body

				// 计算 MD5 校验和并转换为 Base64 编码
				const encoder = new TextEncoder();
				const data = encoder.encode(body);

				// 使用 Web Crypto API 计算 MD5 校验和
				const hashBuffer = await crypto.subtle.digest('MD5', data);
				const hashArray = new Uint8Array(hashBuffer);
				const contentMD5 = btoa(String.fromCharCode.apply(null, hashArray));

				args.request.headers["Content-MD5"] = contentMD5;

				return next(args);
			},
			{ step: "build", name: "inspectRequestMiddleware" }
		);


		await client.send(
			new DeleteObjectsCommand({
				Bucket: bucket,
				Delete: {
					Objects: keys.map(key => ({ Key: key }))
				}
			})
		);
	},

	async getObj(c, key) {
		const client = await this.client(c);
		const { bucket } = await settingService.query(c);
		const result = await client.send(new GetObjectCommand({
			Bucket: bucket,
			Key: key
		}));

		return new Response(result.Body, {
			headers: {
				'Content-Type': result.ContentType || 'application/octet-stream',
				'Content-Disposition': result.ContentDisposition || null,
				'Cache-Control': result.CacheControl || null
			}
		});
	},


	async client(c) {
		const { region, endpoint, s3AccessKey, s3SecretKey, forcePathStyle } = await settingService.query(c);
		return new S3Client({
			region: region || 'auto',
			endpoint: domainUtils.toOssDomain(endpoint),
			forcePathStyle: forcePathStyle === settingConst.forcePathStyle.OPEN,
			credentials: {
				accessKeyId: s3AccessKey,
				secretAccessKey: s3SecretKey,
			}
		});
	},

	// 统计整个 bucket 的实际存储使用量（对象数 + 总大小，非配额）
	// 命中 KV 缓存（6 小时）直接返回；扫描到页数上限时返回值带 incomplete: true 标记
	async getBucketUsage(c) {

		if (c.env?.kv) {
			try {
				const cached = await c.env.kv.get(COS_USAGE_CACHE_KEY, { type: 'json' });
				if (cached && typeof cached.count === 'number') {
					return cached;
				}
			} catch (e) {
				console.error('COS usage cache read error:', e);
			}
		}

		const client = await this.client(c);
		const { bucket } = await settingService.query(c);

		let count = 0;
		let totalSize = 0;
		let continuationToken;
		let pages = 0;
		let incomplete = false;

		do {
			// 页数保护：最多遍历 50 页（约 5 万对象），防止超大桶导致请求超时
			if (++pages > COS_USAGE_MAX_PAGES) {
				incomplete = true;
				break;
			}
			const params = { Bucket: bucket, MaxKeys: 1000 };
			if (continuationToken) {
				params.ContinuationToken = continuationToken;
			}
			const result = await client.send(new ListObjectsV2Command(params));
			for (const obj of result.Contents || []) {
				count += 1;
				totalSize += obj.Size || 0;
			}
			continuationToken = result.IsTruncated ? result.NextContinuationToken : undefined;
		} while (continuationToken);

		const usage = incomplete ? { count, totalSize, incomplete: true } : { count, totalSize };

		if (c.env?.kv) {
			try {
				await c.env.kv.put(COS_USAGE_CACHE_KEY, JSON.stringify(usage), { expirationTtl: COS_USAGE_CACHE_TTL });
			} catch (e) {
				console.error('COS usage cache write error:', e);
			}
		}

		return usage;
	}
}

export default s3Service
