const encoder = new TextEncoder();

const saltHashUtils = {

	generateSalt(length = 16) {
		const array = new Uint8Array(length);
		crypto.getRandomValues(array);
		return btoa(String.fromCharCode(...array));
	},


	async hashPassword(password) {
		const salt = this.generateSalt();
		const hash = await this.genHashPassword(password, salt);
		return { salt, hash };
	},

	async genHashPassword(password, salt) {
		const data = encoder.encode(salt + password);
		const hashBuffer = await crypto.subtle.digest('SHA-256', data);
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		return btoa(String.fromCharCode(...hashArray));
	},

	async verifyPassword(inputPassword, salt, storedHash) {
		const hash = await this.genHashPassword(inputPassword, salt);
		return hash === storedHash;
	},

	genRandomPwd(length = 8) {
		const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		// 安全：拒绝采样消除取模偏差 —— 只接受 < limit 的随机字节，超出区间的丢弃重取
		const limit = Math.floor(256 / chars.length) * chars.length;
		let result = '';
		while (result.length < length) {
			// 一次多取一些字节，减少 getRandomValues 调用次数
			const arr = new Uint8Array(Math.max(length * 2, 8));
			crypto.getRandomValues(arr);
			for (let i = 0; i < arr.length && result.length < length; i++) {
				if (arr[i] < limit) {
					result += chars.charAt(arr[i] % chars.length);
				}
			}
		}
		return result;
	}
};

export default saltHashUtils;
