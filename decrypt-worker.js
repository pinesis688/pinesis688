/**
 * SecureFx 解密 Web Worker
 * 
 * Copyright (c) 2024-2025 SecureFx Contributors
 * SPDX-License-Identifier: MIT
 * 
 * 使用 Streams API 处理大文件解密，避免阻塞主线程
 */

importScripts('argon2-bundled.min.js');

const MAGIC_V2 = new Uint8Array([0x43, 0x56, 0x4C, 0x54, 0x76, 0x33]);
const VERSION_V2 = 0x02;
const SALT_LENGTH = 32;
const NONCE_LENGTH = 12;
const IV_LENGTH = 16;
const KEY_LENGTH = 32;
const HMAC_LENGTH = 32;
const TAG_LENGTH = 16;
const SIGNATURE_LENGTH = 64;
const CHUNK_SIZE = 10 * 1024 * 1024;
const KDF_ARGON2 = 1;
const KDF_SCRYPT = 2;
const MODE_GCM = 1;
const MODE_CBC = 2;
const FLAG_SIGNED = 0x01;
const FLAG_ANONYMOUS = 0x02;
const ARGON2_TIME = 3;
const ARGON2_MEM = 65536;
const ARGON2_PARALLELISM = 4;

function constantTimeCompare(a, b) {
    if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
    }
    return result === 0;
}

async function deriveKeyScrypt(secret, salt) {
    const secretBytes = typeof secret === 'string' ? new TextEncoder().encode(secret) : secret;
    const keyMaterial = await crypto.subtle.importKey('raw', secretBytes, 'PBKDF2', false, ['deriveBits', 'deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: 262144, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function deriveKeyBytesScrypt(secret, salt) {
    const secretBytes = typeof secret === 'string' ? new TextEncoder().encode(secret) : secret;
    const keyMaterial = await crypto.subtle.importKey('raw', secretBytes, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: salt, iterations: 262144, hash: 'SHA-256' },
        keyMaterial,
        KEY_LENGTH * 8
    );
    return new Uint8Array(bits);
}

function arrayToBase64(arr) {
    let binary = '';
    for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i]);
    return btoa(binary);
}

async function deriveKeyArgon2(secret, salt) {
    const secretStr = typeof secret === 'string' ? secret : arrayToBase64(secret);
    const saltB64 = arrayToBase64(salt);
    const result = await argon2.hash({
        pass: secretStr,
        salt: saltB64,
        time: ARGON2_TIME,
        mem: ARGON2_MEM,
        parallelism: ARGON2_PARALLELISM,
        hashLen: KEY_LENGTH,
        type: argon2.ArgonType.Argon2id
    });
    return crypto.subtle.importKey('raw', result.hash, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function deriveKeyBytesArgon2(secret, salt) {
    const secretStr = typeof secret === 'string' ? secret : arrayToBase64(secret);
    const saltB64 = arrayToBase64(salt);
    const result = await argon2.hash({
        pass: secretStr,
        salt: saltB64,
        time: ARGON2_TIME,
        mem: ARGON2_MEM,
        parallelism: ARGON2_PARALLELISM,
        hashLen: KEY_LENGTH,
        type: argon2.ArgonType.Argon2id
    });
    return new Uint8Array(result.hash);
}

function concatArrays(...arrays) {
    const totalLen = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

async function computeHMAC(key, data) {
    const hmacKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', hmacKey, data);
    return new Uint8Array(signature);
}

async function decryptGCM(ciphertext, tag, key, nonce) {
    const combined = new Uint8Array(ciphertext.length + tag.length);
    combined.set(ciphertext);
    combined.set(tag, ciphertext.length);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, combined);
    return new Uint8Array(decrypted);
}

async function decryptCBC(ciphertext, key, iv) {
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: iv }, key, ciphertext);
    return pkcs7Unpad(new Uint8Array(decrypted));
}

function pkcs7Unpad(data) {
    if (!data || data.length === 0) {
        throw new Error('无效的数据');
    }
    const padLen = data[data.length - 1];
    if (padLen < 1 || padLen > 16 || padLen > data.length) {
        throw new Error('无效的PKCS7填充');
    }
    for (let i = data.length - padLen; i < data.length; i++) {
        if (data[i] !== padLen) {
            throw new Error('无效的PKCS7填充');
        }
    }
    return data.slice(0, data.length - padLen);
}

async function decryptMetadata(encryptedMetadata, key) {
    const nonce = encryptedMetadata.slice(0, NONCE_LENGTH);
    const ciphertext = encryptedMetadata.slice(NONCE_LENGTH, encryptedMetadata.length - TAG_LENGTH);
    const tag = encryptedMetadata.slice(encryptedMetadata.length - TAG_LENGTH);
    const decrypted = await decryptGCM(ciphertext, tag, key, nonce);
    return JSON.parse(new TextDecoder().decode(decrypted));
}

self.onmessage = async function (e) {
    const { type, data } = e.data;

    if (type === 'decrypt') {
        try {
            const { fileData, secret } = data;

            const minLen = MAGIC_V2.length + 4 + SALT_LENGTH + NONCE_LENGTH + 2 + HMAC_LENGTH;
            if (!fileData || fileData.length < minLen) {
                self.postMessage({ type: 'error', message: '无效的加密文件：文件太短' });
                return;
            }

            self.postMessage({ type: 'progress', progress: 0, message: '正在解析文件头...' });

            let offset = 0;
            const magic = fileData.slice(0, MAGIC_V2.length);
            offset += MAGIC_V2.length;

            const isV2 = constantTimeCompare(magic, MAGIC_V2);
            if (!isV2) {
                self.postMessage({ type: 'error', message: '不支持的文件格式，请使用v2格式' });
                return;
            }

            const version = fileData[offset++];
            const mode = fileData[offset++];
            const kdfType = fileData[offset++];
            const flags = fileData[offset++];

            self.postMessage({ type: 'progress', progress: 5, message: '正在读取加密参数...' });

            const salt = fileData.slice(offset, offset + SALT_LENGTH);
            offset += SALT_LENGTH;

            const nonceLen = mode === MODE_GCM ? NONCE_LENGTH : IV_LENGTH;
            if (offset + nonceLen + 2 > fileData.length) {
                self.postMessage({ type: 'error', message: '无效的加密文件：头部损坏' });
                return;
            }
            const mainNonce = fileData.slice(offset, offset + nonceLen);
            offset += nonceLen;

            const metaLen = (fileData[offset] << 8) | fileData[offset + 1];
            offset += 2;

            if (offset + metaLen > fileData.length) {
                self.postMessage({ type: 'error', message: '无效的加密文件：元数据损坏' });
                return;
            }
            const encryptedMetadata = fileData.slice(offset, offset + metaLen);
            offset += metaLen;

            const hasSignature = flags & FLAG_SIGNED;

            let encryptedDataEnd = fileData.length - HMAC_LENGTH;
            if (hasSignature) {
                encryptedDataEnd -= SIGNATURE_LENGTH;
            }

            const encryptedData = fileData.slice(offset, encryptedDataEnd);
            const storedHMAC = fileData.slice(encryptedDataEnd, encryptedDataEnd + HMAC_LENGTH);

            self.postMessage({ type: 'progress', progress: 10, message: '正在派生密钥...' });

            let hmacKeyBytes;
            if (kdfType === KDF_ARGON2) {
                hmacKeyBytes = await deriveKeyBytesArgon2(secret, concatArrays(salt, new TextEncoder().encode('hmac')));
            } else {
                hmacKeyBytes = await deriveKeyBytesScrypt(secret, concatArrays(salt, new TextEncoder().encode('hmac')));
            }

            self.postMessage({ type: 'progress', progress: 25, message: '正在验证HMAC...' });

            const computedHMAC = await computeHMAC(hmacKeyBytes, encryptedData);

            if (!constantTimeCompare(storedHMAC, computedHMAC)) {
                self.postMessage({ type: 'error', message: 'HMAC验证失败：文件可能被篡改或密码错误' });
                return;
            }

            let key, metaKey;
            if (kdfType === KDF_ARGON2) {
                key = await deriveKeyArgon2(secret, salt);
                metaKey = await deriveKeyArgon2(secret, concatArrays(salt, new TextEncoder().encode('meta')));
            } else {
                key = await deriveKeyScrypt(secret, salt);
                metaKey = await deriveKeyScrypt(secret, concatArrays(salt, new TextEncoder().encode('meta')));
            }

            self.postMessage({ type: 'progress', progress: 35, message: '正在解密元数据...' });

            let metadata;
            try {
                metadata = await decryptMetadata(encryptedMetadata, metaKey);
            } catch (err) {
                self.postMessage({ type: 'error', message: '元数据解密失败：密码错误' });
                return;
            }

            self.postMessage({ type: 'progress', progress: 40, message: '正在解密数据...' });

            const useGCM = mode === MODE_GCM;
            const chunkSize = CHUNK_SIZE + TAG_LENGTH;
            const totalChunks = Math.ceil(encryptedData.length / chunkSize);

            const decryptedChunks = [];
            for (let i = 0; i < totalChunks; i++) {
                const chunkStart = i * chunkSize;
                const chunkEnd = Math.min(chunkStart + chunkSize, encryptedData.length);
                const chunk = encryptedData.slice(chunkStart, chunkEnd);

                if (useGCM) {
                    const ciphertext = chunk.slice(0, chunk.length - TAG_LENGTH);
                    const tag = chunk.slice(chunk.length - TAG_LENGTH);
                    const chunkNonce = new Uint8Array(mainNonce);
                    const counter = new DataView(chunkNonce.buffer);
                    counter.setUint32(8, counter.getUint32(8) + i, false);

                    try {
                        decryptedChunks.push(await decryptGCM(ciphertext, tag, key, chunkNonce));
                    } catch (e) {
                        self.postMessage({ type: 'error', message: '解密失败：认证标签验证失败' });
                        return;
                    }
                } else {
                    const chunkIv = new Uint8Array(mainNonce);
                    const counter = new DataView(chunkIv.buffer);
                    counter.setUint32(12, counter.getUint32(12) + i, false);
                    try {
                        decryptedChunks.push(await decryptCBC(chunk, key, chunkIv));
                    } catch (e) {
                        self.postMessage({ type: 'error', message: '解密失败：可能是密码错误' });
                        return;
                    }
                }

                const progress = 40 + Math.floor((i + 1) / totalChunks * 50);
                self.postMessage({ type: 'progress', progress, message: `正在解密数据... (${i + 1}/${totalChunks})` });
            }

            self.postMessage({ type: 'progress', progress: 95, message: '正在验证数据...' });

            const totalSize = decryptedChunks.reduce((sum, chunk) => sum + chunk.length, 0);
            const result = new Uint8Array(totalSize);
            let resultOffset = 0;
            for (const chunk of decryptedChunks) {
                result.set(chunk, resultOffset);
                resultOffset += chunk.length;
            }

            if (metadata.size && result.length !== metadata.size) {
                console.warn(`文件大小不匹配: 期望 ${metadata.size}, 实际 ${result.length}`);
            }

            self.postMessage({ type: 'progress', progress: 100, message: '解密完成' });

            self.postMessage({
                type: 'complete',
                result: result,
                metadata: metadata,
                hasSignature: hasSignature
            });

        } catch (err) {
            self.postMessage({ type: 'error', message: err.message });
        }
    }
};

console.log('SecureFx Decrypt Worker loaded');
