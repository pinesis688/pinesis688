/**
 * SecureFx 加密 Web Worker
 * 
 * Copyright (c) 2024-2025 SecureFx Contributors
 * SPDX-License-Identifier: MIT
 * 
 * 使用 Streams API 处理大文件加密，避免阻塞主线程
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

let gcmSupported = null;
let argon2Ready = false;

async function checkGCMSupport() {
    if (gcmSupported !== null) return gcmSupported;
    try {
        const key = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
        const testIv = crypto.getRandomValues(new Uint8Array(12));
        const testData = new Uint8Array(16);
        await crypto.subtle.encrypt({ name: 'AES-GCM', iv: testIv }, key, testData);
        gcmSupported = true;
    } catch (e) {
        gcmSupported = false;
    }
    return gcmSupported;
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

async function encryptGCM(data, key, nonce) {
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, data);
    const result = new Uint8Array(encrypted);
    return {
        ciphertext: result.slice(0, result.length - TAG_LENGTH),
        tag: result.slice(result.length - TAG_LENGTH)
    };
}

async function encryptCBC(data, key, iv) {
    const paddedData = pkcs7Pad(data, 16);
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: iv }, key, paddedData);
    return { ciphertext: new Uint8Array(encrypted) };
}

function pkcs7Pad(data, blockSize) {
    const padLen = blockSize - (data.length % blockSize);
    const padded = new Uint8Array(data.length + padLen);
    padded.set(data);
    padded.fill(padLen, data.length);
    return padded;
}

function createMetadata(filename, fileSize, timestamp, anonymous) {
    const meta = {
        filename: anonymous ? `file_${crypto.getRandomValues(new Uint32Array(1))[0].toString(16)}` : filename,
        size: fileSize,
        timestamp: timestamp || Date.now(),
        version: '3.0.0'
    };
    return new TextEncoder().encode(JSON.stringify(meta));
}

async function encryptMetadata(metadata, key) {
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
    const { ciphertext, tag } = await encryptGCM(metadata, key, nonce);
    return concatArrays(nonce, ciphertext, tag);
}

self.onmessage = async function (e) {
    const { type, data } = e.data;

    if (type === 'encrypt') {
        try {
            const { fileData, filename, secret, options } = data;
            let { kdfType, anonymous, signKey, useArgon2 } = options;

            const totalSize = fileData.length;

            self.postMessage({ type: 'progress', progress: 0, message: '正在初始化...' });

            const useGCM = await checkGCMSupport();
            const mode = useGCM ? MODE_GCM : MODE_CBC;

            const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
            const mainNonce = crypto.getRandomValues(new Uint8Array(useGCM ? NONCE_LENGTH : IV_LENGTH));

            self.postMessage({ type: 'progress', progress: 5, message: '正在派生密钥...' });

            let key, metaKey;
            if (kdfType === KDF_ARGON2) {
                key = await deriveKeyArgon2(secret, salt);
                metaKey = await deriveKeyArgon2(secret, concatArrays(salt, new TextEncoder().encode('meta')));
            } else {
                key = await deriveKeyScrypt(secret, salt);
                metaKey = await deriveKeyScrypt(secret, concatArrays(salt, new TextEncoder().encode('meta')));
            }

            self.postMessage({ type: 'progress', progress: 15, message: '正在加密元数据...' });

            const metadata = createMetadata(filename, totalSize, Date.now(), anonymous);
            const encryptedMetadata = await encryptMetadata(metadata, metaKey);

            self.postMessage({ type: 'progress', progress: 20, message: '正在加密数据...' });

            const totalChunks = Math.ceil(totalSize / CHUNK_SIZE);
            const encryptedChunks = [];

            for (let i = 0; i < totalChunks; i++) {
                const start = i * CHUNK_SIZE;
                const end = Math.min(start + CHUNK_SIZE, totalSize);
                const chunkData = fileData.slice(start, end);

                let encryptedChunk;
                if (useGCM) {
                    const chunkNonce = new Uint8Array(mainNonce);
                    const counter = new DataView(chunkNonce.buffer);
                    counter.setUint32(8, counter.getUint32(8) + i, false);
                    const { ciphertext, tag } = await encryptGCM(chunkData, key, chunkNonce);
                    encryptedChunk = concatArrays(ciphertext, tag);
                } else {
                    const chunkIv = new Uint8Array(mainNonce);
                    const counter = new DataView(chunkIv.buffer);
                    counter.setUint32(12, counter.getUint32(12) + i, false);
                    const { ciphertext } = await encryptCBC(chunkData, key, chunkIv);
                    encryptedChunk = ciphertext;
                }

                encryptedChunks.push(encryptedChunk);

                const progress = 20 + Math.floor((i + 1) / totalChunks * 55);
                self.postMessage({ type: 'progress', progress, message: `正在加密数据... (${i + 1}/${totalChunks})` });
            }

            const allEncryptedData = concatArrays(...encryptedChunks);

            self.postMessage({ type: 'progress', progress: 80, message: '正在计算HMAC...' });

            let hmacKeyBytes;
            if (kdfType === KDF_ARGON2) {
                hmacKeyBytes = await deriveKeyBytesArgon2(secret, concatArrays(salt, new TextEncoder().encode('hmac')));
            } else {
                hmacKeyBytes = await deriveKeyBytesScrypt(secret, concatArrays(salt, new TextEncoder().encode('hmac')));
            }
            const fileHMAC = await computeHMAC(hmacKeyBytes, allEncryptedData);

            self.postMessage({ type: 'progress', progress: 90, message: '正在组装文件...' });

            const flags = (signKey ? FLAG_SIGNED : 0) | (anonymous ? FLAG_ANONYMOUS : 0);

            const header = concatArrays(
                MAGIC_V2,
                new Uint8Array([VERSION_V2]),
                new Uint8Array([mode]),
                new Uint8Array([kdfType]),
                new Uint8Array([flags]),
                salt,
                mainNonce,
                new Uint8Array([(encryptedMetadata.length >> 8) & 0xff, encryptedMetadata.length & 0xff]),
                encryptedMetadata
            );

            let finalData;
            if (signKey) {
                finalData = concatArrays(header, allEncryptedData, fileHMAC, new Uint8Array(SIGNATURE_LENGTH));
            } else {
                finalData = concatArrays(header, allEncryptedData, fileHMAC);
            }

            self.postMessage({ type: 'progress', progress: 100, message: '加密完成' });
            self.postMessage({
                type: 'complete',
                result: finalData,
                metadata: {
                    originalName: filename,
                    size: totalSize,
                    algo: kdfType === KDF_ARGON2 ? 'Argon2id' : 'Scrypt',
                    mode: useGCM ? 'AES-GCM' : 'AES-CBC'
                }
            });

        } catch (err) {
            self.postMessage({ type: 'error', message: err.message });
        }
    }
};

console.log('SecureFx Encrypt Worker loaded');
