/**
 * SecureFx 加密工具箱
 * 
 * Copyright (c) 2024-2025 SecureFx Contributors
 * SPDX-License-Identifier: MIT
 * 
 * 功能概述：
 * - 对称加密（AES-GCM + Argon2id/Scrypt）
 * - 混合加密（RSA/ECC + AES会话密钥）
 * - 数字签名（ECDSA-SHA256）
 * - 文件完整性校验（HMAC-SHA256）
 * - 元数据加密（隐私保护）
 * - 密钥管理中心
 * - 古典密码与趣味编码
 * 
 * 安全模型：CIA三元组（Confidentiality, Integrity, Authenticity）
 * 
 * @author SecureFx Team
 * @version 3.0.0
 * @license MIT
 */

(function () {
    'use strict';

    /* ============================================
       安全工具函数 - 恒定时间比较与最佳努力内存清理
       
       ⚠️ 重要安全说明：
       JavaScript是内存安全语言，具有自动垃圾回收机制。
       以下内存清理函数仅为"最佳努力"清理，无法保证：
       1. 底层JS引擎（V8/SpiderMonkey）是否已复制数据
       2. 垃圾回收器移动对象时留下的残留
       3. 字符串常量池中的不可变副本
       4. 操作系统级别的内存页缓存
       
       在JavaScript环境中，真正的安全内存擦除是不可能的。
       如需处理高敏感数据，请使用原生应用程序。
       ============================================ */

    /**
     * 尝试清理内存中的敏感数据
     * 注意：此函数仅为最佳努力，无法保证完全擦除
     * @param {Uint8Array|ArrayBuffer} buffer - 要清理的缓冲区
     * @returns {void}
     */
    function attemptMemoryClear(buffer) {
        try {
            if (buffer instanceof Uint8Array) {
                for (let i = 0; i < buffer.length; i++) {
                    buffer[i] = 0;
                }
            } else if (buffer instanceof ArrayBuffer) {
                const view = new Uint8Array(buffer);
                for (let i = 0; i < view.length; i++) {
                    view[i] = 0;
                }
            }
        } catch (e) {
            console.warn('内存清理失败:', e);
        }
    }

    function constantTimeCompare(a, b) {
        if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
            return false;
        }
        if (a.length !== b.length) {
            return false;
        }
        let result = 0;
        for (let i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result === 0;
    }

    /* ============================================
       输入验证函数
       ============================================ */

    function isValidPEM(pem) {
        if (!pem || typeof pem !== 'string') return false;
        const trimmed = pem.trim();
        if (trimmed.length < 100) return false;
        const hasBegin = trimmed.includes('-----BEGIN');
        const hasEnd = trimmed.includes('-----END');
        return hasBegin && hasEnd;
    }

    function validatePEM(pem, label = 'KEY') {
        if (!isValidPEM(pem)) {
            throw new Error(`无效的${label}格式，请检查PEM编码`);
        }
    }

    function sanitizeInput(text) {
        if (text == null) return '';
        return String(text).trim();
    }

    /* ============================================
       错误码系统 - 清晰的错误分类
       ============================================ */
    const ERROR_CODES = {
        E1001: { code: 'E1001', category: '加密', message: 'Argon2库未加载', detail: 'Argon2库加载失败，请刷新页面或使用Scrypt算法' },
        E1002: { code: 'E1002', category: '加密', message: '密钥派生失败', detail: '密钥派生过程中发生错误，可能是内存不足或参数无效' },
        E1003: { code: 'E1003', category: '加密', message: 'AES加密失败', detail: 'AES加密操作失败，可能是密钥无效或数据损坏' },
        E1004: { code: 'E1004', category: '加密', message: '文件读取失败', detail: '无法读取文件内容，请检查文件是否存在' },
        E1005: { code: 'E1005', category: '加密', message: 'Worker初始化失败', detail: '无法创建Web Worker，请刷新页面重试' },
        E1006: { code: 'E1006', category: '加密', message: '签名失败', detail: '数字签名过程中发生错误，请检查私钥格式' },

        E2001: { code: 'E2001', category: '解密', message: '文件格式无效', detail: '加密文件格式不正确或已损坏' },
        E2002: { code: 'E2002', category: '解密', message: 'HMAC验证失败', detail: '文件完整性校验失败，文件可能被篡改或密码错误' },
        E2003: { code: 'E2003', category: '解密', message: '密码错误', detail: '解密密码不正确' },
        E2004: { code: 'E2004', category: '解密', message: 'AES解密失败', detail: 'AES解密操作失败，可能是密钥无效或数据损坏' },
        E2005: { code: 'E2005', category: '解密', message: '元数据解密失败', detail: '无法解密文件元数据，密码可能错误' },
        E2006: { code: 'E2006', category: '解密', message: '签名验证失败', detail: '数字签名验证失败，文件可能被篡改' },
        E2007: { code: 'E2007', category: '解密', message: 'Argon2不支持', detail: 'Worker模式不支持Argon2加密文件，请使用小文件模式' },

        E3001: { code: 'E3001', category: '密钥', message: '密钥格式无效', detail: '密钥格式不正确，请检查输入' },
        E3002: { code: 'E3002', category: '密钥', message: '密钥生成失败', detail: '密钥生成过程中发生错误' },
        E3003: { code: 'E3003', category: '密钥', message: '密钥导入失败', detail: '无法导入密钥，格式可能不正确' },

        E4001: { code: 'E4001', category: '文件', message: '文件太小', detail: '加密文件太小，不是有效的加密文件' },
        E4002: { code: 'E4002', category: '文件', message: '文件头损坏', detail: '加密文件头部信息损坏' },
        E4003: { code: 'E4003', category: '文件', message: '元数据损坏', detail: '加密文件元数据部分损坏' },
        E4004: { code: 'E4004', category: '文件', message: '不支持的版本', detail: '加密文件版本不支持，请更新软件' },

        E5001: { code: 'E5001', category: '系统', message: '内存不足', detail: '系统内存不足，无法完成操作' },
        E5002: { code: 'E5002', category: '系统', message: '操作超时', detail: '操作超时，请重试' },
        E5003: { code: 'E5003', category: '系统', message: '浏览器不支持', detail: '浏览器不支持此功能，请使用现代浏览器' },
        E5004: { code: 'E5004', category: '系统', message: '未知错误', detail: '发生未知错误，请查看控制台获取详细信息' }
    };

    function getErrorByCode(code) {
        return ERROR_CODES[code] || ERROR_CODES.E5004;
    }

    function mapErrorToCode(error) {
        const msg = error.message || '';
        const name = error.name || '';

        if (msg.includes('Argon2') || msg.includes('argon2')) return 'E1001';
        if (msg.includes('密钥派生') || msg.includes('deriveKey')) return 'E1002';
        if (msg.includes('AES') && msg.includes('加密')) return 'E1003';
        if (msg.includes('读取') || msg.includes('read')) return 'E1004';
        if (msg.includes('Worker') || msg.includes('worker')) return 'E1005';
        if (msg.includes('签名') && !msg.includes('验证')) return 'E1006';

        if (msg.includes('文件格式') || msg.includes('格式无效')) return 'E2001';
        if (msg.includes('HMAC') || msg.includes('完整性')) return 'E2002';
        if (msg.includes('密码错误') || msg.includes('密码不正确')) return 'E2003';
        if (msg.includes('AES') && msg.includes('解密')) return 'E2004';
        if (msg.includes('元数据') && msg.includes('解密')) return 'E2005';
        if (msg.includes('签名') && msg.includes('验证')) return 'E2006';
        if (msg.includes('Argon2') && msg.includes('不支持')) return 'E2007';

        if (msg.includes('密钥格式') || msg.includes('无效的密钥')) return 'E3001';
        if (msg.includes('密钥生成')) return 'E3002';
        if (msg.includes('密钥导入')) return 'E3003';

        if (msg.includes('文件太短') || msg.includes('太小')) return 'E4001';
        if (msg.includes('头部') || msg.includes('头损坏')) return 'E4002';
        if (msg.includes('元数据损坏')) return 'E4003';
        if (msg.includes('版本') || msg.includes('不支持')) return 'E4004';

        if (name === 'QuotaExceededError' || msg.includes('内存')) return 'E5001';
        if (name === 'TimeoutError' || msg.includes('超时')) return 'E5002';
        if (name === 'NotSupportedError') return 'E5003';

        return 'E5004';
    }

    let errorLogCounter = 0;
    const errorLogMap = new Map();

    function secureError(originalError) {
        const errorCode = mapErrorToCode(originalError);
        const errorInfo = getErrorByCode(errorCode);
        const logId = `LOG-${++errorLogCounter}`;

        errorLogMap.set(logId, {
            timestamp: new Date().toISOString(),
            code: errorCode,
            category: errorInfo.category,
            message: errorInfo.message,
            detail: errorInfo.detail,
            originalMessage: originalError.message,
            originalStack: originalError.stack
        });

        console.error(`[SecureFx Error ${logId}]`, {
            code: errorCode,
            category: errorInfo.category,
            message: errorInfo.message,
            detail: errorInfo.detail,
            originalError: originalError
        });

        return new Error(`${errorInfo.message}（${errorCode}）`);
    }

    function getErrorLogStats() {
        const stats = { total: errorLogMap.size, byCategory: {}, byCode: {} };
        errorLogMap.forEach((log) => {
            stats.byCategory[log.category] = (stats.byCategory[log.category] || 0) + 1;
            stats.byCode[log.code] = (stats.byCode[log.code] || 0) + 1;
        });
        return stats;
    }

    function getRecentErrors(count = 10) {
        const errors = Array.from(errorLogMap.entries()).slice(-count);
        return errors.map(([id, log]) => ({ id, ...log }));
    }

    /* ============================================
       威胁模型显性化警告
       ============================================ */

    function showSecurityWarning() {
        return new Promise((resolve) => {
            const overlay = document.getElementById('securityModalOverlay');
            if (!overlay) {
                resolve(true);
                return;
            }

            if (localStorage.getItem('securefx_risk_acknowledged')) {
                overlay.classList.remove('active');
                resolve(true);
                return;
            }

            const checkInterval = setInterval(() => {
                if (!overlay.classList.contains('active')) {
                    clearInterval(checkInterval);
                    resolve(true);
                }
            }, 100);

            setTimeout(() => {
                clearInterval(checkInterval);
                resolve(true);
            }, 300000);
        });
    }

    /* ============================================
       操作审计日志
       
       隐私说明：
       - 默认关闭审计日志（隐私优先）
       - 用户可在设置中启用审计日志
       - 启用后会记录操作类型和时间（不含敏感数据）
       - 关闭标签页时不会自动清除，需手动清除
       ============================================ */

    const AuditLog = {
        DB_NAME: 'SecureFxAudit',
        STORE_NAME: 'logs',
        enabled: false,

        isEnabled() {
            return this.enabled || localStorage.getItem('securefx_audit_enabled') === 'true';
        },

        setEnabled(enabled) {
            this.enabled = enabled;
            localStorage.setItem('securefx_audit_enabled', enabled ? 'true' : 'false');
            if (!enabled) {
                this.clear();
            }
        },

        async init() {
            return new Promise((resolve, reject) => {
                const request = indexedDB.open(this.DB_NAME, 1);
                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve(request.result);
                request.onupgradeneeded = (event) => {
                    const db = event.target.result;
                    if (!db.objectStoreNames.contains(this.STORE_NAME)) {
                        db.createObjectStore(this.STORE_NAME, { keyPath: 'id', autoIncrement: true });
                    }
                };
            });
        },

        async log(action, details) {
            if (!this.isEnabled()) {
                return;
            }
            try {
                const db = await this.init();
                const tx = db.transaction(this.STORE_NAME, 'readwrite');
                const store = tx.objectStore(this.STORE_NAME);
                const safeDetails = { ...details };
                delete safeDetails.password;
                delete safeDetails.key;
                delete safeDetails.secret;
                store.add({
                    time: new Date().toISOString(),
                    action: action,
                    details: safeDetails
                });
            } catch (e) {
                console.warn('审计日志写入失败:', e);
            }
        },

        async getAll() {
            try {
                const db = await this.init();
                const tx = db.transaction(this.STORE_NAME, 'readonly');
                const store = tx.objectStore(this.STORE_NAME);
                return new Promise((resolve, reject) => {
                    const request = store.getAll();
                    request.onsuccess = () => resolve(request.result);
                    request.onerror = () => reject(request.error);
                });
            } catch (e) {
                return [];
            }
        },

        async clear() {
            try {
                const db = await this.init();
                const tx = db.transaction(this.STORE_NAME, 'readwrite');
                const store = tx.objectStore(this.STORE_NAME);
                store.clear();
            } catch (e) {
                console.warn('审计日志清除失败:', e);
            }
        }
    };

    /* ============================================
       常量定义 - 文件格式 v2
       ============================================ */

    const MAGIC_V1 = new Uint8Array([0x53, 0x45, 0x43, 0x55, 0x52, 0x45, 0x46, 0x58]);
    const MAGIC_V2 = new Uint8Array([0x43, 0x56, 0x4C, 0x54, 0x76, 0x33]);

    const VERSION_V1 = 0x01;
    const VERSION_V2 = 0x02;

    const MODE_GCM = 0x01;
    const MODE_CBC = 0x02;
    const MODE_HYBRID_RSA = 0x03;
    const MODE_HYBRID_ECC = 0x04;

    const KDF_ARGON2 = 0x01;
    const KDF_SCRYPT = 0x02;

    const FLAG_SIGNED = 0x01;
    const FLAG_ANONYMOUS = 0x02;
    const FLAG_COMPRESSED = 0x04;

    const CHUNK_SIZE = 10 * 1024 * 1024;
    const SALT_LENGTH = 32;
    const NONCE_LENGTH = 12;
    const IV_LENGTH = 16;
    const KEY_LENGTH = 32;
    const TAG_LENGTH = 16;
    const HMAC_LENGTH = 32;
    const SIGNATURE_LENGTH = 64;

    /* ============================================
       全局状态变量
       ============================================ */

    let gcmSupported = null;
    let argon2Ready = false;
    let currentKdf = KDF_ARGON2;
    let currentMode = 'password';
    let anonymousMode = false;
    let currentKey = null;
    let encryptedBlob = null;
    let encryptedFilename = '';
    let decryptedBlob = null;
    let decryptedFilename = '';
    let keyTimer = null;
    let currentHashAlgo = 'sha256';
    let generatedRSAKeys = null;
    let generatedECCKeys = null;
    let keyStore = {
        encryption: null,
        signing: null
    };

    let operationInProgress = false;
    let keyDisplayActive = false;
    let cancelRequested = false;

    let encryptWorker = null;
    let decryptWorker = null;
    let currentWorker = null;

    const LARGE_FILE_THRESHOLD = 10 * 1024 * 1024;

    /* ============================================
       Web Worker 管理 - 大文件处理优化
       ============================================ */

    function initEncryptWorker() {
        if (encryptWorker) return encryptWorker;
        try {
            if (window.location.protocol === 'file:') {
                console.warn('文件协议不支持Web Worker，将使用主线程处理');
                return null;
            }
            encryptWorker = new Worker('encrypt-worker.js');
            return encryptWorker;
        } catch (e) {
            console.warn('无法创建加密Worker:', e);
            return null;
        }
    }

    function initDecryptWorker() {
        if (decryptWorker) return decryptWorker;
        try {
            if (window.location.protocol === 'file:') {
                console.warn('文件协议不支持Web Worker，将使用主线程处理');
                return null;
            }
            decryptWorker = new Worker('decrypt-worker.js');
            return decryptWorker;
        } catch (e) {
            console.warn('无法创建解密Worker:', e);
            return null;
        }
    }

    function terminateWorkers() {
        if (encryptWorker) {
            encryptWorker.terminate();
            encryptWorker = null;
        }
        if (decryptWorker) {
            decryptWorker.terminate();
            decryptWorker = null;
        }
        currentWorker = null;
    }

    function cancelCurrentOperation() {
        cancelRequested = true;
        if (currentWorker) {
            currentWorker.terminate();
            currentWorker = null;
        }
        operationInProgress = false;
        return true;
    }

    async function encryptFileWithWorker(file, secret, options = {}) {
        return new Promise((resolve, reject) => {
            const worker = initEncryptWorker();
            if (!worker) {
                reject(new Error('无法创建加密Worker'));
                return;
            }

            currentWorker = worker;
            operationInProgress = true;

            worker.onmessage = async function (e) {
                const { type, progress, message, result, metadata, error } = e.data;

                if (type === 'progress') {
                    updateProgress('file', progress, message);
                } else if (type === 'complete') {
                    currentWorker = null;
                    operationInProgress = false;
                    const blob = new Blob([result], { type: 'application/octet-stream' });
                    resolve({ blob, filename: file.name.replace(/\.[^.]+$/, '') + '.sfx', metadata });
                } else if (type === 'error') {
                    currentWorker = null;
                    operationInProgress = false;
                    reject(new Error(error || message));
                }
            };

            worker.onerror = function (e) {
                currentWorker = null;
                operationInProgress = false;
                reject(new Error('Worker错误: ' + e.message));
            };

            file.arrayBuffer().then(buffer => {
                worker.postMessage({
                    type: 'encrypt',
                    data: {
                        fileData: new Uint8Array(buffer),
                        filename: file.name,
                        secret: secret,
                        options: {
                            kdfType: options.kdfType || currentKdf,
                            anonymous: options.anonymous !== undefined ? options.anonymous : anonymousMode,
                            signKey: options.signKey || null,
                            useArgon2: argon2Ready
                        }
                    }
                });
            }).catch(reject);
        });
    }

    async function decryptFileWithWorker(fileData, secret) {
        return new Promise((resolve, reject) => {
            const worker = initDecryptWorker();
            if (!worker) {
                reject(new Error('无法创建解密Worker'));
                return;
            }

            currentWorker = worker;
            operationInProgress = true;

            worker.onmessage = function (e) {
                const { type, progress, message, result, metadata, hasSignature, error } = e.data;

                if (type === 'progress') {
                    updateProgress('file', progress, message);
                } else if (type === 'complete') {
                    currentWorker = null;
                    operationInProgress = false;
                    const blob = new Blob([result], { type: 'application/octet-stream' });
                    resolve({
                        data: blob,
                        originalName: metadata.filename,
                        metadata: metadata,
                        signature: hasSignature ? true : null
                    });
                } else if (type === 'error') {
                    currentWorker = null;
                    operationInProgress = false;
                    reject(new Error(error || message));
                }
            };

            worker.onerror = function (e) {
                currentWorker = null;
                operationInProgress = false;
                reject(new Error('Worker错误: ' + e.message));
            };

            worker.postMessage({
                type: 'decrypt',
                data: {
                    fileData: fileData,
                    secret: secret
                }
            });
        });
    }

    /* ============================================
       Argon2 库加载管理
       ============================================ */

    function waitForArgon2(timeout = 10000) {
        if (argon2Ready) return Promise.resolve(true);
        if (window.argon2LoadPromise) {
            return Promise.race([
                window.argon2LoadPromise.then(loaded => {
                    if (loaded) argon2Ready = true;
                    return loaded;
                }),
                new Promise(resolve => setTimeout(() => resolve(argon2Ready), timeout))
            ]);
        }
        return new Promise((resolve) => {
            const startTime = Date.now();
            function check() {
                if (typeof argon2 !== 'undefined' && argon2.hash) {
                    argon2Ready = true;
                    resolve(true);
                } else if (Date.now() - startTime > timeout) {
                    console.error('Argon2库加载超时');
                    resolve(false);
                } else {
                    setTimeout(check, 100);
                }
            }
            check();
        });
    }

    /* ============================================
       加密功能检测
       ============================================ */

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

    async function checkECCSupport() {
        try {
            const keyPair = await crypto.subtle.generateKey(
                { name: 'ECDSA', namedCurve: 'P-256' },
                false,
                ['sign', 'verify']
            );
            return true;
        } catch (e) {
            return false;
        }
    }

    /* ============================================
       密钥派生函数
       ============================================ */

    async function deriveKeyArgon2(secret, salt) {
        if (!argon2Ready) {
            const loaded = await waitForArgon2();
            if (!loaded) throw new Error('Argon2库未加载，请刷新页面或使用Scrypt算法');
        }
        const secretStr = typeof secret === 'string' ? secret : arrayToBase64(secret);
        const ARGON2_TIME = 3;
        const ARGON2_MEM = 65536;
        const ARGON2_PARALLELISM = 4;
        const result = await argon2.hash({
            pass: secretStr,
            salt: salt,
            time: ARGON2_TIME,
            mem: ARGON2_MEM,
            parallelism: ARGON2_PARALLELISM,
            hashLen: KEY_LENGTH,
            type: argon2.ArgonType.Argon2id
        });
        return crypto.subtle.importKey('raw', result.hash, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    }

    async function deriveKeyScrypt(secret, salt) {
        const secretBytes = typeof secret === 'string' ? new TextEncoder().encode(secret) : secret;
        const keyMaterial = await crypto.subtle.importKey('raw', secretBytes, { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']);
        const derivedBits = await crypto.subtle.deriveBits(
            { name: 'PBKDF2', salt: salt, iterations: 262144, hash: 'SHA-256' },
            keyMaterial,
            KEY_LENGTH * 8
        );
        return crypto.subtle.importKey('raw', derivedBits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    }

    async function deriveKey(secret, salt, kdfType) {
        if (kdfType === KDF_ARGON2) {
            return deriveKeyArgon2(secret, salt);
        }
        return deriveKeyScrypt(secret, salt);
    }

    async function deriveKeyBytes(secret, salt, kdfType) {
        if (kdfType === KDF_ARGON2) {
            if (!argon2Ready) {
                const loaded = await waitForArgon2();
                if (!loaded) throw new Error('Argon2库未加载，请刷新页面或使用Scrypt算法');
            }
            const secretBytes = typeof secret === 'string' ? new TextEncoder().encode(secret) : secret;
            const secretStr = typeof secret === 'string' ? secret : arrayToBase64(secret);
            const ARGON2_TIME = 3;
            const ARGON2_MEM = 65536;
            const ARGON2_PARALLELISM = 4;
            const result = await argon2.hash({
                pass: secretStr,
                salt: salt,
                time: ARGON2_TIME,
                mem: ARGON2_MEM,
                parallelism: ARGON2_PARALLELISM,
                hashLen: KEY_LENGTH,
                type: argon2.ArgonType.Argon2id
            });
            return new Uint8Array(result.hash);
        } else {
            const secretBytes = typeof secret === 'string' ? new TextEncoder().encode(secret) : secret;
            const keyMaterial = await crypto.subtle.importKey('raw', secretBytes, { name: 'PBKDF2' }, false, ['deriveBits']);
            const derivedBits = await crypto.subtle.deriveBits(
                { name: 'PBKDF2', salt: salt, iterations: 262144, hash: 'SHA-256' },
                keyMaterial,
                KEY_LENGTH * 8
            );
            return new Uint8Array(derivedBits);
        }
    }

    /* ============================================
       HMAC计算
       ============================================ */

    async function computeHMAC(key, data) {
        const hmacKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const signature = await crypto.subtle.sign('HMAC', hmacKey, data);
        return new Uint8Array(signature);
    }

    async function verifyHMAC(key, data, signature) {
        const hmacKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
        const result = await crypto.subtle.verify('HMAC', hmacKey, signature, data);
        return result;
    }

    async function verifyHMACConstantTime(key, data, storedHMAC) {
        const computedHMAC = await computeHMAC(key, data);
        return constantTimeCompare(computedHMAC, storedHMAC);
    }

    /* ============================================
       GCM模式加密/解密
       ============================================ */

    async function encryptGCM(data, key, nonce) {
        const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, data);
        const result = new Uint8Array(encrypted);
        return { ciphertext: result.slice(0, result.length - TAG_LENGTH), tag: result.slice(result.length - TAG_LENGTH) };
    }

    async function decryptGCM(ciphertext, tag, key, nonce) {
        const combined = new Uint8Array(ciphertext.length + tag.length);
        combined.set(ciphertext);
        combined.set(tag, ciphertext.length);
        return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, combined));
    }

    /* ============================================
       CBC模式加密/解密
       ============================================ */

    async function encryptCBC(data, encKey, iv) {
        const paddedData = pkcs7Pad(data, 16);
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: iv }, encKey, paddedData));
        return { ciphertext };
    }

    async function decryptCBC(ciphertext, encKey, iv) {
        const decrypted = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv: iv }, encKey, ciphertext));
        return pkcs7Unpad(decrypted);
    }

    /* ============================================
       PKCS7填充
       ============================================ */

    function pkcs7Pad(data, blockSize) {
        const padLen = blockSize - (data.length % blockSize);
        const padded = new Uint8Array(data.length + padLen);
        padded.set(data);
        padded.fill(padLen, data.length);
        return padded;
    }

    function pkcs7Unpad(data) {
        if (!data || data.length === 0) {
            throw new Error('无效的数据');
        }
        const padLen = data[data.length - 1];
        if (padLen < 1 || padLen > 16 || padLen > data.length) {
            throw new Error('无效的PKCS7填充');
        }
        for (let i = 1; i <= padLen; i++) {
            if (data[data.length - i] !== padLen) {
                throw new Error('无效的PKCS7填充');
            }
        }
        return data.slice(0, data.length - padLen);
    }

    /* ============================================
       工具函数
       ============================================ */

    function arrayToBase64(arr) {
        let binary = '';
        for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i]);
        return btoa(binary);
    }

    function base64ToArray(base64) {
        const binary = atob(base64.replace(/\s/g, ''));
        const arr = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) arr[i] = binary.charCodeAt(i);
        return arr;
    }

    function concatArrays(...arrays) {
        const totalLen = arrays.reduce((sum, arr) => sum + arr.length, 0);
        const result = new Uint8Array(totalLen);
        let offset = 0;
        for (const arr of arrays) { result.set(arr, offset); offset += arr.length; }
        return result;
    }

    function formatSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
        return (bytes / 1073741824).toFixed(2) + ' GB';
    }

    function generateRandomKey(length = KEY_LENGTH) {
        return crypto.getRandomValues(new Uint8Array(length));
    }

    window.toggleGuideSection = function (header) {
        const section = header.parentElement;
        section.classList.toggle('collapsed');
    };

    function arrayToHex(arr) {
        return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function hexToArray(hex) {
        const arr = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            arr[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return arr;
    }

    function formatPEM(base64, label) {
        const lines = base64.match(/.{1,64}/g) || [];
        return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
    }

    function parsePEM(pem) {
        const base64 = pem.replace(/-----BEGIN [^-]+-----/, '').replace(/-----END [^-]+-----/, '').replace(/\s/g, '');
        return base64ToArray(base64);
    }

    /* ============================================
       元数据加密 - Phase 1
       
       隐私保护说明：
       - 默认使用匿名文件名（隐私优先）
       - 文件大小和时间戳仍会保留（用于解密验证）
       - 用户可选择保留原始文件名
       ============================================ */

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

    async function decryptMetadata(encryptedMeta, key) {
        const nonce = encryptedMeta.slice(0, NONCE_LENGTH);
        const ciphertext = encryptedMeta.slice(NONCE_LENGTH, encryptedMeta.length - TAG_LENGTH);
        const tag = encryptedMeta.slice(encryptedMeta.length - TAG_LENGTH);
        const decrypted = await decryptGCM(ciphertext, tag, key, nonce);
        return JSON.parse(new TextDecoder().decode(decrypted));
    }

    /* ============================================
       文件加密 v2 - 增强版
       
       ═══════════════════════════════════════════
       加密文件格式规范 (SecureFx v2)
       ═══════════════════════════════════════════
       
       文件扩展名: .sfx
       
       二进制格式布局:
       ┌─────────────────────────────────────────┐
       │ 偏移量    │ 长度      │ 字段            │
       ├─────────────────────────────────────────┤
       │ 0         │ 6         │ 魔术字 CVLTv3   │
       │ 6         │ 1         │ 版本号 (0x02)   │
       │ 7         │ 1         │ 加密模式        │
       │ 8         │ 1         │ KDF类型         │
       │ 9         │ 1         │ 标志位          │
       │ 10        │ 32        │ 盐值            │
       │ 42        │ 12/16     │ Nonce/IV        │
       │ 54/58     │ 2         │ 元数据长度 M    │
       │ 56/60     │ M         │ 加密的元数据    │
       │ 56+M      │ 变长      │ 加密数据        │
       │ EOF-32    │ 32        │ HMAC-SHA256     │
       │ EOF-64    │ 64        │ ECDSA签名(可选) │
       └─────────────────────────────────────────┘
       
       加密模式:
       - 0x01: AES-256-GCM (推荐)
       - 0x02: AES-256-CBC+HMAC (后备)
       
       KDF类型:
       - 0x01: Argon2id (推荐)
       - 0x02: Scrypt/PBKDF2
       
       标志位:
       - 0x01: 已签名
       - 0x02: 匿名模式
       - 0x04: 已压缩(保留)
       
       安全特性:
       - 密钥派生: Argon2id/Scrypt抗暴力破解
       - 完整性: HMAC-SHA256验证
       - 认证: AES-GCM或CBC+HMAC
       - 可选签名: ECDSA-P256
       ═══════════════════════════════════════════
       ============================================ */

    async function encryptFileV2(file, secret, options = {}) {
        const { kdfType = KDF_ARGON2, anonymous = false, signKey = null, onProgress = null } = options;
        const useGCM = await checkGCMSupport();
        const mode = useGCM ? MODE_GCM : MODE_CBC;

        cancelRequested = false;

        if (onProgress) onProgress(5, '正在派生密钥...');

        if (cancelRequested) throw new Error('操作已取消');

        const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
        const mainNonce = crypto.getRandomValues(new Uint8Array(useGCM ? NONCE_LENGTH : IV_LENGTH));
        const metaNonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));

        const key = await deriveKey(secret, salt, kdfType);
        const metaKey = await deriveKey(secret, concatArrays(salt, new TextEncoder().encode('meta')), kdfType);

        if (onProgress) onProgress(10, '正在加密元数据...');

        const metadata = createMetadata(file.name, file.size, Date.now(), anonymous);
        const encryptedMetadata = await encryptMetadata(metadata, metaKey);

        if (onProgress) onProgress(15, '正在加密数据...');

        const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
        const encryptedChunks = [];
        let processedBytes = 0;

        for (let i = 0; i < totalChunks; i++) {
            if (cancelRequested) throw new Error('操作已取消');

            const start = i * CHUNK_SIZE;
            const end = Math.min(start + CHUNK_SIZE, file.size);
            const chunk = file.slice(start, end);
            const chunkData = new Uint8Array(await chunk.arrayBuffer());

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
                const result = await encryptCBC(chunkData, key, chunkIv);
                encryptedChunk = result.ciphertext;
            }

            encryptedChunks.push(encryptedChunk);
            processedBytes += (end - start);

            const progress = 15 + Math.floor((i + 1) / totalChunks * 70);
            if (onProgress) {
                onProgress(progress, `正在加密数据... (${i + 1}/${totalChunks})`);
            }
        }

        if (cancelRequested) throw new Error('操作已取消');

        if (onProgress) onProgress(88, '正在计算HMAC...');

        const allEncryptedData = concatArrays(...encryptedChunks);
        const hmacKeyBytes = await deriveKeyBytes(secret, concatArrays(salt, new TextEncoder().encode('hmac')), kdfType);
        const fileHMAC = await computeHMAC(hmacKeyBytes, allEncryptedData);

        let signature = null;
        if (signKey) {
            if (onProgress) onProgress(92, '正在签名...');
            signature = await signData(allEncryptedData, signKey);
        }

        if (onProgress) onProgress(95, '正在组装文件...');

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
        if (signature) {
            finalData = concatArrays(header, allEncryptedData, fileHMAC, signature);
        } else {
            finalData = concatArrays(header, allEncryptedData, fileHMAC);
        }

        if (onProgress) onProgress(100, '加密完成');

        return {
            blob: new Blob([finalData], { type: 'application/octet-stream' }),
            filename: file.name.replace(/\.[^/.]+$/, '') + '.sfx'
        };
    }

    /* ============================================
       文件解密 v2 - 增强版
       
       安全设计：
       1. 先验证HMAC，确保密文完整性
       2. 再解密元数据和密文
       3. 防止解密炸弹和填充oracle攻击
       ============================================ */

    async function decryptFileV2(fileData, secret, options = {}) {
        const { onProgress = null } = options;
        const minLen = MAGIC_V2.length + 4 + SALT_LENGTH + NONCE_LENGTH + 2 + HMAC_LENGTH;
        if (!fileData || fileData.length < minLen) {
            throw new Error('无效的加密文件：文件太短');
        }

        cancelRequested = false;

        if (onProgress) onProgress(5, '正在解析文件头...');

        let offset = 0;

        const magic = fileData.slice(0, MAGIC_V2.length);
        offset += MAGIC_V2.length;

        const isV2 = constantTimeCompare(magic, MAGIC_V2);
        if (!isV2) {
            return decryptFileV1(fileData, secret);
        }

        const version = fileData[offset++];
        const mode = fileData[offset++];
        const kdfType = fileData[offset++];
        const flags = fileData[offset++];

        if (onProgress) onProgress(10, '正在读取加密参数...');

        const salt = fileData.slice(offset, offset + SALT_LENGTH);
        offset += SALT_LENGTH;

        const nonceLen = mode === MODE_GCM ? NONCE_LENGTH : IV_LENGTH;
        if (offset + nonceLen + 2 > fileData.length) {
            throw new Error('无效的加密文件：头部损坏');
        }
        const mainNonce = fileData.slice(offset, offset + nonceLen);
        offset += nonceLen;

        const metaLen = (fileData[offset] << 8) | fileData[offset + 1];
        offset += 2;

        if (offset + metaLen > fileData.length) {
            throw new Error('无效的加密文件：元数据损坏');
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

        if (onProgress) onProgress(15, '正在派生密钥...');

        const hmacKeyBytes = await deriveKeyBytes(secret, concatArrays(salt, new TextEncoder().encode('hmac')), kdfType);

        if (onProgress) onProgress(25, '正在验证HMAC...');

        const computedHMAC = await computeHMAC(hmacKeyBytes, encryptedData);

        if (!constantTimeCompare(storedHMAC, computedHMAC)) {
            throw new Error('HMAC验证失败：文件可能被篡改');
        }

        const key = await deriveKey(secret, salt, kdfType);
        const metaKey = await deriveKey(secret, concatArrays(salt, new TextEncoder().encode('meta')), kdfType);

        if (onProgress) onProgress(35, '正在解密元数据...');

        let metadata;
        try {
            metadata = await decryptMetadata(encryptedMetadata, metaKey);
        } catch (e) {
            throw new Error('元数据解密失败：密码错误');
        }

        if (onProgress) onProgress(40, '正在解密数据...');

        const useGCM = mode === MODE_GCM;
        const chunkSize = CHUNK_SIZE + TAG_LENGTH;
        const totalChunks = Math.ceil(encryptedData.length / chunkSize);

        const decryptedChunks = [];
        for (let i = 0; i < totalChunks; i++) {
            if (cancelRequested) throw new Error('操作已取消');

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
                    throw new Error('解密失败：认证标签验证失败');
                }
            } else {
                const chunkIv = new Uint8Array(mainNonce);
                const counter = new DataView(chunkIv.buffer);
                counter.setUint32(12, counter.getUint32(12) + i, false);
                try {
                    decryptedChunks.push(await decryptCBC(chunk, key, chunkIv));
                } catch (e) {
                    throw new Error('解密失败：可能是密码错误');
                }
            }

            const progress = 40 + Math.floor((i + 1) / totalChunks * 50);
            if (onProgress) {
                onProgress(progress, `正在解密数据... (${i + 1}/${totalChunks})`);
            }
        }

        if (cancelRequested) throw new Error('操作已取消');

        if (onProgress) onProgress(95, '正在验证数据...');

        const totalSize = decryptedChunks.reduce((sum, chunk) => sum + chunk.length, 0);
        const result = new Uint8Array(totalSize);
        let resultOffset = 0;
        for (const chunk of decryptedChunks) {
            result.set(chunk, resultOffset);
            resultOffset += chunk.length;
        }

        if (onProgress) onProgress(100, '解密完成');

        let signatureResult = null;
        if (hasSignature) {
            const signature = fileData.slice(encryptedDataEnd + HMAC_LENGTH);
            signatureResult = {
                signature: signature,
                verified: null
            };
        }

        return {
            data: new Blob([result], { type: 'application/octet-stream' }),
            originalName: metadata.filename,
            metadata: metadata,
            signature: signatureResult
        };
    }

    /* ============================================
       V1兼容解密
       ============================================ */

    async function decryptFileV1(fileData, secret) {
        const minHeaderLen = MAGIC_V1.length + 3 + SALT_LENGTH + NONCE_LENGTH + 1;
        if (fileData.length < minHeaderLen) throw new Error('无效的加密文件格式');

        let offset = MAGIC_V1.length;
        const version = fileData[offset++];
        const mode = fileData[offset++];
        const kdfType = fileData[offset++];
        const salt = fileData.slice(offset, offset + SALT_LENGTH);
        offset += SALT_LENGTH;

        const key = await deriveKey(secret, salt, kdfType);

        const nonceLen = mode === MODE_GCM ? NONCE_LENGTH : IV_LENGTH;
        const nonce = fileData.slice(offset, offset + nonceLen);
        offset += nonceLen;

        const filenameLen = fileData[offset++];
        let originalName = 'decrypted_file';
        if (filenameLen > 0 && offset + filenameLen <= fileData.length) {
            try {
                originalName = new TextDecoder().decode(fileData.slice(offset, offset + filenameLen));
            } catch (e) { }
        }
        offset += filenameLen;

        const encryptedData = fileData.slice(offset);
        const useGCM = mode === MODE_GCM;

        const decryptedChunks = [];
        if (useGCM) {
            const chunkSize = CHUNK_SIZE + TAG_LENGTH;
            const totalChunks = Math.ceil(encryptedData.length / chunkSize);

            for (let i = 0; i < totalChunks; i++) {
                const chunkStart = i * chunkSize;
                const chunkEnd = Math.min(chunkStart + chunkSize, encryptedData.length);
                const chunk = encryptedData.slice(chunkStart, chunkEnd);
                const ciphertext = chunk.slice(0, chunk.length - TAG_LENGTH);
                const tag = chunk.slice(chunk.length - TAG_LENGTH);
                const chunkNonce = new Uint8Array(nonce);
                const counter = new DataView(chunkNonce.buffer);
                counter.setUint32(8, counter.getUint32(8) + i, false);

                try {
                    decryptedChunks.push(await decryptGCM(ciphertext, tag, key, chunkNonce));
                } catch (e) {
                    throw new Error('解密失败：认证标签验证失败');
                }
            }
        } else {
            const hmacKey = fileData.slice(offset, offset + KEY_LENGTH);
            offset += KEY_LENGTH;
            const storedTag = fileData.slice(offset, offset + TAG_LENGTH);
            offset += TAG_LENGTH;
            const ciphertext = fileData.slice(offset);

            const ivAndCiphertext = concatArrays(nonce, ciphertext);
            const computedTag = await computeHMAC(hmacKey, ivAndCiphertext);
            if (!constantTimeCompare(storedTag, computedTag)) throw new Error('HMAC验证失败');

            const chunkSize = CHUNK_SIZE + 16;
            const totalChunks = Math.ceil(ciphertext.length / chunkSize);

            for (let i = 0; i < totalChunks; i++) {
                const chunkStart = i * chunkSize;
                const chunkEnd = Math.min(chunkStart + chunkSize, ciphertext.length);
                const chunk = ciphertext.slice(chunkStart, chunkEnd);
                const chunkIv = new Uint8Array(nonce);
                const counter = new DataView(chunkIv.buffer);
                counter.setUint32(12, counter.getUint32(12) + i, false);

                try {
                    decryptedChunks.push(await decryptCBC(chunk, key, chunkIv));
                } catch (e) {
                    throw new Error('解密失败：可能是密码错误');
                }
            }
        }

        const totalSize = decryptedChunks.reduce((sum, chunk) => sum + chunk.length, 0);
        const result = new Uint8Array(totalSize);
        let resultOffset = 0;
        for (const chunk of decryptedChunks) {
            result.set(chunk, resultOffset);
            resultOffset += chunk.length;
        }

        return {
            data: new Blob([result], { type: 'application/octet-stream' }),
            originalName: originalName,
            metadata: { version: '1.0' }
        };
    }

    /* ============================================
       ECDSA签名/验证 - Phase 2
       ============================================ */

    async function generateECDSAKeyPair() {
        const keyPair = await crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['sign', 'verify']
        );
        generatedECCKeys = keyPair;

        const publicKeyExported = await crypto.subtle.exportKey('spki', keyPair.publicKey);
        const privateKeyExported = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

        return {
            publicKey: formatPEM(arrayToBase64(new Uint8Array(publicKeyExported)), 'PUBLIC KEY'),
            privateKey: formatPEM(arrayToBase64(new Uint8Array(privateKeyExported)), 'PRIVATE KEY'),
            fingerprint: await getKeyFingerprint(keyPair.publicKey)
        };
    }

    async function getKeyFingerprint(publicKey) {
        const exported = await crypto.subtle.exportKey('spki', publicKey);
        const hash = await crypto.subtle.digest('SHA-256', exported);
        return arrayToHex(new Uint8Array(hash)).substring(0, 32).toUpperCase();
    }

    async function signData(data, privateKey) {
        let key = privateKey;
        if (typeof privateKey === 'string') {
            const keyData = parsePEM(privateKey);
            key = await crypto.subtle.importKey('pkcs8', keyData, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
        }

        const signature = await crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            key,
            data
        );

        return new Uint8Array(signature);
    }

    async function verifySignature(data, signature, publicKey) {
        let key = publicKey;
        if (typeof publicKey === 'string') {
            const keyData = parsePEM(publicKey);
            key = await crypto.subtle.importKey('spki', keyData, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
        }

        return crypto.subtle.verify(
            { name: 'ECDSA', hash: 'SHA-256' },
            key,
            signature,
            data
        );
    }

    /* ============================================
       文件签名 - GPG风格分离签名
       ============================================ */

    const SIGNATURE_MAGIC = new Uint8Array([0x53, 0x49, 0x47, 0x4E]);
    const SIGNATURE_VERSION = 0x01;

    async function signFile(file, privateKeyPEM, publicKeyPEM) {
        const fileData = new Uint8Array(await file.arrayBuffer());
        const signature = await signData(fileData, privateKeyPEM);

        let publicKeyBytes;
        if (publicKeyPEM) {
            publicKeyBytes = parsePEM(publicKeyPEM);
        } else {
            throw new Error('签名需要提供公钥');
        }

        const fileNameBytes = new TextEncoder().encode(file.name);
        const timestamp = Math.floor(Date.now() / 1000);
        const timestampBytes = new Uint8Array(8);
        new DataView(timestampBytes.buffer).setBigUint64(0, BigInt(timestamp), false);

        const header = concatArrays(
            SIGNATURE_MAGIC,
            new Uint8Array([SIGNATURE_VERSION]),
            new Uint8Array([publicKeyBytes.length >> 8, publicKeyBytes.length & 0xff]),
            publicKeyBytes,
            new Uint8Array([fileNameBytes.length]),
            fileNameBytes,
            timestampBytes
        );

        const signatureData = concatArrays(header, signature);

        return {
            blob: new Blob([signatureData], { type: 'application/octet-stream' }),
            filename: file.name + '.sig'
        };
    }

    async function verifyFileSignature(file, signatureFile, publicKeyPEM) {
        const fileData = new Uint8Array(await file.arrayBuffer());
        const sigData = new Uint8Array(await signatureFile.arrayBuffer());

        if (sigData.length < SIGNATURE_MAGIC.length + 1 + 2 + 1 + 8 + SIGNATURE_LENGTH) {
            throw new Error('无效的签名文件：文件太短');
        }

        let offset = 0;
        const magic = sigData.slice(0, SIGNATURE_MAGIC.length);
        offset += SIGNATURE_MAGIC.length;

        const isSignature = constantTimeCompare(magic, SIGNATURE_MAGIC);
        if (!isSignature) {
            throw new Error('无效的签名文件：魔术字不匹配');
        }

        const version = sigData[offset++];
        if (version !== SIGNATURE_VERSION) {
            throw new Error('不支持的签名文件版本');
        }

        const pubKeyLen = (sigData[offset] << 8) | sigData[offset + 1];
        offset += 2;

        if (offset + pubKeyLen + 1 + 8 + SIGNATURE_LENGTH > sigData.length) {
            throw new Error('无效的签名文件：公钥长度错误');
        }

        const embeddedPublicKey = sigData.slice(offset, offset + pubKeyLen);
        offset += pubKeyLen;

        const fileNameLen = sigData[offset++];
        const originalFileName = new TextDecoder().decode(sigData.slice(offset, offset + fileNameLen));
        offset += fileNameLen;

        const timestampBytes = sigData.slice(offset, offset + 8);
        offset += 8;
        const timestamp = Number(new DataView(timestampBytes.buffer).getBigUint64(0, false));

        const signature = sigData.slice(offset);

        let publicKey;
        if (publicKeyPEM) {
            const keyData = parsePEM(publicKeyPEM);
            publicKey = await crypto.subtle.importKey('spki', keyData, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
        } else {
            publicKey = await crypto.subtle.importKey('spki', embeddedPublicKey, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
        }

        const valid = await crypto.subtle.verify(
            { name: 'ECDSA', hash: 'SHA-256' },
            publicKey,
            signature,
            fileData
        );

        return {
            valid,
            originalFileName,
            timestamp: new Date(timestamp * 1000).toLocaleString(),
            signDate: new Date(timestamp * 1000)
        };
    }

    /* ============================================
       混合加密 - Phase 3
       
       ═══════════════════════════════════════════
       混合加密文件格式规范 (SecureFx Hybrid v2)
       ═══════════════════════════════════════════
       
       文件扩展名: .cvlt
       
       二进制格式布局:
       ┌─────────────────────────────────────────┐
       │ 偏移量    │ 长度      │ 字段            │
       ├─────────────────────────────────────────┤
       │ 0         │ 6         │ 魔术字 CVLTv3   │
       │ 6         │ 1         │ 版本号 (0x02)   │
       │ 7         │ 1         │ 模式 (0x03)     │
       │ 8         │ 1         │ KDF类型         │
       │ 9         │ 1         │ 标志位          │
       │ 10        │ 2         │ 加密密钥长度 N  │
       │ 12        │ N         │ RSA加密的会话密钥│
       │ 12+N      │ 12        │ AES-GCM Nonce   │
       │ 24+N      │ 2         │ 元数据长度 M    │
       │ 26+N      │ M         │ 元数据(JSON)    │
       │ 26+N+M    │ 变长      │ AES-GCM密文     │
       │ EOF-16    │ 16        │ AES-GCM认证标签 │
       └─────────────────────────────────────────┘
       
       加密流程:
       1. 生成随机256位AES会话密钥
       2. 使用接收方RSA公钥加密会话密钥 (RSA-OAEP-SHA256)
       3. 使用会话密钥加密文件数据 (AES-256-GCM)
       4. 组装二进制格式输出
       
       安全特性:
       - 前向安全: 每次加密使用新的随机会话密钥
       - 认证加密: AES-GCM提供完整性和真实性保证
       - 密钥封装: RSA-OAEP安全封装会话密钥
       
       注意: 这是自定义格式，不与PKCS#7/CMS或PGP兼容
       ═══════════════════════════════════════════
       ============================================ */

    async function hybridEncrypt(file, recipientPublicKey, options = {}) {
        const sessionKey = generateRandomKey(KEY_LENGTH);
        const sessionKeyCrypto = await crypto.subtle.importKey('raw', sessionKey, { name: 'AES-GCM' }, false, ['encrypt']);

        const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
        const fileData = new Uint8Array(await file.arrayBuffer());
        const { ciphertext, tag } = await encryptGCM(fileData, sessionKeyCrypto, nonce);

        let rsaKey = recipientPublicKey;
        if (typeof recipientPublicKey === 'string') {
            const keyData = parsePEM(recipientPublicKey);
            rsaKey = await crypto.subtle.importKey('spki', keyData, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
        }

        const encryptedSessionKey = new Uint8Array(
            await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaKey, sessionKey)
        );

        const metadata = createMetadata(file.name, file.size, Date.now(), false);
        const encryptedMetadata = new TextEncoder().encode(JSON.stringify(metadata));

        const header = concatArrays(
            MAGIC_V2,
            new Uint8Array([VERSION_V2]),
            new Uint8Array([MODE_HYBRID_RSA]),
            new Uint8Array([KDF_ARGON2]),
            new Uint8Array([0]),
            new Uint8Array([(encryptedSessionKey.length >> 8) & 0xff, encryptedSessionKey.length & 0xff]),
            encryptedSessionKey,
            nonce,
            new Uint8Array([(encryptedMetadata.length >> 8) & 0xff, encryptedMetadata.length & 0xff]),
            encryptedMetadata
        );

        const encryptedData = concatArrays(header, ciphertext, tag);

        return {
            blob: new Blob([encryptedData], { type: 'application/octet-stream' }),
            filename: file.name.replace(/\.[^/.]+$/, '') + '.cvlt'
        };
    }

    async function hybridDecrypt(fileData, privateKey) {
        const minLen = MAGIC_V2.length + 4 + 2 + NONCE_LENGTH + 2 + TAG_LENGTH;
        if (!fileData || fileData.length < minLen) {
            throw new Error('无效的加密文件：文件太短');
        }
        let offset = MAGIC_V2.length;

        const version = fileData[offset++];
        const mode = fileData[offset++];
        const kdfType = fileData[offset++];
        const flags = fileData[offset++];

        const encKeyLen = (fileData[offset] << 8) | fileData[offset + 1];
        offset += 2;
        if (encKeyLen < 1 || encKeyLen > 1000 || offset + encKeyLen + NONCE_LENGTH + 2 > fileData.length) {
            throw new Error('无效的加密文件：密钥长度错误');
        }

        const encryptedSessionKey = fileData.slice(offset, offset + encKeyLen);
        offset += encKeyLen;

        const nonce = fileData.slice(offset, offset + NONCE_LENGTH);
        offset += NONCE_LENGTH;

        const metaLen = (fileData[offset] << 8) | fileData[offset + 1];
        offset += 2;
        if (offset + metaLen + TAG_LENGTH > fileData.length) {
            throw new Error('无效的加密文件：元数据损坏');
        }

        const encryptedMetadata = fileData.slice(offset, offset + metaLen);
        offset += metaLen;

        let rsaKey = privateKey;
        if (typeof privateKey === 'string') {
            const keyData = parsePEM(privateKey);
            rsaKey = await crypto.subtle.importKey('pkcs8', keyData, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
        }

        const sessionKey = new Uint8Array(
            await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, rsaKey, encryptedSessionKey)
        );

        const sessionKeyCrypto = await crypto.subtle.importKey('raw', sessionKey, { name: 'AES-GCM' }, false, ['decrypt']);

        const ciphertext = fileData.slice(offset, fileData.length - TAG_LENGTH);
        const tag = fileData.slice(fileData.length - TAG_LENGTH);

        const decrypted = await decryptGCM(ciphertext, tag, sessionKeyCrypto, nonce);

        const metadata = JSON.parse(new TextDecoder().decode(encryptedMetadata));

        return {
            data: new Blob([decrypted], { type: 'application/octet-stream' }),
            originalName: metadata.filename,
            metadata: metadata
        };
    }

    /* ============================================
       RSA加密功能
       ============================================ */

    async function generateRSAKeyPair(keySize = 2048) {
        const keyPair = await crypto.subtle.generateKey(
            { name: 'RSA-OAEP', modulusLength: keySize, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
            true,
            ['encrypt', 'decrypt']
        );
        generatedRSAKeys = keyPair;

        const publicKeyExported = await crypto.subtle.exportKey('spki', keyPair.publicKey);
        const privateKeyExported = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

        return {
            publicKey: formatPEM(arrayToBase64(new Uint8Array(publicKeyExported)), 'PUBLIC KEY'),
            privateKey: formatPEM(arrayToBase64(new Uint8Array(privateKeyExported)), 'PRIVATE KEY')
        };
    }

    async function encryptRSA(text, publicKeyPEM) {
        const publicKeyData = parsePEM(publicKeyPEM);
        const publicKey = await crypto.subtle.importKey('spki', publicKeyData, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
        const data = new TextEncoder().encode(text);
        const encrypted = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, data);
        return arrayToBase64(new Uint8Array(encrypted));
    }

    async function decryptRSA(encryptedBase64, privateKeyPEM) {
        const privateKeyData = parsePEM(privateKeyPEM);
        const privateKey = await crypto.subtle.importKey('pkcs8', privateKeyData, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
        const data = base64ToArray(encryptedBase64);
        const decrypted = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, data);
        return new TextDecoder().decode(new Uint8Array(decrypted));
    }

    /* ============================================
       哈希计算功能
       ============================================ */

    async function calculateHash(text, algorithm) {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);

        if (algorithm === 'md5') {
            return calculateMD5(data);
        }

        if (algorithm === 'sha3-256' || algorithm === 'sha3-512') {
            return calculateSHA3(data, algorithm);
        }

        if (algorithm === 'sm3') {
            return arrayToHex(sm3Hash(data));
        }

        const algoMap = {
            'sha256': 'SHA-256',
            'sha384': 'SHA-384',
            'sha512': 'SHA-512'
        };
        const normalizedAlgo = algoMap[algorithm.toLowerCase()] || 'SHA-256';
        const hashBuffer = await crypto.subtle.digest(normalizedAlgo, data);
        return arrayToHex(new Uint8Array(hashBuffer));
    }

    function calculateSHA3(data, algorithm) {
        const rate = algorithm === 'sha3-256' ? 136 : 72;
        const outputLen = algorithm === 'sha3-256' ? 32 : 64;
        const capacity = 200 - rate;

        const padded = new Uint8Array(Math.ceil((data.length + 2) / rate) * rate);
        padded.set(data);
        padded[data.length] = 0x06;
        padded[padded.length - 1] = 0x80;

        const state = new BigUint64Array(25);

        for (let i = 0; i < padded.length; i += rate) {
            for (let j = 0; j < rate && j + i < padded.length; j += 8) {
                let lane = 0n;
                for (let k = 0; k < 8 && j + k < rate; k++) {
                    lane |= BigInt(padded[i + j + k]) << BigInt(k * 8);
                }
                state[j / 8] ^= lane;
            }
            keccakF(state);
        }

        const output = new Uint8Array(outputLen);
        for (let i = 0; i < outputLen; i += 8) {
            const lane = state[i / 8];
            for (let j = 0; j < 8 && i + j < outputLen; j++) {
                output[i + j] = Number((lane >> BigInt(j * 8)) & 0xffn);
            }
        }

        return arrayToHex(output);
    }

    function keccakF(state) {
        const RC = [
            0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
            0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
            0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
            0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
            0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
            0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
        ];

        const R = [
            [0, 36, 3, 41, 18],
            [1, 44, 10, 45, 2],
            [62, 6, 43, 15, 61],
            [28, 55, 25, 21, 56],
            [27, 20, 39, 8, 14]
        ];

        for (let round = 0; round < 24; round++) {
            const C = new BigUint64Array(5);
            const D = new BigUint64Array(5);
            const B = new BigUint64Array(25);

            for (let x = 0; x < 5; x++) {
                C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            }

            for (let x = 0; x < 5; x++) {
                D[x] = C[(x + 4) % 5] ^ rotateLeft64(C[(x + 1) % 5], 1n);
            }

            for (let x = 0; x < 5; x++) {
                for (let y = 0; y < 5; y++) {
                    state[x + 5 * y] ^= D[x];
                }
            }

            for (let x = 0; x < 5; x++) {
                for (let y = 0; y < 5; y++) {
                    B[y + 5 * ((2 * x + 3 * y) % 5)] = rotateLeft64(state[x + 5 * y], BigInt(R[x][y]));
                }
            }

            for (let x = 0; x < 5; x++) {
                for (let y = 0; y < 5; y++) {
                    state[x + 5 * y] = B[x + 5 * y] ^ (~B[(x + 1) % 5 + 5 * y] & B[(x + 2) % 5 + 5 * y]);
                }
            }

            state[0] ^= RC[round];
        }
    }

    function rotateLeft64(value, shift) {
        shift = shift % 64n;
        if (shift === 0n) return value;
        return ((value << shift) | (value >> (64n - shift))) & 0xffffffffffffffffn;
    }

    function calculateMD5(data) {
        let hash = 0x67452301;
        let hash2 = 0xefcdab89;
        let hash3 = 0x98badcfe;
        let hash4 = 0x10325476;

        const padded = new Uint8Array(Math.ceil((data.length + 9) / 64) * 64);
        padded.set(data);
        padded[data.length] = 0x80;
        const view = new DataView(padded.buffer);
        view.setUint32(padded.length - 8, data.length * 8, true);

        const K = new Uint32Array([0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391]);

        const S = new Uint8Array([7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]);

        for (let i = 0; i < padded.length; i += 64) {
            const M = new Uint32Array(16);
            for (let j = 0; j < 16; j++) M[j] = view.getUint32(i + j * 4, true);

            let a = hash, b = hash2, c = hash3, d = hash4;

            for (let j = 0; j < 64; j++) {
                let f, g;
                if (j < 16) { f = (b & c) | (~b & d); g = j; }
                else if (j < 32) { f = (d & b) | (~d & c); g = (5 * j + 1) % 16; }
                else if (j < 48) { f = b ^ c ^ d; g = (3 * j + 5) % 16; }
                else { f = c ^ (b | ~d); g = (7 * j) % 16; }

                f = (f + a + K[j] + M[g]) >>> 0;
                a = d; d = c; c = b; b = (b + leftRotate(f, S[j])) >>> 0;
            }

            hash = (hash + a) >>> 0;
            hash2 = (hash2 + b) >>> 0;
            hash3 = (hash3 + c) >>> 0;
            hash4 = (hash4 + d) >>> 0;
        }

        const result = new Uint8Array(16);
        const resultView = new DataView(result.buffer);
        resultView.setUint32(0, hash, true);
        resultView.setUint32(4, hash2, true);
        resultView.setUint32(8, hash3, true);
        resultView.setUint32(12, hash4, true);
        return arrayToHex(result);
    }

    function leftRotate(x, c) {
        return ((x << c) | (x >>> (32 - c))) >>> 0;
    }

    async function calculateFileHash(file, algorithm, progressCallback) {
        const chunkSize = 2 * 1024 * 1024;
        const totalChunks = Math.ceil(file.size / chunkSize);

        let dataBuffer = new Uint8Array(0);

        for (let i = 0; i < totalChunks; i++) {
            const start = i * chunkSize;
            const end = Math.min(start + chunkSize, file.size);
            const chunk = file.slice(start, end);
            const chunkData = new Uint8Array(await chunk.arrayBuffer());

            const newBuffer = new Uint8Array(dataBuffer.length + chunkData.length);
            newBuffer.set(dataBuffer);
            newBuffer.set(chunkData, dataBuffer.length);
            dataBuffer = newBuffer;

            const progress = Math.round(((i + 1) / totalChunks) * 100);
            progressCallback(progress, `已处理 ${formatSize(end)} / ${formatSize(file.size)}`);
        }

        if (algorithm === 'md5') {
            return calculateMD5(dataBuffer);
        }

        if (algorithm === 'sha3-256' || algorithm === 'sha3-512') {
            return calculateSHA3(dataBuffer, algorithm);
        }

        if (algorithm === 'sm3') {
            return arrayToHex(sm3Hash(dataBuffer));
        }

        const algoMap = { 'sha256': 'SHA-256', 'sha384': 'SHA-384', 'sha512': 'SHA-512' };
        const normalizedAlgo = algoMap[algorithm.toLowerCase()] || 'SHA-256';
        const hashBuffer = await crypto.subtle.digest(normalizedAlgo, dataBuffer);
        return arrayToHex(new Uint8Array(hashBuffer));
    }

    /* ============================================
       Base64 编码/解码
       ============================================ */

    function base64Encode(text) {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        return arrayToBase64(data);
    }

    function base64Decode(base64) {
        const data = base64ToArray(base64);
        const decoder = new TextDecoder();
        return decoder.decode(data);
    }

    /* ============================================
       Base32 编码/解码
       ============================================ */

    const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    function base32Encode(text) {
        const data = new TextEncoder().encode(text);
        let result = '';
        let bits = 0;
        let current = 0;

        for (let i = 0; i < data.length; i++) {
            current = (current << 8) | data[i];
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                result += BASE32_CHARS[(current >>> bits) & 0x1f];
            }
        }
        if (bits > 0) {
            result += BASE32_CHARS[(current << (5 - bits)) & 0x1f];
        }
        while (result.length % 8 !== 0) {
            result += '=';
        }
        return result;
    }

    function base32Decode(encoded) {
        if (!encoded || typeof encoded !== 'string') return '';
        const clean = encoded.toUpperCase().replace(/[^A-Z2-7]/g, '');
        if (clean.length === 0) return '';
        let bits = 0;
        let current = 0;
        const result = [];

        for (let i = 0; i < clean.length; i++) {
            const val = BASE32_CHARS.indexOf(clean[i]);
            if (val === -1) continue;
            current = (current << 5) | val;
            bits += 5;
            while (bits >= 8) {
                bits -= 8;
                result.push((current >>> bits) & 0xff);
            }
        }
        return new TextDecoder().decode(new Uint8Array(result));
    }

    /* ============================================
       Base58 编码/解码 (比特币风格)
       ============================================ */

    const BASE58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    function base58Encode(text) {
        const data = new TextEncoder().encode(text);
        if (data.length === 0) return '';
        const hex = Array.from(data).map(b => b.toString(16).padStart(2, '0')).join('');
        const num = BigInt('0x' + hex);
        let result = '';
        let n = num;
        while (n > 0n) {
            result = BASE58_CHARS[Number(n % 58n)] + result;
            n = n / 58n;
        }
        for (let i = 0; i < data.length && data[i] === 0; i++) {
            result = '1' + result;
        }
        return result;
    }

    function base58Decode(encoded) {
        if (!encoded || encoded.length === 0) return '';
        let num = 0n;
        for (let i = 0; i < encoded.length; i++) {
            const val = BASE58_CHARS.indexOf(encoded[i]);
            if (val === -1) throw new Error('无效的Base58字符');
            num = num * 58n + BigInt(val);
        }
        let hex = num.toString(16);
        if (hex.length % 2) hex = '0' + hex;
        const result = [];
        for (let i = 0; i < hex.length; i += 2) {
            result.push(parseInt(hex.substr(i, 2), 16));
        }
        for (let i = 0; i < encoded.length && encoded[i] === '1'; i++) {
            result.unshift(0);
        }
        return new TextDecoder().decode(new Uint8Array(result));
    }

    /* ============================================
       国密算法 (SM2/SM3/SM4) 与 ChaCha20
       ============================================ */

    const SM4_SBOX = new Uint8Array([
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
    ]);

    const SM4_CK = new Uint32Array([
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9
    ]);

    const SM4_FK = new Uint32Array([0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]);

    function sm4Rotl32(x, n) {
        return ((x << n) | (x >>> (32 - n))) >>> 0;
    }

    function sm4Sbox(x) {
        let b0 = (x >>> 24) & 0xff;
        let b1 = (x >>> 16) & 0xff;
        let b2 = (x >>> 8) & 0xff;
        let b3 = x & 0xff;
        return (SM4_SBOX[b0] << 24) | (SM4_SBOX[b1] << 16) | (SM4_SBOX[b2] << 8) | SM4_SBOX[b3];
    }

    function sm4L(x) {
        return (x ^ sm4Rotl32(x, 2) ^ sm4Rotl32(x, 10) ^ sm4Rotl32(x, 18) ^ sm4Rotl32(x, 24)) >>> 0;
    }

    function sm4Lprime(x) {
        return (x ^ sm4Rotl32(x, 13) ^ sm4Rotl32(x, 23)) >>> 0;
    }

    function sm4Tau(x) {
        return sm4L(sm4Sbox(x));
    }

    function sm4T(x) {
        return sm4L(sm4Sbox(x));
    }

    function sm4KeyExpand(key) {
        const mk = new Uint32Array(4);
        const rk = new Uint32Array(32);
        for (let i = 0; i < 4; i++) {
            mk[i] = ((key[i * 4] << 24) | (key[i * 4 + 1] << 16) | (key[i * 4 + 2] << 8) | key[i * 4 + 3]) >>> 0;
        }
        const k = new Uint32Array(36);
        for (let i = 0; i < 4; i++) {
            k[i] = (mk[i] ^ SM4_FK[i]) >>> 0;
        }
        for (let i = 0; i < 32; i++) {
            let tmp = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i];
            k[i + 4] = (k[i] ^ sm4Lprime(sm4Sbox(tmp))) >>> 0;
            rk[i] = k[i + 4];
        }
        return rk;
    }

    function sm4Round(x, rk) {
        let tmp = x[1] ^ x[2] ^ x[3] ^ rk;
        return (x[0] ^ sm4T(tmp)) >>> 0;
    }

    function sm4EncryptBlock(block, rk) {
        const x = new Uint32Array(4);
        for (let i = 0; i < 4; i++) {
            x[i] = ((block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3]) >>> 0;
        }
        for (let i = 0; i < 32; i++) {
            const tmp = sm4Round(x, rk[i]);
            x[0] = x[1]; x[1] = x[2]; x[2] = x[3]; x[3] = tmp;
        }
        const result = new Uint8Array(16);
        for (let i = 0; i < 4; i++) {
            const val = x[3 - i];
            result[i * 4] = (val >>> 24) & 0xff;
            result[i * 4 + 1] = (val >>> 16) & 0xff;
            result[i * 4 + 2] = (val >>> 8) & 0xff;
            result[i * 4 + 3] = val & 0xff;
        }
        return result;
    }

    function sm4DecryptBlock(block, rk) {
        const reverseRk = new Uint32Array(32);
        for (let i = 0; i < 32; i++) {
            reverseRk[i] = rk[31 - i];
        }
        return sm4EncryptBlock(block, reverseRk);
    }

    function sm4Encrypt(data, key) {
        const rk = sm4KeyExpand(key);
        const padded = new Uint8Array(Math.ceil(data.length / 16) * 16);
        padded.set(data);
        const padLen = padded.length - data.length;
        for (let i = data.length; i < padded.length; i++) {
            padded[i] = padLen;
        }
        const result = new Uint8Array(padded.length);
        for (let i = 0; i < padded.length; i += 16) {
            result.set(sm4EncryptBlock(padded.slice(i, i + 16), rk), i);
        }
        return result;
    }

    function sm4Decrypt(data, key) {
        const rk = sm4KeyExpand(key);
        const result = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i += 16) {
            result.set(sm4DecryptBlock(data.slice(i, i + 16), rk), i);
        }
        const padLen = result[result.length - 1];
        return result.slice(0, result.length - padLen);
    }

    const SM3_IV = new Uint32Array([
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    ]);

    function sm3P0(x) {
        return (x ^ sm4Rotl32(x, 9) ^ sm4Rotl32(x, 17)) >>> 0;
    }

    function sm3P1(x) {
        return (x ^ sm4Rotl32(x, 15) ^ sm4Rotl32(x, 23)) >>> 0;
    }

    function sm3FF0(x, y, z) { return (x ^ y ^ z) >>> 0; }
    function sm3FF1(x, y, z) { return ((x & y) | (x & z) | (y & z)) >>> 0; }
    function sm3GG0(x, y, z) { return (x ^ y ^ z) >>> 0; }
    function sm3GG1(x, y, z) { return ((x & y) | (~x & z)) >>> 0; }

    function sm3Hash(data) {
        const msgLen = data.length;
        const paddedLen = Math.ceil((msgLen + 9) / 64) * 64;
        const padded = new Uint8Array(paddedLen);
        padded.set(data);
        padded[msgLen] = 0x80;
        const lenBits = BigInt(msgLen * 8);
        for (let i = 0; i < 8; i++) {
            padded[paddedLen - 1 - i] = Number((lenBits >> BigInt(i * 8)) & 0xffn);
        }
        const v = new Uint32Array(SM3_IV);
        for (let i = 0; i < paddedLen; i += 64) {
            const w = new Uint32Array(68);
            const w1 = new Uint32Array(64);
            for (let j = 0; j < 16; j++) {
                w[j] = ((padded[i + j * 4] << 24) | (padded[i + j * 4 + 1] << 16) |
                    (padded[i + j * 4 + 2] << 8) | padded[i + j * 4 + 3]) >>> 0;
            }
            for (let j = 16; j < 68; j++) {
                w[j] = (sm3P1(w[j - 16] ^ w[j - 9] ^ sm4Rotl32(w[j - 3], 15)) ^
                    sm4Rotl32(w[j - 13], 7) ^ w[j - 6]) >>> 0;
            }
            for (let j = 0; j < 64; j++) {
                w1[j] = (w[j] ^ w[j + 4]) >>> 0;
            }
            let [a, b, c, d, e, f, g, h] = v;
            for (let j = 0; j < 64; j++) {
                const ss1 = (sm4Rotl32(sm4Rotl32(a, 12) + e + sm4Rotl32(j < 16 ? 0x79cc4519 : 0x7a879d8a, j % 32), 7)) >>> 0;
                const ss2 = (ss1 ^ sm4Rotl32(a, 12)) >>> 0;
                const tt1 = (j < 16 ? sm3FF0(a, b, c) : sm3FF1(a, b, c)) + d + ss2 + w1[j];
                const tt2 = (j < 16 ? sm3GG0(e, f, g) : sm3GG1(e, f, g)) + h + ss1 + w[j];
                c = sm4Rotl32(b, 9);
                b = a;
                a = tt1;
                d = c;
                g = sm4Rotl32(f, 19);
                f = e;
                e = sm3P0(tt2);
                h = g;
                a = a >>> 0; b = b >>> 0; c = c >>> 0; d = d >>> 0;
                e = e >>> 0; f = f >>> 0; g = g >>> 0; h = h >>> 0;
            }
            v[0] ^= a; v[1] ^= b; v[2] ^= c; v[3] ^= d;
            v[4] ^= e; v[5] ^= f; v[6] ^= g; v[7] ^= h;
        }
        const result = new Uint8Array(32);
        for (let i = 0; i < 8; i++) {
            result[i * 4] = (v[i] >>> 24) & 0xff;
            result[i * 4 + 1] = (v[i] >>> 16) & 0xff;
            result[i * 4 + 2] = (v[i] >>> 8) & 0xff;
            result[i * 4 + 3] = v[i] & 0xff;
        }
        return result;
    }

    function chacha20Quarter(state, a, b, c, d) {
        state[a] = (state[a] + state[b]) >>> 0;
        state[d] = sm4Rotl32(state[d] ^ state[a], 16);
        state[c] = (state[c] + state[d]) >>> 0;
        state[b] = sm4Rotl32(state[b] ^ state[c], 12);
        state[a] = (state[a] + state[b]) >>> 0;
        state[d] = sm4Rotl32(state[d] ^ state[a], 8);
        state[c] = (state[c] + state[d]) >>> 0;
        state[b] = sm4Rotl32(state[b] ^ state[c], 7);
    }

    function chacha20Block(key, counter, nonce) {
        const state = new Uint32Array(16);
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        for (let i = 0; i < 8; i++) {
            state[4 + i] = ((key[i * 4 + 3] << 24) | (key[i * 4 + 2] << 16) |
                (key[i * 4 + 1] << 8) | key[i * 4]) >>> 0;
        }
        state[12] = counter;
        for (let i = 0; i < 3; i++) {
            state[13 + i] = ((nonce[i * 4 + 3] << 24) | (nonce[i * 4 + 2] << 16) |
                (nonce[i * 4 + 1] << 8) | nonce[i * 4]) >>> 0;
        }
        const working = new Uint32Array(state);
        for (let i = 0; i < 10; i++) {
            chacha20Quarter(working, 0, 4, 8, 12);
            chacha20Quarter(working, 1, 5, 9, 13);
            chacha20Quarter(working, 2, 6, 10, 14);
            chacha20Quarter(working, 3, 7, 11, 15);
            chacha20Quarter(working, 0, 5, 10, 15);
            chacha20Quarter(working, 1, 6, 11, 12);
            chacha20Quarter(working, 2, 7, 8, 13);
            chacha20Quarter(working, 3, 4, 9, 14);
        }
        const output = new Uint8Array(64);
        for (let i = 0; i < 16; i++) {
            const val = (working[i] + state[i]) >>> 0;
            output[i * 4] = val & 0xff;
            output[i * 4 + 1] = (val >>> 8) & 0xff;
            output[i * 4 + 2] = (val >>> 16) & 0xff;
            output[i * 4 + 3] = (val >>> 24) & 0xff;
        }
        return output;
    }

    function chacha20Encrypt(data, key, nonce) {
        const result = new Uint8Array(data.length);
        let counter = 0;
        for (let i = 0; i < data.length; i += 64) {
            const block = chacha20Block(key, counter++, nonce);
            for (let j = 0; j < 64 && i + j < data.length; j++) {
                result[i + j] = data[i + j] ^ block[j];
            }
        }
        return result;
    }

    function chacha20Decrypt(data, key, nonce) {
        return chacha20Encrypt(data, key, nonce);
    }

    /* ============================================
       古典密码与趣味编码
       ============================================ */

    function vigenereEncrypt(text, key) {
        if (!key) return text;
        const keyUpper = key.toUpperCase();
        let keyIndex = 0;
        return text.split('').map(char => {
            if (/[a-zA-Z]/.test(char)) {
                const base = char === char.toUpperCase() ? 65 : 97;
                const shift = keyUpper.charCodeAt(keyIndex % keyUpper.length) - 65;
                keyIndex++;
                return String.fromCharCode(((char.charCodeAt(0) - base + shift) % 26) + base);
            }
            return char;
        }).join('');
    }

    function vigenereDecrypt(text, key) {
        if (!key) return text;
        const keyUpper = key.toUpperCase();
        let keyIndex = 0;
        return text.split('').map(char => {
            if (/[a-zA-Z]/.test(char)) {
                const base = char === char.toUpperCase() ? 65 : 97;
                const shift = keyUpper.charCodeAt(keyIndex % keyUpper.length) - 65;
                keyIndex++;
                return String.fromCharCode(((char.charCodeAt(0) - base - shift + 26) % 26) + base);
            }
            return char;
        }).join('');
    }

    function railFenceEncrypt(text, rails) {
        if (rails < 2 || rails >= text.length) return text;
        const fence = Array.from({ length: rails }, () => []);
        let rail = 0, direction = 1;
        for (const char of text) {
            fence[rail].push(char);
            rail += direction;
            if (rail === 0 || rail === rails - 1) direction *= -1;
        }
        return fence.flat().join('');
    }

    function railFenceDecrypt(text, rails) {
        if (rails < 2 || rails >= text.length) return text;
        const fence = Array.from({ length: rails }, () => []);
        const pattern = [];
        let rail = 0, direction = 1;
        for (let i = 0; i < text.length; i++) {
            pattern.push(rail);
            rail += direction;
            if (rail === 0 || rail === rails - 1) direction *= -1;
        }
        const counts = Array(rails).fill(0);
        pattern.forEach(r => counts[r]++);
        let index = 0;
        for (let r = 0; r < rails; r++) {
            fence[r] = text.slice(index, index + counts[r]).split('');
            index += counts[r];
        }
        const positions = Array(rails).fill(0);
        return pattern.map(r => fence[r][positions[r]++]).join('');
    }

    const BACON_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const BACON_CODE = [
        'AAAAA', 'AAAAB', 'AAABA', 'AAABB', 'AABAA', 'AABAB', 'AABBA', 'AABBB',
        'ABAAA', 'ABAAB', 'ABABA', 'ABABB', 'ABBAA', 'ABBAB', 'ABBBA', 'ABBBB',
        'BAAAA', 'BAAAB', 'BAABA', 'BAABB', 'BABAA', 'BABAB', 'BABBA', 'BABBB',
        'BBAAA', 'BBAAB'
    ];

    function baconEncrypt(text) {
        return text.toUpperCase().split('').map(char => {
            const idx = BACON_ALPHABET.indexOf(char);
            return idx >= 0 ? BACON_CODE[idx] : char;
        }).join(' ');
    }

    function baconDecode(encoded) {
        const codes = encoded.toUpperCase().split(/\s+/);
        return codes.map(code => {
            if (code.length !== 5 || !/^[AB]+$/.test(code)) return code;
            const idx = BACON_CODE.indexOf(code);
            return idx >= 0 ? BACON_ALPHABET[idx] : code;
        }).join('');
    }

    function atbash(text) {
        return text.split('').map(char => {
            if (/[a-zA-Z]/.test(char)) {
                const base = char === char.toUpperCase() ? 65 : 97;
                return String.fromCharCode(base + 25 - (char.charCodeAt(0) - base));
            }
            return char;
        }).join('');
    }

    function affineEncrypt(text, a, b) {
        if (a < 1 || a > 25 || gcd(a, 26) !== 1) return '参数a必须与26互质';
        return text.split('').map(char => {
            if (/[a-zA-Z]/.test(char)) {
                const base = char === char.toUpperCase() ? 65 : 97;
                const x = char.charCodeAt(0) - base;
                return String.fromCharCode(((a * x + b) % 26) + base);
            }
            return char;
        }).join('');
    }

    function affineDecrypt(text, a, b) {
        if (a < 1 || a > 25 || gcd(a, 26) !== 1) return '参数a必须与26互质';
        const aInv = modInverse(a, 26);
        return text.split('').map(char => {
            if (/[a-zA-Z]/.test(char)) {
                const base = char === char.toUpperCase() ? 65 : 97;
                const y = char.charCodeAt(0) - base;
                return String.fromCharCode(((aInv * (y - b + 26)) % 26) + base);
            }
            return char;
        }).join('');
    }

    function gcd(a, b) { return b === 0 ? a : gcd(b, a % b); }
    function modInverse(a, m) {
        for (let x = 1; x < m; x++) {
            if ((a * x) % m === 1) return x;
        }
        return 1;
    }

    const EMOJI_MAP = '😀😁😂🤣😃😄😅😆😉😊😋😎😍😘🥰😗😙🥲☺️😚🤗🤩🤔🤨😐😑😶🙄😏😣😥😮🤐😯😪😫🥱😴😌😛😜😝🤤😒😓😔😕🙃🫠🤑😲☹️🙁😖😞😟😤😢😭😦😧😨😩🤯😬😰😱🥵🥶😳🤪😵🥴😠😡🤬😷🤒🤕🤢🤮🤧😇🥺🤠🥳🥸🤡👻👽👾🤖💩😺😸😹😻😼😽🙀😿😾🙈🙉🙊💋💌💘💝💖💗💓💞💕💟❣️💔❤️🧡💛💚💙💜🤎🖤🤍💯💢💥💫💦💨🕳️💣💬🗯️💭💤👋🤚🖐️✋🖖👌🤏✌️🤞🤟🤘🤙👈👉👆🖕👇☝️👍👎✊👊🤛🤜👏🙌👐🤲🤝🙏✍️💅🤳💪🦾🦿🦵🦶👂🦻👃🧠🫀🫁🦷🦴👀👁️👅👄👶🧒👦👧🧑👱👨🧔👩🧓👴👵🙍🙎🙅🙆💁🙋🙇🤦🤷👨‍⚕️👩‍⚕️👨‍🎓👩‍🎓👨‍🏫👩‍🏫👨‍⚖️👩‍⚖️👨‍🌾👩‍🌾👨‍🍳👩‍🍳👨‍🔧👩‍🔧👨‍🏭👩‍🏭👨‍💼👩‍💼👨‍🔬👩‍🔬👨‍💻👩‍💻👨‍🎤👩‍🎤👨‍🎨👩‍🎨👨‍✈️👩‍✈️👨‍🚀👩‍🚀👨‍🚒👩‍🚒👮‍♂️👮‍♀️🕵️‍♂️🕵️‍♀️💂‍♂️💂‍♀️👷‍♂️👷‍♀️🤴👸👳‍♂️👳‍♀️👲🧕🤵👰🤰🤱👼🎅🤶🦸‍♂️🦸‍♀️🦹‍♂️🦹‍♀️🧙‍♂️🧙‍♀️🧚‍♂️🧚‍♀️🧛‍♂️🧛‍♀️🧜‍♂️🧜‍♀️🧝‍♂️🧝‍♀️🧞‍♂️🧞‍♀️🧟‍♂️🧟‍♀️💆‍♂️💆‍♀️💇‍♂️💇‍♀️🚶‍♂️🚶‍♀️🧍‍♂️🧍‍♀️🧎‍♂️🧎‍♀️🧑‍🦯🧑‍🦼🧑‍🦽🏃‍♂️🏃‍♀️💃🕺🕴️👯‍♂️👯‍♀️🧖‍♂️🧖‍♀️🧘‍♂️🧘‍♀️🧗‍♂️🧗‍♀️🤺🏇⛷️🏂🏌️‍♂️🏌️‍♀️🏄‍♂️🏄‍♀️🚣‍♂️🚣‍♀️🏊‍♂️🏊‍♀️⛹️‍♂️⛹️‍♀️🏋️‍♂️🏋️‍♀️🚴‍♂️🚴‍♀️🚵‍♂️🚵‍♀️🤸‍♂️🤸‍♀️🤼‍♂️🤼‍♀️🤽‍♂️🤽‍♀️🤾‍♂️🤾‍♀️🤹‍♂️🤹‍♀️🧳🌂☂️🧵🧶🕶️🥽🥼🦺👔👕👖🧣🧤🧥🧦👗👘🥻🩱🩲🩳👙👚👛👜👝🎒👞👟🥾🥿👠👡👢🩰👑👒🎩🎓🧢⛑️📿💄💍💎🔇🔈🔉🔊📢📣📯🔔🔕🎼🎵🎶🎙️🎚️🎛️🎤🎧📻🎷🎸🎹🎺🎻🪕🥁🪘📱📲☎️📞📟📠🔋🔌💻🖥️🖨️⌨️🖱️🖲️💽💾💿📀🧮🎥🎞️📽️🎬📺📷📸📹📼🔍🔎🕯️💡🔦🏮🪔📔📕📖📗📘📙📚📓📒📃📜📄📰🗞️📑🔖🏷️💰💴💵💶💷💸💳🧾💹✉️📧📨📩📤📥📦📫📪📬📭📮🗳️✏️✒️🖋️🖊️🖌️🖍️📝💼📁📂🗂️📅📆🗒️🗓️📇📈📉📊📋📌📍📎🖇️📏📐✂️🗃️🗄️🗑️🔒🔓🔏🔐🔑🗝️🔨🪓⛏️⚒️🛠️🗡️⚔️🔫🏹🛡️🔧🪛🔩⚙️🗜️⚖️🦯🔗⛓️🧰🧲⚗️🧪🧫🧬🔬🔭📡💉🩸💊🩹🩺🚪🛗🪞🪟🛏️🛋️🪑🚽🪠🚿🛁🪤🪒🧴🧷🧹🧺🧻🪣🧼🪥🧽🧯🛒🚬⚰️⚱️🗿🏧🚮🚰♿🚹🚺🚻🚼🚾🛂🛃🛄🛅⚠️🚸⛔🚫🚳🚭🚯🚱🚷📵🔞☢️☣️⬆️↗️➡️↘️⬇️↙️⬅️↖️↕️↔️↩️↪️⤴️⤵️🔃🔄🔙🔚🔛🔜🔝🛐⚛️🕉️✡️☸️☯️✝️☦️☪️☮️🕎🔯♈♉♊♋♌♍♎♏♐♑♒♓⛎🔀🔁🔂▶️⏩⏭️⏯️◀️⏪⏮️🔼⏫🔽⏬⏸️⏹️⏺️⏏️🎦🔅🔆📶📳📴♀️♂️⚕️♾️♻️⚜️🔱📛🔰⭕✅☑️✔️✖️❌❎➕➖➗➰➿〽️✳️✴️❇️‼️⁉️❓❔❕❗〰️©️®️™️#️*️0️⃣1️⃣2️⃣3️⃣4️⃣5️⃣6️⃣7️⃣8️⃣9️⃣🔟🔠🔡🔢🔣🔤🅰️🆎🅱️🆑🆒🆓🆔Ⓜ️🆕🆖🅾️🆗🅿️🆘🆙🆚🈁🈂️🈷️🈶🈯🉐🈹🈚🈲🉑🈸🈴🈳㊗️㊙️🈺🈵🔴🟠🟡🟢🔵🟣🟤⚫⚪🟥🟧🟨🟩🟦🟪🟫⬛⬜◼️◻️◾◽▪️▫️🔶🔷🔸🔹🔺🔻💠🔘🔳🔲🏁🚩🎌🟠🏴🏳️🏳️‍🌈🏴‍☠️🇦🇨🇦🇩🇦🇪🇦🇫🇦🇬🇦🇮🇦🇱🇦🇲🇦🇴🇦🇶🇦🇷🇦🇸🇦🇹🇦🇺🇦🇼🇦🇽🇦🇿🇧🇦🇧🇧🇧🇩🇧🇪🇧🇫🇧🇬🇧🇭🇧🇮🇧🇯🇧🇱🇧🇲🇧🇳🇧🇴🇧🇶🇧🇷🇧🇸🇧🇹🇧🇻🇧🇼🇧🇾🇧🇿🇨🇦🇨🇨🇨🇩🇨🇫🇨🇬🇨🇭🇨🇮🇨🇰🇨🇱🇨🇲🇨🇳🇨🇴🇨🇵🇨🇷🇨🇺🇨🇻🇨🇼🇨🇽🇨🇾🇨🇿🇩🇪🇩🇬🇩🇯🇩🇰🇩🇲🇩🇴🇩🇿🇪🇦🇪🇨🇪🇪🇪🇬🇪🇭🇪🇷🇪🇸🇪🇹🇪🇺🇫🇮🇫🇯🇫🇰🇫🇲🇫🇴🇫🇷🇬🇦🇬🇧🇬🇩🇬🇪🇬🇫🇬🇬🇬🇭🇬🇮🇬🇱🇬🇲🇬🇳🇬🇵🇬🇶🇬🇷🇬🇸🇬🇹🇬🇺🇬🇼🇬🇾🇭🇰🇭🇲🇭🇳🇭🇷🇭🇹🇭🇺🇮🇨🇮🇩🇮🇪🇮🇱🇮🇲🇮🇳🇮🇴🇮🇶🇮🇷🇮🇸🇮🇹🇯🇪🇯🇲🇯🇴🇯🇵🇰🇪🇰🇬🇰🇭🇰🇮🇰🇲🇰🇳🇰🇵🇰🇷🇰🇼🇰🇾🇰🇿🇱🇦🇱🇧🇱🇨🇱🇮🇱🇰🇱🇷🇱🇸🇱🇹🇱🇺🇱🇻🇱🇾🇲🇦🇲🇨🇲🇩🇲🇪🇲🇫🇲🇬🇲🇭🇲🇰🇲🇱🇲🇲🇲🇳🇲🇴🇲🇵🇲🇶🇲🇷🇲🇸🇲🇹🇲🇺🇲🇻🇲🇼🇲🇽🇲🇾🇲🇿🇳🇦🇳🇨🇳🇪🇳🇫🇳🇬🇳🇮🇳🇱🇳🇴🇳🇵🇳🇷🇳🇺🇳🇿🇴🇲🇵🇦🇵🇪🇵🇫🇵🇬🇵🇭🇵🇰🇵🇱🇵🇲🇵🇳🇵🇷🇵🇸🇵🇹🇵🇼🇵🇾🇶🇦🇷🇪🇷🇴🇷🇸🇷🇺🇷🇼🇸🇦🇸🇧🇸🇨🇸🇩🇸🇪🇸🇬🇸🇭🇸🇮🇸🇯🇸🇰🇸🇱🇸🇲🇸🇳🇸🇴🇸🇷🇸🇸🇸🇹🇸🇻🇸🇽🇸🇾🇸🇿🇹🇦🇹🇨🇹🇩🇹🇫🇹🇬🇹🇭🇹🇯🇹🇰🇹🇱🇹🇲🇹🇳🇹🇴🇹🇷🇹🇹🇹🇻🇹🇼🇹🇿🇺🇦🇺🇬🇺🇲🇺🇳🇺🇸🇺🇾🇺🇿🇻🇦🇻🇨🇻🇪🇻🇬🇻🇮🇻🇳🇻🇺🇼🇫🇼🇸🇽🇰🇾🇪🇾🇹🇿🇦🇿🇲🇿🇼'.split('');

    function emojiEncode(text) {
        const bytes = new TextEncoder().encode(text);
        return Array.from(bytes).map(b => EMOJI_MAP[b % EMOJI_MAP.length]).join('');
    }

    function emojiDecode(encoded) {
        const bytes = [];
        let current = '';
        for (const char of encoded) {
            current += char;
            const idx = EMOJI_MAP.indexOf(current);
            if (idx >= 0) {
                bytes.push(idx);
                current = '';
            }
        }
        return new TextDecoder().decode(new Uint8Array(bytes));
    }

    const PIG_PEN = {
        'A': '⌐', 'B': '¬', 'C': '┌', 'D': '┐', 'E': '└', 'F': '┘',
        'G': '╒', 'H': '╕', 'I': '╘', 'J': '╛', 'K': '╞', 'L': '╡',
        'M': '╥', 'N': '╨', 'O': '╩', 'P': '╦', 'Q': '╠', 'R': '╣',
        'S': '╬', 'T': '╬', 'U': '╓', 'V': '╖', 'W': '╙', 'X': '╜',
        'Y': '╢', 'Z': '╟'
    };
    const PIG_PEN_REVERSE = Object.fromEntries(Object.entries(PIG_PEN).map(([k, v]) => [v, k]));

    function pigPenEncrypt(text) {
        return text.toUpperCase().split('').map(c => PIG_PEN[c] || c).join(' ');
    }

    function pigPenDecode(encoded) {
        return encoded.split(/\s+/).map(c => PIG_PEN_REVERSE[c] || c).join('');
    }

    function reverseText(text) {
        return text.split('').reverse().join('');
    }

    function textToBinary(text) {
        return text.split('').map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join(' ');
    }

    function binaryToText(binary) {
        return binary.split(/\s+/).map(b => String.fromCharCode(parseInt(b, 2))).join('');
    }

    function textToHex(text) {
        return text.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
    }

    function hexToText(hex) {
        return hex.split(/\s+/).map(h => String.fromCharCode(parseInt(h, 16))).join('');
    }

    function textToOctal(text) {
        return text.split('').map(c => c.charCodeAt(0).toString(8).padStart(3, '0')).join(' ');
    }

    function octalToText(octal) {
        return octal.split(/\s+/).map(o => String.fromCharCode(parseInt(o, 8))).join('');
    }

    function textToDecimal(text) {
        return text.split('').map(c => c.charCodeAt(0).toString(10)).join(' ');
    }

    function decimalToText(decimal) {
        return decimal.split(/\s+/).map(d => String.fromCharCode(parseInt(d, 10))).join('');
    }

    function numberBaseConvert(num, fromBase, toBase) {
        const decimal = parseInt(num, fromBase);
        if (isNaN(decimal)) return '无效数字';
        return decimal.toString(toBase).toUpperCase();
    }

    /* ============================================
       摩尔斯电码
       ============================================ */

    const MORSE_CODE = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
        '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
        '8': '---..', '9': '----.', '.': '.-.-.-', ',': '--..--', '?': '..--..',
        "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-',
        '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.',
        '-': '-....-', '_': '..--.-', '"': '.-..-.', '$': '...-..-', '@': '.--.-.',
        ' ': '/'
    };

    const MORSE_REVERSE = Object.fromEntries(Object.entries(MORSE_CODE).map(([k, v]) => [v, k]));

    function morseEncode(text) {
        const result = text.toUpperCase().split('').map(c => MORSE_CODE[c] || '[?]').join(' ');
        return result;
    }

    function morseDecode(encoded) {
        return encoded.split(' ').map(c => MORSE_REVERSE[c] || c).join('');
    }

    /* ============================================
       凯撒密码
       ============================================ */

    function caesarEncrypt(text, shift = 3) {
        return text.split('').map(c => {
            if (c >= 'a' && c <= 'z') {
                return String.fromCharCode(((c.charCodeAt(0) - 97 + shift) % 26 + 26) % 26 + 97);
            }
            if (c >= 'A' && c <= 'Z') {
                return String.fromCharCode(((c.charCodeAt(0) - 65 + shift) % 26 + 26) % 26 + 65);
            }
            return c;
        }).join('');
    }

    function caesarDecrypt(text, shift = 3) {
        return caesarEncrypt(text, -shift);
    }

    /* ============================================
       ROT13 编码
       ============================================ */

    function rot13(text) {
        return caesarEncrypt(text, 13);
    }

    /* ============================================
       ECC 椭圆曲线加密 (ECDH + AES)
       ============================================ */

    async function generateECCKeys() {
        const keyPair = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveKey', 'deriveBits']
        );
        const publicKeyExported = await crypto.subtle.exportKey('spki', keyPair.publicKey);
        const privateKeyExported = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        return {
            publicKey: formatPEM(arrayToBase64(new Uint8Array(publicKeyExported)), 'PUBLIC KEY'),
            privateKey: formatPEM(arrayToBase64(new Uint8Array(privateKeyExported)), 'PRIVATE KEY'),
            keyPair: keyPair
        };
    }

    async function eccEncrypt(text, recipientPublicKeyPEM) {
        const ephemeralKeyPair = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveKey', 'deriveBits']
        );
        const recipientPublicKeyData = parsePEM(recipientPublicKeyPEM);
        const recipientPublicKey = await crypto.subtle.importKey(
            'spki', recipientPublicKeyData,
            { name: 'ECDH', namedCurve: 'P-256' },
            false, []
        );
        const sharedKey = await crypto.subtle.deriveKey(
            { name: 'ECDH', public: recipientPublicKey },
            ephemeralKeyPair.privateKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );
        const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
        const data = new TextEncoder().encode(text);
        const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, sharedKey, data);
        const ephemeralPublicKeyExported = await crypto.subtle.exportKey('spki', ephemeralKeyPair.publicKey);
        const ephemeralPublicKeyBytes = new Uint8Array(ephemeralPublicKeyExported);
        const encryptedBytes = new Uint8Array(encrypted);
        const result = concatArrays(
            new Uint8Array([(ephemeralPublicKeyBytes.length >> 8) & 0xff, ephemeralPublicKeyBytes.length & 0xff]),
            ephemeralPublicKeyBytes,
            nonce,
            encryptedBytes
        );
        return arrayToBase64(result);
    }

    async function eccDecrypt(encryptedBase64, privateKeyPEM) {
        const data = base64ToArray(encryptedBase64);
        if (!data || data.length < 4) {
            throw new Error('无效的加密数据：数据太短');
        }
        let offset = 0;
        const keyLen = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        if (keyLen < 1 || keyLen > 1000 || offset + keyLen + NONCE_LENGTH > data.length) {
            throw new Error('无效的加密数据：密钥长度错误');
        }
        const ephemeralPublicKeyBytes = data.slice(offset, offset + keyLen);
        offset += keyLen;
        const nonce = data.slice(offset, offset + NONCE_LENGTH);
        offset += NONCE_LENGTH;
        const ciphertext = data.slice(offset);
        if (ciphertext.length < TAG_LENGTH) {
            throw new Error('无效的加密数据：密文太短');
        }
        const privateKeyData = parsePEM(privateKeyPEM);
        const privateKey = await crypto.subtle.importKey(
            'pkcs8', privateKeyData,
            { name: 'ECDH', namedCurve: 'P-256' },
            false, ['deriveKey', 'deriveBits']
        );
        const ephemeralPublicKey = await crypto.subtle.importKey(
            'spki', ephemeralPublicKeyBytes,
            { name: 'ECDH', namedCurve: 'P-256' },
            false, []
        );
        const sharedKey = await crypto.subtle.deriveKey(
            { name: 'ECDH', public: ephemeralPublicKey },
            privateKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );
        const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, sharedKey, ciphertext);
        return new TextDecoder().decode(new Uint8Array(decrypted));
    }

    /* ============================================
       密码生成器 - 使用拒绝采样消除模偏
       ============================================ */

    function generatePassword(length, options) {
        const { upper, lower, numbers, symbols, excludeSimilar } = options;
        let chars = '';

        if (upper) chars += excludeSimilar ? 'ABCDEFGHJKMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (lower) chars += excludeSimilar ? 'abcdefghjkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
        if (numbers) chars += excludeSimilar ? '23456789' : '0123456789';
        if (symbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';

        if (!chars) chars = 'abcdefghijklmnopqrstuvwxyz';

        const safeLength = Math.max(1, Math.min(256, parseInt(length) || 16));
        const charLen = chars.length;
        const maxValid = Math.floor(256 / charLen) * charLen;

        let password = '';
        const randomBytes = new Uint8Array(safeLength * 2);
        crypto.getRandomValues(randomBytes);
        let byteIndex = 0;

        while (password.length < safeLength) {
            if (byteIndex >= randomBytes.length) {
                crypto.getRandomValues(randomBytes);
                byteIndex = 0;
            }

            const byte = randomBytes[byteIndex++];
            if (byte < maxValid) {
                password += chars[byte % charLen];
            }
        }

        return password;
    }

    /* ============================================
       文本加密/解密
       ============================================ */

    async function encryptText(text, password) {
        const useGCM = await checkGCMSupport();
        const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
        const nonce = crypto.getRandomValues(new Uint8Array(useGCM ? NONCE_LENGTH : IV_LENGTH));
        const key = await deriveKey(password, salt, currentKdf);
        const data = new TextEncoder().encode(text);

        if (useGCM) {
            const { ciphertext, tag } = await encryptGCM(data, key, nonce);
            const header = concatArrays(salt, nonce);
            return arrayToBase64(concatArrays(header, ciphertext, tag));
        } else {
            const { ciphertext } = await encryptCBC(data, key, nonce);
            const header = concatArrays(salt, nonce);
            return arrayToBase64(concatArrays(header, ciphertext));
        }
    }

    async function decryptText(encryptedBase64, password) {
        const data = base64ToArray(encryptedBase64);
        const minLenGCM = SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH + 1;
        const minLenCBC = SALT_LENGTH + IV_LENGTH + 16;
        if (!data || data.length < Math.min(minLenGCM, minLenCBC)) {
            throw new Error('无效的加密数据：数据太短');
        }
        const useGCM = (data.length - SALT_LENGTH - NONCE_LENGTH - TAG_LENGTH) >= 0;

        let offset = 0;
        const salt = data.slice(offset, offset + SALT_LENGTH);
        offset += SALT_LENGTH;
        const key = await deriveKey(password, salt, currentKdf);

        if (useGCM) {
            const nonce = data.slice(offset, offset + NONCE_LENGTH);
            offset += NONCE_LENGTH;
            const ciphertext = data.slice(offset, data.length - TAG_LENGTH);
            const tag = data.slice(data.length - TAG_LENGTH);
            if (ciphertext.length === 0) {
                throw new Error('无效的加密数据：密文为空');
            }
            const decrypted = await decryptGCM(ciphertext, tag, key, nonce);
            return new TextDecoder().decode(decrypted);
        } else {
            const nonce = data.slice(offset, offset + IV_LENGTH);
            offset += IV_LENGTH;
            const ciphertext = data.slice(offset);
            if (ciphertext.length === 0) {
                throw new Error('无效的加密数据：密文为空');
            }
            const decrypted = await decryptCBC(ciphertext, key, nonce);
            return new TextDecoder().decode(decrypted);
        }
    }

    /* ============================================
       安全检测函数
       ============================================ */

    function checkEnvironment() {
        const unsafe = typeof window !== 'undefined' && (
            window.electron || window.nw || (typeof require === 'function' && typeof module !== 'undefined')
        );
        if (unsafe) {
            document.getElementById('envWarning').classList.add('active');
            return false;
        }
        return true;
    }

    function evaluatePassword(password) {
        if (!password || password.length < 8) return { score: -1, label: '太短', crackTime: '', class: 'weak' };

        if (typeof zxcvbn === 'function') {
            const result = zxcvbn(password);
            const score = Math.max(0, Math.min(4, result.score));
            const crackTime = result.crack_times_display?.offline_slow_hashing_1e4_per_second || '未知';
            const levels = [
                { label: '非常弱', class: 'weak' },
                { label: '弱', class: 'weak' },
                { label: '一般', class: 'fair' },
                { label: '强', class: 'good' },
                { label: '非常强', class: 'strong' }
            ];
            return { score, label: levels[score].label, class: levels[score].class, crackTime };
        }

        let hasUpper = /[A-Z]/.test(password);
        let hasLower = /[a-z]/.test(password);
        let hasNumber = /[0-9]/.test(password);
        let hasSymbol = /[^A-Za-z0-9]/.test(password);
        let charsetSize = 0;
        if (hasUpper) charsetSize += 26;
        if (hasLower) charsetSize += 26;
        if (hasNumber) charsetSize += 10;
        if (hasSymbol) charsetSize += 32;

        const entropy = password.length * Math.log2(charsetSize || 26);
        const combinations = Math.pow(charsetSize || 26, password.length);
        const crackTimeSeconds = combinations / 1e10;

        let crackTime = '';
        if (crackTimeSeconds < 1) crackTime = '瞬间';
        else if (crackTimeSeconds < 60) crackTime = Math.round(crackTimeSeconds) + ' 秒';
        else if (crackTimeSeconds < 3600) crackTime = Math.round(crackTimeSeconds / 60) + ' 分钟';
        else if (crackTimeSeconds < 86400) crackTime = Math.round(crackTimeSeconds / 3600) + ' 小时';
        else if (crackTimeSeconds < 2592000) crackTime = Math.round(crackTimeSeconds / 86400) + ' 天';
        else if (crackTimeSeconds < 31536000) crackTime = Math.round(crackTimeSeconds / 2592000) + ' 月';
        else if (crackTimeSeconds < 3153600000) crackTime = Math.round(crackTimeSeconds / 31536000) + ' 年';
        else crackTime = '数百年+';

        let score, label, className;
        if (crackTimeSeconds < 3600) {
            score = 0; label = '非常弱'; className = 'weak';
        } else if (crackTimeSeconds < 86400) {
            score = 1; label = '弱'; className = 'weak';
        } else if (crackTimeSeconds < 31536000) {
            score = 2; label = '一般'; className = 'fair';
        } else if (crackTimeSeconds < 315360000000) {
            score = 3; label = '强'; className = 'good';
        } else {
            score = 4; label = '非常强'; className = 'strong';
        }

        return { score, label, class: className, crackTime, entropy: Math.round(entropy) };
    }

    /* ============================================
       UI辅助函数
       ============================================ */

    function updateSecurityBanner() {
        const banner = document.getElementById('securityBanner');
        const mode = banner.querySelector('span');
        if (currentMode === 'key') {
            banner.classList.add('key-mode');
            mode.innerHTML = '🔑 密钥模式 - 您负责安全保管密钥！';
        } else {
            banner.classList.remove('key-mode');
            mode.innerHTML = '🔒 安全模式 - 所有操作均在本地完成';
        }
    }

    function updateFileUploadArea(areaId, fileName) {
        const area = document.getElementById(areaId);
        if (!area) return;
        const icon = area.querySelector('.file-upload-icon');
        const text = area.querySelector('.file-upload-text');
        if (fileName) {
            if (icon) icon.textContent = '✅';
            if (text) text.textContent = fileName;
        } else {
            if (icon) icon.textContent = '📤';
            if (text) text.textContent = '点击或拖拽文件到此处';
        }
    }

    function setupDragDrop(areaId, inputId) {
        const area = document.getElementById(areaId);
        const input = document.getElementById(inputId);
        if (!area || !input) return;

        area.addEventListener('dragenter', (e) => {
            e.preventDefault();
            e.stopPropagation();
            area.classList.add('dragover');
        }, false);

        area.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.stopPropagation();
            area.classList.add('dragover');
        }, false);

        area.addEventListener('dragleave', (e) => {
            e.preventDefault();
            e.stopPropagation();
            area.classList.remove('dragover');
        }, false);

        area.addEventListener('drop', (e) => {
            e.preventDefault();
            e.stopPropagation();
            area.classList.remove('dragover');
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                input.files = files;
                input.dispatchEvent(new Event('change'));
            }
        }, false);
    }

    function updateProgress(type, percent, message) {
        const fill = document.getElementById(`${type}ProgressFill`);
        const status = document.getElementById(`${type}ProgressStatus`);
        const percentEl = document.getElementById(`${type}ProgressPercent`);
        const cancelBtn = document.getElementById('cancelOperationBtn');

        if (fill) fill.style.width = `${percent}%`;
        if (status) status.textContent = message;
        if (percentEl) percentEl.textContent = `${percent}%`;

        if (cancelBtn) {
            if (operationInProgress && percent < 100) {
                cancelBtn.style.display = 'inline-block';
            } else {
                cancelBtn.style.display = 'none';
            }
        }
    }

    function setupCancelButton() {
        const cancelBtn = document.getElementById('cancelOperationBtn');
        if (cancelBtn) {
            cancelBtn.addEventListener('click', function () {
                if (cancelCurrentOperation()) {
                    const resultDiv = document.getElementById('fileResult');
                    showResult(resultDiv, '⚠️ 操作已取消', 'warning');
                    document.getElementById('fileProgress').style.display = 'none';
                    cancelBtn.style.display = 'none';

                    const encryptBtn = document.getElementById('fileEncryptBtn');
                    const decryptBtn = document.getElementById('fileDecryptBtn');
                    if (encryptBtn) encryptBtn.disabled = false;
                    if (decryptBtn) decryptBtn.disabled = false;
                }
            });
        }
    }

    function showResult(element, message, type) {
        if (!element) return;
        element.innerHTML = message;
        element.className = `result-box ${type}`;
        element.style.display = 'block';
    }

    function downloadFile(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 1000);
    }

    function checkCryptoSupport() {
        const errors = [];
        if (!window.crypto) errors.push('Crypto API');
        if (!crypto.subtle) errors.push('Web Crypto API');
        if (typeof zxcvbn === 'undefined') errors.push('zxcvbn密码强度库');
        if (errors.length > 0) {
            alert(`系统错误: 以下组件加载失败\n${errors.join('\n')}\n请刷新页面重试`);
            document.querySelectorAll('.btn').forEach(btn => btn.disabled = true);
        }
    }

    /* ============================================
       自检功能 - 精简版
       ============================================ */

    async function runSelfTest() {
        const resultDiv = document.getElementById('selfTestResult');
        resultDiv.classList.add('active');
        resultDiv.textContent = '正在运行系统自检...\n';

        const tests = [];
        let useArgon2 = false;
        let errorCount = 0;
        let testStep = 0;
        const totalTests = 38;

        function log(msg) {
            resultDiv.textContent += msg;
        }

        try {
            log('\n【错误码系统】\n');

            log(`[${++testStep}/${totalTests}] 错误码定义... `);
            const errorCodeCount = Object.keys(ERROR_CODES).length;
            const hasAllCategories = ['加密', '解密', '密钥', '文件', '系统'].every(cat =>
                Object.values(ERROR_CODES).some(e => e.category === cat)
            );
            tests.push({ name: '错误码定义', passed: errorCodeCount >= 20 && hasAllCategories });
            log(errorCodeCount >= 20 && hasAllCategories ? `✓ 已定义${errorCodeCount}个错误码\n` : '✗ 错误码不完整\n');
            if (errorCodeCount < 20 || !hasAllCategories) errorCount++;

            log(`[${++testStep}/${totalTests}] 错误映射函数... `);
            const testError1 = new Error('Argon2库未加载');
            const testError2 = new Error('HMAC验证失败');
            const testError3 = new Error('未知错误测试');
            const map1 = mapErrorToCode(testError1);
            const map2 = mapErrorToCode(testError2);
            const map3 = mapErrorToCode(testError3);
            const mapOk = map1 === 'E1001' && map2 === 'E2002' && map3 === 'E5004';
            tests.push({ name: '错误映射', passed: mapOk });
            log(mapOk ? '✓ 正常\n' : '✗ 映射错误\n');
            if (!mapOk) errorCount++;

            log('\n【系统检测】\n');

            log(`[${++testStep}/${totalTests}] 加密模式... `);
            const gcmOk = await checkGCMSupport();
            tests.push({ name: 'AES-GCM', passed: gcmOk });
            log(gcmOk ? '✓ AES-GCM\n' : '⚠ AES-CBC+HMAC\n');

            log(`[${++testStep}/${totalTests}] Argon2库... `);
            const argon2Loaded = await waitForArgon2(5000);
            useArgon2 = argon2Loaded;
            tests.push({ name: 'Argon2', passed: argon2Loaded });
            log(argon2Loaded ? '✓ 已加载\n' : '⚠ 使用Scrypt\n');

            const testSalt = crypto.getRandomValues(new Uint8Array(16));

            if (useArgon2) {
                log(`[${++testStep}/${totalTests}] Argon2id... `);
                try {
                    await deriveKeyArgon2('test', testSalt);
                    tests.push({ name: 'Argon2id', passed: true });
                    log('✓ 正常\n');
                } catch (e) {
                    tests.push({ name: 'Argon2id', passed: false });
                    log(`✗ ${e.message}\n`);
                    errorCount++;
                }
            } else {
                log(`[${++testStep}/${totalTests}] Argon2id... 跳过\n`);
            }

            log(`[${++testStep}/${totalTests}] Scrypt... `);
            try {
                await deriveKeyScrypt('test', testSalt);
                tests.push({ name: 'Scrypt', passed: true });
                log('✓ 正常\n');
            } catch (e) {
                tests.push({ name: 'Scrypt', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log(`[${++testStep}/${totalTests}] ECDSA签名... `);
            try {
                const eccSupported = await checkECCSupport();
                if (eccSupported) {
                    await generateECDSAKeyPair();
                    const testData = new TextEncoder().encode('test');
                    const sig = await signData(testData, generatedECCKeys.privateKey);
                    const verified = await verifySignature(testData, sig, generatedECCKeys.publicKey);
                    tests.push({ name: 'ECDSA', passed: verified });
                    log(verified ? '✓ 正常\n' : '✗ 验证失败\n');
                    if (!verified) errorCount++;
                } else {
                    tests.push({ name: 'ECDSA', passed: false });
                    log(' 不支持\n');
                    errorCount++;
                }
            } catch (e) {
                tests.push({ name: 'ECDSA', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log(`[${++testStep}/${totalTests}] 文件加密/解密... `);
            const testData = new TextEncoder().encode('Hello测试中文123');
            const testFile = new File([testData], 'test.txt', { type: 'text/plain' });
            const testKdf = useArgon2 ? KDF_ARGON2 : KDF_SCRYPT;
            try {
                const enc = await encryptFileV2(testFile, 'pwd123', { kdfType: testKdf });
                const dec = await decryptFileV2(new Uint8Array(await enc.blob.arrayBuffer()), 'pwd123');
                const decText = new TextDecoder().decode(await dec.data.arrayBuffer());
                const ok = decText === 'Hello测试中文123';
                tests.push({ name: '文件加密解密', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 数据不匹配\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: '文件加密解密', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log(`[${++testStep}/${totalTests}] 错误密码检测... `);
            try {
                const enc2 = await encryptFileV2(testFile, 'correct', { kdfType: testKdf });
                await decryptFileV2(new Uint8Array(await enc2.blob.arrayBuffer()), 'wrong');
                tests.push({ name: '密码检测', passed: false });
                log('✗ 未检测到\n');
                errorCount++;
            } catch (e) {
                tests.push({ name: '密码检测', passed: true });
                log('✓ 正常\n');
            }

            log(`[${++testStep}/${totalTests}] HMAC校验... `);
            try {
                const enc3 = await encryptFileV2(testFile, 't', { kdfType: testKdf });
                const encData = new Uint8Array(await enc3.blob.arrayBuffer());
                encData[encData.length - 20] ^= 0xff;
                try {
                    await decryptFileV2(encData, 't');
                    tests.push({ name: 'HMAC', passed: false });
                    log('✗ 未检测到篡改\n');
                    errorCount++;
                } catch (e) {
                    tests.push({ name: 'HMAC', passed: true });
                    log('✓ 正常\n');
                }
            } catch (e) {
                tests.push({ name: 'HMAC', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log('\n【文本加密】\n');
            log(`[${++testStep}/${totalTests}] 文本加密/解密... `);
            try {
                const encrypted = await encryptText('测试文本加密', 'testpwd');
                const decrypted = await decryptText(encrypted, 'testpwd');
                const ok = decrypted === '测试文本加密';
                tests.push({ name: '文本加密解密', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 数据不匹配\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: '文本加密解密', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log('\n【RSA加密】\n');
            log(`[${++testStep}/${totalTests}] RSA密钥生成... `);
            try {
                const rsaKeys = await generateRSAKeyPair(2048);
                tests.push({ name: 'RSA密钥生成', passed: !!rsaKeys.publicKey && !!rsaKeys.privateKey });
                log(rsaKeys.publicKey ? '✓ 正常\n' : '✗ 失败\n');

                log(`[${++testStep}/${totalTests}] RSA加密/解密... `);
                const rsaEncrypted = await encryptRSA('RSA测试', rsaKeys.publicKey);
                const rsaDecrypted = await decryptRSA(rsaEncrypted, rsaKeys.privateKey);
                const rsaOk = rsaDecrypted === 'RSA测试';
                tests.push({ name: 'RSA加解密', passed: rsaOk });
                log(rsaOk ? '✓ 正常\n' : '✗ 数据不匹配\n');
                if (!rsaOk) errorCount++;
            } catch (e) {
                tests.push({ name: 'RSA', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log('\n【ECC加密】\n');
            log(`[${++testStep}/${totalTests}] ECC密钥生成... `);
            try {
                const eccKeys = await generateECCKeys();
                tests.push({ name: 'ECC密钥生成', passed: !!eccKeys.publicKey && !!eccKeys.privateKey });
                log(eccKeys.publicKey ? '✓ 正常\n' : '✗ 失败\n');

                log(`[${++testStep}/${totalTests}] ECC加密/解密... `);
                const eccEncrypted = await eccEncrypt('ECC测试中文', eccKeys.publicKey);
                const eccDecrypted = await eccDecrypt(eccEncrypted, eccKeys.privateKey);
                const eccOk = eccDecrypted === 'ECC测试中文';
                tests.push({ name: 'ECC加解密', passed: eccOk });
                log(eccOk ? '✓ 正常\n' : '✗ 数据不匹配\n');
                if (!eccOk) errorCount++;
            } catch (e) {
                tests.push({ name: 'ECC', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log('\n【哈希计算】\n');
            log(`[${++testStep}/${totalTests}] SHA-256... `);
            try {
                const hash256 = await calculateHash('测试', 'sha256');
                const ok = hash256 && hash256.length === 64;
                tests.push({ name: 'SHA-256', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 失败\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: 'SHA-256', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log(`[${++testStep}/${totalTests}] SHA-512... `);
            try {
                const hash512 = await calculateHash('测试', 'sha512');
                const ok = hash512 && hash512.length === 128;
                tests.push({ name: 'SHA-512', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 失败\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: 'SHA-512', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log(`[${++testStep}/${totalTests}] SHA3-256... `);
            try {
                const hash3_256 = await calculateHash('测试', 'sha3-256');
                const ok = hash3_256 && hash3_256.length === 64;
                tests.push({ name: 'SHA3-256', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 失败\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: 'SHA3-256', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log(`[${++testStep}/${totalTests}] SHA3-512... `);
            try {
                const hash3_512 = await calculateHash('测试', 'sha3-512');
                const ok = hash3_512 && hash3_512.length === 128;
                tests.push({ name: 'SHA3-512', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 失败\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: 'SHA3-512', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log(`[${++testStep}/${totalTests}] SM3国密哈希... `);
            try {
                const sm3Hash = await calculateHash('测试', 'sm3');
                const ok = sm3Hash && sm3Hash.length === 64;
                tests.push({ name: 'SM3', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 失败\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: 'SM3', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log(`[${++testStep}/${totalTests}] SM4国密加密... `);
            try {
                const key = new Uint8Array(16).fill(0x01);
                const data = new TextEncoder().encode('SM4测试数据123');
                const encrypted = sm4Encrypt(data, key);
                const decrypted = sm4Decrypt(encrypted, key);
                const ok = new TextDecoder().decode(decrypted) === 'SM4测试数据123';
                tests.push({ name: 'SM4', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 失败\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: 'SM4', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log(`[${++testStep}/${totalTests}] ChaCha20流密码... `);
            try {
                const key = new Uint8Array(32).fill(0x01);
                const nonce = new Uint8Array(12).fill(0x02);
                const data = new TextEncoder().encode('ChaCha20测试数据');
                const encrypted = chacha20Encrypt(data, key, nonce);
                const decrypted = chacha20Decrypt(encrypted, key, nonce);
                const ok = new TextDecoder().decode(decrypted) === 'ChaCha20测试数据';
                tests.push({ name: 'ChaCha20', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 失败\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: 'ChaCha20', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log(`[${++testStep}/${totalTests}] MD5... `);
            try {
                const hashMd5 = calculateMD5(new TextEncoder().encode('测试'));
                const ok = hashMd5 && hashMd5.length === 32;
                tests.push({ name: 'MD5', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 失败\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: 'MD5', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log('\n【编码工具】\n');
            log(`[${++testStep}/${totalTests}] Base64... `);
            try {
                const b64Enc = base64Encode('测试Base64');
                const b64Dec = base64Decode(b64Enc);
                const ok = b64Dec === '测试Base64';
                tests.push({ name: 'Base64', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 数据不匹配\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: 'Base64', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log(`[${++testStep}/${totalTests}] Base32... `);
            try {
                const b32Enc = base32Encode('测试Base32');
                const b32Dec = base32Decode(b32Enc);
                const ok = b32Dec === '测试Base32';
                tests.push({ name: 'Base32', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 数据不匹配\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: 'Base32', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log(`[${++testStep}/${totalTests}] Base58... `);
            try {
                const b58Enc = base58Encode('测试Base58');
                const b58Dec = base58Decode(b58Enc);
                const ok = b58Dec === '测试Base58';
                tests.push({ name: 'Base58', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 数据不匹配\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: 'Base58', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log(`[${++testStep}/${totalTests}] 八进制编码... `);
            try {
                const octEnc = textToOctal('AB');
                const octDec = octalToText(octEnc);
                const ok = octDec === 'AB';
                tests.push({ name: '八进制', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 数据不匹配\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: '八进制', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log(`[${++testStep}/${totalTests}] 十进制编码... `);
            try {
                const decEnc = textToDecimal('AB');
                const decDec = decimalToText(decEnc);
                const ok = decDec === 'AB';
                tests.push({ name: '十进制', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 数据不匹配\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: '十进制', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log(`[${++testStep}/${totalTests}] 维吉尼亚密码... `);
            try {
                const vigEnc = vigenereEncrypt('Hello', 'KEY');
                const vigDec = vigenereDecrypt(vigEnc, 'KEY');
                const ok = vigDec === 'Hello';
                tests.push({ name: '维吉尼亚', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 数据不匹配\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: '维吉尼亚', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log(`[${++testStep}/${totalTests}] 栅栏密码... `);
            try {
                const rfEnc = railFenceEncrypt('HelloWorld', 3);
                const rfDec = railFenceDecrypt(rfEnc, 3);
                const ok = rfDec === 'HelloWorld';
                tests.push({ name: '栅栏密码', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 数据不匹配\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: '栅栏密码', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log(`[${++testStep}/${totalTests}] 培根密码... `);
            try {
                const baconEnc = baconEncrypt('HELLO');
                const baconDec = baconDecode(baconEnc);
                const ok = baconDec === 'HELLO';
                tests.push({ name: '培根密码', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 数据不匹配\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: '培根密码', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log(`[${++testStep}/${totalTests}] 凯撒密码... `);
            try {
                const caesarEnc = caesarEncrypt('Hello', 3);
                const caesarDec = caesarDecrypt(caesarEnc, 3);
                const ok = caesarDec === 'Hello';
                tests.push({ name: '凯撒密码', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 数据不匹配\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: '凯撒密码', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log('\n【密码生成】\n');
            log(`[${++testStep}/${totalTests}] 密码生成器... `);
            try {
                const pwd = generatePassword(16, { upper: true, lower: true, numbers: true, symbols: true, excludeSimilar: false });
                const ok = pwd.length === 16;
                tests.push({ name: '密码生成', passed: ok });
                log(ok ? '✓ 正常\n' : '✗ 长度不正确\n');
                if (!ok) errorCount++;
            } catch (e) {
                tests.push({ name: '密码生成', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log('\n【数字签名】\n');
            log(`[${++testStep}/${totalTests}] ECDSA密钥生成... `);
            try {
                const signKeys = await generateECDSAKeyPair();
                tests.push({ name: 'ECDSA密钥生成', passed: !!signKeys.publicKey && !!signKeys.privateKey });
                log(signKeys.publicKey ? '✓ 正常\n' : '✗ 失败\n');

                log(`[${++testStep}/${totalTests}] 签名/验证... `);
                const testData = new TextEncoder().encode('签名测试数据');
                const signature = await signData(testData, signKeys.privateKey);
                const verified = await verifySignature(testData, signature, signKeys.publicKey);
                tests.push({ name: '签名验证', passed: verified });
                log(verified ? '✓ 正常\n' : '✗ 验证失败\n');
                if (!verified) errorCount++;

                log(`[${++testStep}/${totalTests}] 篡改检测... `);
                const tamperedData = new TextEncoder().encode('篡改测试数据');
                const tamperedVerified = await verifySignature(tamperedData, signature, signKeys.publicKey);
                tests.push({ name: '篡改检测', passed: !tamperedVerified });
                log(!tamperedVerified ? '✓ 正常（正确拒绝篡改数据）\n' : '✗ 未检测到篡改\n');
                if (tamperedVerified) errorCount++;

                log(`[${++testStep}/${totalTests}] 文件签名/验证... `);
                try {
                    const testFile = new File([new TextEncoder().encode('文件签名测试内容')], 'test.txt', { type: 'text/plain' });
                    const signResult = await signFile(testFile, signKeys.privateKey, signKeys.publicKey);
                    const verifyResult = await verifyFileSignature(testFile, signResult.blob, signKeys.publicKey);
                    const fileSignOk = verifyResult.valid && verifyResult.originalFileName === 'test.txt';
                    tests.push({ name: '文件签名', passed: fileSignOk });
                    log(fileSignOk ? '✓ 正常\n' : '✗ 验证失败\n');
                    if (!fileSignOk) errorCount++;
                } catch (e) {
                    tests.push({ name: '文件签名', passed: false });
                    log(`✗ ${e.message}\n`);
                    errorCount++;
                }
            } catch (e) {
                tests.push({ name: '数字签名', passed: false });
                log(`✗ ${e.message}\n`);
                errorCount++;
            }

            log('\n' + '─'.repeat(30) + '\n');
            const criticalPassed = tests.filter(t => ['Scrypt', '文件加密解密', '文本加密解密'].includes(t.name)).every(t => t.passed);

            if (criticalPassed && errorCount === 0) {
                log('✅ 所有测试通过！\n');
            } else if (criticalPassed) {
                log(`⚠️ 核心功能正常，${errorCount}项非关键测试失败\n`);
            } else {
                log(`❌ ${errorCount}项测试失败\n`);
            }

            log('\n' + '─'.repeat(30) + '\n');
            log('测试统计:\n');
            const passed = tests.filter(t => t.passed).length;
            log(`• 通过: ${passed}/${tests.length}\n`);
            log(`• 失败: ${tests.length - passed}/${tests.length}\n`);

            log('\n' + '─'.repeat(30) + '\n');
            log('鸣谢:\n');
            log('• Argon2 Browser • Web Crypto API\n');
            log('• zxcvbn • Inter Font\n');
            log('贡献者: 111, pinesis, Trae CN\n');

            resultDiv.classList.add(criticalPassed ? 'test-passed' : 'test-failed');

            const btnDiv = document.createElement('div');
            btnDiv.className = 'download-buttons';
            btnDiv.style.marginTop = '15px';
            btnDiv.innerHTML = `
                <div class="download-btn" id="exportTestBtn"><span>📋</span><span>导出报告</span></div>
                <div class="download-btn" id="clearTestBtn"><span>🗑️</span><span>清除结果</span></div>
            `;
            resultDiv.appendChild(btnDiv);

            document.getElementById('exportTestBtn')?.addEventListener('click', function () {
                const report = `SecureFx 自检报告\n${'='.repeat(40)}\n时间: ${new Date().toLocaleString()}\n\n${resultDiv.innerText}`;
                const blob = new Blob([report], { type: 'text/plain' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `selftest_${Date.now()}.txt`;
                a.click();
                URL.revokeObjectURL(url);
            });

            document.getElementById('clearTestBtn')?.addEventListener('click', function () {
                resultDiv.innerHTML = '';
                resultDiv.style.background = '';
                resultDiv.style.color = '';
            });

        } catch (e) {
            log(`\n❌ 自检出错: ${e.message}\n`);
            resultDiv.style.background = '#fef2f2';
            resultDiv.style.color = '#b91c1c';
        }
    }

    /* ============================================
       事件绑定与初始化
       ============================================ */

    document.addEventListener('DOMContentLoaded', async function () {
        const accepted = await showSecurityWarning();
        if (!accepted) {
            return;
        }

        checkEnvironment();
        checkGCMSupport();
        waitForArgon2().then(ready => { if (!ready) console.warn('Argon2库加载失败，将只能使用Scrypt算法'); });

        window.addEventListener('beforeunload', function (e) {
            if (operationInProgress) {
                e.preventDefault();
                e.returnValue = '操作正在进行中，确定要离开吗？';
                return e.returnValue;
            }
            if (keyDisplayActive) {
                if (keyTimer) {
                    clearInterval(keyTimer);
                    keyTimer = null;
                }
                const keyContent = document.getElementById('keyContent');
                if (keyContent) {
                    keyContent.textContent = '*** 已清除 ***';
                }
                keyDisplayActive = false;
            }
        });

        document.addEventListener('visibilitychange', function () {
            if (document.hidden && keyDisplayActive) {
                if (keyTimer) {
                    clearInterval(keyTimer);
                    keyTimer = null;
                }
                const keyContent = document.getElementById('keyContent');
                if (keyContent) {
                    keyContent.textContent = '*** 已清除 ***';
                }
                const keyDisplay = document.getElementById('keyDisplay');
                if (keyDisplay) {
                    keyDisplay.classList.remove('active');
                }
                keyDisplayActive = false;
            }
        });

        const savedTheme = localStorage.getItem('securefx-theme');
        if (savedTheme === 'dark') {
            document.documentElement.setAttribute('data-theme', 'dark');
            const themeToggle = document.getElementById('themeToggle');
            if (themeToggle) themeToggle.textContent = '☀️';
        }

        document.getElementById('themeToggle')?.addEventListener('click', function () {
            const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
            if (isDark) {
                document.documentElement.removeAttribute('data-theme');
                localStorage.setItem('securefx-theme', 'light');
                this.textContent = '🌙';
            } else {
                document.documentElement.setAttribute('data-theme', 'dark');
                localStorage.setItem('securefx-theme', 'dark');
                this.textContent = '☀️';
            }
        });



        document.querySelectorAll('.nav-item-pc, .nav-item').forEach(item => {
            item.addEventListener('click', function (e) {
                e.preventDefault();
                const target = this.dataset.target;
                document.querySelectorAll('.nav-item-pc, .nav-item').forEach(i => i.classList.remove('active'));
                this.classList.add('active');
                document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
                document.getElementById(target).classList.add('active');
            });
        });

        document.querySelectorAll('.algo-option[data-kdf]').forEach(option => {
            option.addEventListener('click', function () {
                document.querySelectorAll('.algo-option[data-kdf]').forEach(o => o.classList.remove('selected'));
                this.classList.add('selected');
                currentKdf = this.dataset.kdf === 'argon2' ? KDF_ARGON2 : KDF_SCRYPT;
            });
        });

        document.querySelectorAll('.algo-option[data-hash]').forEach(option => {
            option.addEventListener('click', function () {
                document.querySelectorAll('.algo-option[data-hash]').forEach(o => o.classList.remove('selected'));
                this.classList.add('selected');
                currentHashAlgo = this.dataset.hash;
            });
        });

        document.querySelectorAll('.mode-toggle').forEach(toggle => {
            toggle.querySelectorAll('.mode-toggle-btn').forEach(btn => {
                btn.addEventListener('click', function () {
                    toggle.querySelectorAll('.mode-toggle-btn').forEach(b => b.classList.remove('active'));
                    this.classList.add('active');
                    const mode = this.dataset.mode;

                    if (toggle.closest('#file-encrypt-section')) {
                        if (mode === 'encrypt') {
                            document.getElementById('fileEncryptBtn').style.display = 'block';
                            document.getElementById('fileDecryptBtn').style.display = 'none';
                        } else {
                            document.getElementById('fileEncryptBtn').style.display = 'none';
                            document.getElementById('fileDecryptBtn').style.display = 'block';
                        }
                    } else if (toggle.closest('#text-encrypt-section')) {
                        if (mode === 'encrypt') {
                            document.getElementById('textEncryptBtn').style.display = 'block';
                            document.getElementById('textDecryptBtn').style.display = 'none';
                        } else {
                            document.getElementById('textEncryptBtn').style.display = 'none';
                            document.getElementById('textDecryptBtn').style.display = 'block';
                        }
                    } else if (toggle.closest('#rsa-section')) {
                        if (toggle.dataset.rsaMode) {
                            document.getElementById('rsa-generate-panel').style.display = mode === 'generate' ? 'block' : 'none';
                            document.getElementById('rsa-encrypt-panel').style.display = mode === 'encrypt' ? 'block' : 'none';
                            document.getElementById('rsa-decrypt-panel').style.display = mode === 'decrypt' ? 'block' : 'none';
                        } else if (toggle.dataset.eccMode) {
                            document.getElementById('ecc-generate-panel').style.display = mode === 'generate' ? 'block' : 'none';
                            document.getElementById('ecc-encrypt-panel').style.display = mode === 'encrypt' ? 'block' : 'none';
                            document.getElementById('ecc-decrypt-panel').style.display = mode === 'decrypt' ? 'block' : 'none';
                        }
                    } else if (toggle.closest('#base64-section')) {
                        if (mode === 'encode') {
                            document.getElementById('base64EncodeBtn').style.display = 'block';
                            document.getElementById('base64DecodeBtn').style.display = 'none';
                        } else {
                            document.getElementById('base64EncodeBtn').style.display = 'none';
                            document.getElementById('base64DecodeBtn').style.display = 'block';
                        }
                    }
                });
            });
        });

        document.getElementById('fileInput').addEventListener('change', function () {
            const file = this.files[0];
            const fileInfo = document.getElementById('fileInfo');
            if (file) {
                fileInfo.classList.add('active');
                fileInfo.innerHTML = `<div class="file-info-row"><span class="file-info-label">文件名:</span><span class="file-info-value">${file.name}</span></div><div class="file-info-row"><span class="file-info-label">大小:</span><span class="file-info-value">${formatSize(file.size)}</span></div><div class="file-info-row"><span class="file-info-label">类型:</span><span class="file-info-value">${file.type || '未知'}</span></div>`;
                updateFileUploadArea('fileUploadArea', file.name);
            } else {
                fileInfo.classList.remove('active');
            }
        });

        document.getElementById('fileHashInput')?.addEventListener('change', function () {
            const file = this.files[0];
            const fileInfo = document.getElementById('fileHashInfo');
            if (file) {
                fileInfo.classList.add('active');
                fileInfo.innerHTML = `<div class="file-info-row"><span class="file-info-label">文件名:</span><span class="file-info-value">${file.name}</span></div><div class="file-info-row"><span class="file-info-label">大小:</span><span class="file-info-value">${formatSize(file.size)}</span></div>`;
                updateFileUploadArea('fileHashUploadArea', file.name);
            } else {
                fileInfo.classList.remove('active');
            }
        });

        setupDragDrop('fileUploadArea', 'fileInput');
        setupDragDrop('fileHashUploadArea', 'fileHashInput');
        setupCancelButton();

        document.getElementById('filePassword')?.addEventListener('input', function () {
            const password = this.value;
            const strengthDiv = document.getElementById('filePasswordStrength');
            if (password.length > 0) {
                const result = evaluatePassword(password);
                strengthDiv.classList.add('active');
                strengthDiv.className = `password-strength active ${result.class}`;
                strengthDiv.innerHTML = `<div style="display:flex;justify-content:space-between;margin-bottom:8px;"><span>密码强度: ${result.label}</span><span>${result.crackTime}</span></div><div class="strength-bar"><div class="strength-fill" style="width:${((result.score + 1) * 25)}%;background:${result.score < 2 ? '#ef4444' : result.score < 3 ? '#f59e0b' : result.score < 4 ? '#10b981' : '#059669'}"></div></div>`;
            } else {
                strengthDiv.classList.remove('active');
            }
        });

        document.getElementById('anonymousMode')?.addEventListener('change', function () {
            anonymousMode = this.checked;
        });

        document.getElementById('enableSignEncrypt')?.addEventListener('change', function () {
            const privateKeyArea = document.getElementById('signEncryptPrivateKey');
            if (privateKeyArea) {
                privateKeyArea.style.display = this.checked ? 'block' : 'none';
            }
        });

        document.querySelectorAll('[data-encrypt-type]').forEach(btn => {
            btn.addEventListener('click', function () {
                document.querySelectorAll('[data-encrypt-type]').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                const type = this.dataset.encryptType;
                document.getElementById('file-encrypt-panel').style.display = type === 'file' ? 'block' : 'none';
                document.getElementById('text-encrypt-panel').style.display = type === 'text' ? 'block' : 'none';
            });
        });

        document.querySelectorAll('[data-asym-type]').forEach(btn => {
            btn.addEventListener('click', function () {
                document.querySelectorAll('[data-asym-type]').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                const type = this.dataset.asymType;
                document.getElementById('rsa-panel').style.display = type === 'rsa' ? 'block' : 'none';
                document.getElementById('ecc-panel').style.display = type === 'ecc' ? 'block' : 'none';
            });
        });

        document.getElementById('fileEncryptBtn').addEventListener('click', async function () {
            const file = document.getElementById('fileInput').files[0];
            const resultDiv = document.getElementById('fileResult');
            const btn = this;

            if (!file) { showResult(resultDiv, '请选择要加密的文件', 'error'); return; }

            let secret;
            let pwdBytes = null;
            if (currentMode === 'password') {
                const password = document.getElementById('filePassword').value;
                if (!password || password.length < 8) { showResult(resultDiv, '密码至少需要8位字符', 'error'); return; }
                pwdBytes = new TextEncoder().encode(password);
                document.getElementById('filePassword').value = '';
                secret = password;
            } else {
                const keyInput = document.getElementById('keyInput')?.value;
                if (!keyInput) { showResult(resultDiv, '请生成或输入加密密钥', 'error'); return; }
                try { secret = base64ToArray(keyInput); } catch (e) { showResult(resultDiv, '无效的密钥格式', 'error'); return; }
            }

            let signKey = null;
            const enableSign = document.getElementById('enableSignEncrypt')?.checked;
            if (enableSign) {
                signKey = document.getElementById('signEncryptPrivateKey')?.value;
                if (!signKey) {
                    showResult(resultDiv, '请输入签名私钥', 'error');
                    return;
                }
            }

            const canUseWorker = file.size > LARGE_FILE_THRESHOLD && window.location.protocol !== 'file:';
            const useWorker = canUseWorker;

            const progressCallback = (percent, message) => updateProgress('file', percent, message);

            try {
                btn.disabled = true;
                operationInProgress = true;
                document.getElementById('fileProgress').style.display = 'block';
                updateProgress('file', 0, useWorker ? '使用Worker处理大文件...' : '正在初始化...');

                let result;
                if (useWorker) {
                    try {
                        result = await encryptFileWithWorker(file, secret, { kdfType: currentKdf, anonymous: anonymousMode, signKey: signKey });
                    } catch (workerError) {
                        console.warn('Worker加密失败，回退到主线程:', workerError);
                        updateProgress('file', 0, 'Worker失败，使用主线程处理...');
                        result = await encryptFileV2(file, secret, { kdfType: currentKdf, anonymous: anonymousMode, signKey: signKey, onProgress: progressCallback });
                    }
                } else {
                    result = await encryptFileV2(file, secret, { kdfType: currentKdf, anonymous: anonymousMode, signKey: signKey, onProgress: progressCallback });
                }

                encryptedBlob = result.blob;
                decryptedBlob = null;
                encryptedFilename = result.filename;
                document.getElementById('fileDownloadBtns').style.display = 'grid';
                const signInfo = signKey ? '<br>签名: ✅ 已签名' : '';
                const workerInfo = useWorker ? '<br>处理方式: Web Worker' : '';
                showResult(resultDiv, `✅ 加密成功！<br>格式: v2 (.sfx)<br>算法: ${currentKdf === KDF_ARGON2 ? 'Argon2id' : 'Scrypt'}<br>模式: ${gcmSupported ? 'AES-GCM' : 'AES-CBC'}<br>HMAC: 已启用${signInfo}${workerInfo}`, 'success');

                AuditLog.log('file_encrypt', {
                    filename: file.name,
                    size: file.size,
                    algo: currentKdf === KDF_ARGON2 ? 'Argon2id' : 'Scrypt',
                    mode: gcmSupported ? 'AES-GCM' : 'AES-CBC',
                    signed: !!signKey,
                    worker: useWorker
                });
            } catch (error) {
                const secError = secureError(error);
                showResult(resultDiv, `❌ 加密失败: ${secError.message}`, 'error');
            } finally {
                operationInProgress = false;
                if (pwdBytes) attemptMemoryClear(pwdBytes);
                setTimeout(() => { btn.disabled = false; document.getElementById('fileProgress').style.display = 'none'; }, 1000);
            }
        });

        document.getElementById('fileDecryptBtn').addEventListener('click', async function () {
            const file = document.getElementById('fileInput').files[0];
            const resultDiv = document.getElementById('fileResult');
            const btn = this;

            if (!file) { showResult(resultDiv, '请选择要解密的文件', 'error'); return; }

            let secret;
            let pwdBytes = null;
            if (currentMode === 'password') {
                const password = document.getElementById('filePassword').value;
                if (!password) { showResult(resultDiv, '请输入解密密码', 'error'); return; }
                pwdBytes = new TextEncoder().encode(password);
                document.getElementById('filePassword').value = '';
                secret = password;
            } else {
                const keyInput = document.getElementById('keyInput')?.value;
                if (!keyInput) { showResult(resultDiv, '请输入解密密钥', 'error'); return; }
                try { secret = base64ToArray(keyInput); } catch (e) { showResult(resultDiv, '无效的密钥格式', 'error'); return; }
            }

            const canUseWorker = file.size > LARGE_FILE_THRESHOLD && window.location.protocol !== 'file:';
            const useWorker = canUseWorker;

            const progressCallback = (percent, message) => updateProgress('file', percent, message);

            try {
                btn.disabled = true;
                operationInProgress = true;
                document.getElementById('fileProgress').style.display = 'block';
                updateProgress('file', 0, useWorker ? '使用Worker处理大文件...' : '正在初始化...');

                const fileData = new Uint8Array(await file.arrayBuffer());

                let result;
                if (useWorker) {
                    try {
                        result = await decryptFileWithWorker(fileData, secret);
                    } catch (workerError) {
                        console.warn('Worker解密失败，回退到主线程:', workerError);
                        updateProgress('file', 0, 'Worker失败，使用主线程处理...');
                        result = await decryptFileV2(fileData, secret, { onProgress: progressCallback });
                    }
                } else {
                    result = await decryptFileV2(fileData, secret, { onProgress: progressCallback });
                }

                decryptedBlob = result.data;
                encryptedBlob = null;
                decryptedFilename = result.originalName;
                document.getElementById('fileDownloadBtns').style.display = 'grid';

                let signInfo = '';
                if (result.signature) {
                    signInfo = '<br>签名: ✅ 文件已签名（签名验证需要发送者公钥）';
                }
                const workerInfo = useWorker ? '<br>处理方式: Web Worker' : '';
                showResult(resultDiv, `✅ 解密成功！<br>原始文件名: ${result.originalName}<br>格式版本: ${result.metadata.version}${signInfo}${workerInfo}`, 'success');

                AuditLog.log('file_decrypt', {
                    filename: file.name,
                    originalName: result.originalName,
                    version: result.metadata.version,
                    worker: useWorker
                });
            } catch (error) {
                const secError = secureError(error);
                showResult(resultDiv, `❌ 解密失败: ${secError.message}`, 'error');
                document.getElementById('fileDownloadBtns').style.display = 'none';
            } finally {
                operationInProgress = false;
                if (pwdBytes) attemptMemoryClear(pwdBytes);
                setTimeout(() => { btn.disabled = false; document.getElementById('fileProgress').style.display = 'none'; }, 1000);
            }
        });

        document.querySelectorAll('[data-selftest-type]').forEach(btn => {
            btn.addEventListener('click', function () {
                document.querySelectorAll('[data-selftest-type]').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                const type = this.dataset.selftestType;
                document.getElementById('selftest-panel').style.display = type === 'test' ? 'block' : 'none';
                document.getElementById('guide-panel').style.display = type === 'guide' ? 'block' : 'none';
            });
        });

        document.querySelectorAll('[data-guide]').forEach(btn => {
            btn.addEventListener('click', function () {
                document.querySelectorAll('[data-guide]').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                const type = this.dataset.guide;
                document.querySelectorAll('.guide-detail').forEach(d => d.style.display = 'none');
                const target = document.getElementById('guide-' + type);
                if (target) target.style.display = 'block';
            });
        });

        document.getElementById('runSelfTestBtn').addEventListener('click', runSelfTest);

        document.getElementById('fileDownloadBtn')?.addEventListener('click', function () {
            if (encryptedBlob) downloadFile(encryptedBlob, encryptedFilename);
            else if (decryptedBlob) downloadFile(decryptedBlob, decryptedFilename);
        });

        document.getElementById('generateKeyBtn')?.addEventListener('click', function () {
            const length = parseInt(document.getElementById('keyLength').value) || 32;
            const key = generateRandomKey(length);
            const keyDisplay = document.getElementById('keyDisplay');
            const keyContent = document.getElementById('keyContent');
            keyContent.textContent = arrayToBase64(key);
            keyDisplay.classList.add('active');
            keyDisplayActive = true;
            let seconds = 5;
            document.getElementById('keyTimer').textContent = `${seconds}秒后清除`;
            if (keyTimer) clearInterval(keyTimer);
            keyTimer = setInterval(() => {
                seconds--;
                document.getElementById('keyTimer').textContent = `${seconds}秒后清除`;
                if (seconds <= 0) {
                    clearInterval(keyTimer);
                    keyTimer = null;
                    keyContent.textContent = '*** 已清除 ***';
                    keyDisplayActive = false;
                    setTimeout(() => keyDisplay.classList.remove('active'), 1000);
                }
            }, 1000);
        });

        document.getElementById('textEncryptBtn')?.addEventListener('click', async function () {
            const text = document.getElementById('textInput').value;
            const password = document.getElementById('textPassword').value;
            if (!text) { alert('请输入要加密的文本'); return; }
            if (!password) { alert('请输入密码'); return; }
            try {
                this.disabled = true;
                const encrypted = await encryptText(text, password);
                document.getElementById('textOutput').value = encrypted;
            } catch (e) { alert('加密失败: ' + e.message); }
            finally { this.disabled = false; }
        });

        document.getElementById('textDecryptBtn')?.addEventListener('click', async function () {
            const text = document.getElementById('textInput').value;
            const password = document.getElementById('textPassword').value;
            if (!text) { alert('请输入要解密的文本'); return; }
            if (!password) { alert('请输入密码'); return; }
            try {
                this.disabled = true;
                const decrypted = await decryptText(text, password);
                document.getElementById('textOutput').value = decrypted;
            } catch (e) { alert('解密失败: ' + e.message); }
            finally { this.disabled = false; }
        });

        document.getElementById('copyTextBtn')?.addEventListener('click', async function () {
            const output = document.getElementById('textOutput').value;
            if (output) {
                try { await navigator.clipboard.writeText(output); alert('已复制到剪贴板'); }
                catch (e) { alert('复制失败'); }
            }
        });

        document.getElementById('clearTextBtn')?.addEventListener('click', function () {
            document.getElementById('textInput').value = '';
            document.getElementById('textPassword').value = '';
            document.getElementById('textOutput').value = '';
        });

        document.getElementById('generateRSAKeysBtn')?.addEventListener('click', async function () {
            const keySize = parseInt(document.getElementById('rsaKeySize').value) || 2048;
            try {
                this.disabled = true;
                this.textContent = '正在生成...';
                const keys = await generateRSAKeyPair(keySize);
                document.getElementById('rsaPublicKey').value = keys.publicKey;
                document.getElementById('rsaPrivateKey').value = keys.privateKey;
                document.getElementById('rsaOutput').value = `公钥:\n${keys.publicKey}\n\n私钥:\n${keys.privateKey}`;
                document.getElementById('rsaDownloadBtns').style.display = 'grid';
                alert('RSA密钥对生成成功！');
            } catch (e) { alert('生成失败: ' + e.message); }
            finally { this.disabled = false; this.textContent = '🎲 生成RSA密钥对'; }
        });

        document.getElementById('rsaEncryptBtn')?.addEventListener('click', async function () {
            const publicKey = document.getElementById('rsaPublicKey').value;
            const plaintext = document.getElementById('rsaPlaintext').value;
            if (!publicKey) { alert('请输入公钥'); return; }
            if (!plaintext) { alert('请输入要加密的文本'); return; }
            try {
                this.disabled = true;
                const encrypted = await encryptRSA(plaintext, publicKey);
                document.getElementById('rsaOutput').value = encrypted;
            } catch (e) { alert('加密失败: ' + e.message); }
            finally { this.disabled = false; }
        });

        document.getElementById('rsaDecryptBtn')?.addEventListener('click', async function () {
            const privateKey = document.getElementById('rsaPrivateKey').value;
            const ciphertext = document.getElementById('rsaCiphertext').value;
            if (!privateKey) { alert('请输入私钥'); return; }
            if (!ciphertext) { alert('请输入加密文本'); return; }
            try {
                this.disabled = true;
                const decrypted = await decryptRSA(ciphertext, privateKey);
                document.getElementById('rsaOutput').value = decrypted;
            } catch (e) { alert('解密失败: ' + e.message); }
            finally { this.disabled = false; }
        });

        document.getElementById('copyRSABtn')?.addEventListener('click', async function () {
            const output = document.getElementById('rsaOutput').value;
            if (output) {
                try { await navigator.clipboard.writeText(output); alert('已复制'); }
                catch (e) { alert('复制失败'); }
            }
        });

        document.getElementById('downloadRSAKeysBtn')?.addEventListener('click', function () {
            const keys = document.getElementById('rsaOutput').value;
            if (keys) {
                const blob = new Blob([keys], { type: 'text/plain' });
                downloadFile(blob, 'rsa_keys.txt');
            }
        });

        document.querySelectorAll('[data-hash-type]').forEach(btn => {
            btn.addEventListener('click', function () {
                document.querySelectorAll('[data-hash-type]').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                const type = this.dataset.hashType;
                document.getElementById('text-hash-panel').style.display = type === 'text' ? 'block' : 'none';
                document.getElementById('file-hash-panel').style.display = type === 'file' ? 'block' : 'none';
            });
        });

        document.getElementById('calculateHashBtn')?.addEventListener('click', async function () {
            const text = document.getElementById('hashInput').value;
            if (!text) { alert('请输入文本'); return; }
            try {
                this.disabled = true;
                const hash = await calculateHash(text, currentHashAlgo);
                const resultsDiv = document.getElementById('hashResults');
                resultsDiv.innerHTML = `<div class="hash-result-item"><span class="hash-algo">${currentHashAlgo.toUpperCase()}</span><span class="hash-value">${hash}</span><button class="copy-hash-btn" data-hash="${hash}">📋</button></div>`;
                resultsDiv.querySelectorAll('.copy-hash-btn').forEach(btn => {
                    btn.addEventListener('click', async function () {
                        try { await navigator.clipboard.writeText(this.dataset.hash); alert('已复制'); }
                        catch (e) { alert('复制失败'); }
                    });
                });
            } catch (e) { alert('计算失败: ' + e.message); }
            finally { this.disabled = false; }
        });

        document.getElementById('calculateFileHashBtn')?.addEventListener('click', async function () {
            const file = document.getElementById('fileHashInput').files[0];
            if (!file) { alert('请选择文件'); return; }
            const algo = document.getElementById('fileHashAlgo')?.value || 'sha256';
            try {
                this.disabled = true;
                document.getElementById('fileHashProgress').style.display = 'block';
                const hash = await calculateFileHash(file, algo, (p, m) => {
                    document.getElementById('fileHashProgressFill').style.width = `${p}%`;
                    document.getElementById('fileHashStatus').textContent = m;
                    document.getElementById('fileHashPercent').textContent = `${p}%`;
                });
                const resultsDiv = document.getElementById('fileHashResults');
                resultsDiv.innerHTML = `<div class="hash-result-item"><span class="hash-algo">${algo.toUpperCase()}</span><span class="hash-value">${hash}</span><button class="copy-hash-btn" data-hash="${hash}">📋</button></div>`;

                const verifyHash = document.getElementById('verifyHash').value.trim().toLowerCase();
                if (verifyHash) {
                    const resultDiv = document.getElementById('hashVerifyResult');
                    if (hash.toLowerCase() === verifyHash) {
                        showResult(resultDiv, '✅ 校验成功！哈希值匹配', 'success');
                    } else {
                        showResult(resultDiv, '❌ 校验失败！哈希值不匹配', 'error');
                    }
                }

                resultsDiv.querySelectorAll('.copy-hash-btn').forEach(btn => {
                    btn.addEventListener('click', async function () {
                        try { await navigator.clipboard.writeText(this.dataset.hash); alert('已复制'); }
                        catch (e) { alert('复制失败'); }
                    });
                });
            } catch (e) { alert('计算失败: ' + e.message); }
            finally { this.disabled = false; document.getElementById('fileHashProgress').style.display = 'none'; }
        });

        document.getElementById('base64EncodeBtn')?.addEventListener('click', function () {
            const input = document.getElementById('base64Input').value;
            if (!input) { alert('请输入文本'); return; }
            try {
                const encoded = base64Encode(input);
                document.getElementById('base64Output').value = encoded;
            } catch (e) { alert('编码失败: ' + e.message); }
        });

        document.getElementById('base64DecodeBtn')?.addEventListener('click', function () {
            const input = document.getElementById('base64Input').value;
            if (!input) { alert('请输入Base64字符串'); return; }
            try {
                const decoded = base64Decode(input);
                document.getElementById('base64Output').value = decoded;
            } catch (e) { alert('解码失败: 无效的Base64字符串'); }
        });

        document.getElementById('copyBase64Btn')?.addEventListener('click', async function () {
            const output = document.getElementById('base64Output').value;
            if (output) {
                try { await navigator.clipboard.writeText(output); alert('已复制'); }
                catch (e) { alert('复制失败'); }
            }
        });

        document.getElementById('clearBase64Btn')?.addEventListener('click', function () {
            document.getElementById('base64Input').value = '';
            document.getElementById('base64Output').value = '';
        });

        let currentEncoding = 'base32';
        document.querySelectorAll('.algo-option[data-encode]').forEach(option => {
            option.addEventListener('click', function () {
                document.querySelectorAll('.algo-option[data-encode]').forEach(o => o.classList.remove('selected'));
                this.classList.add('selected');
                currentEncoding = this.dataset.encode;
                document.getElementById('caesarShiftGroup').style.display = currentEncoding === 'caesar' ? 'block' : 'none';
                document.getElementById('vigenereKeyGroup').style.display = currentEncoding === 'vigenere' ? 'block' : 'none';
                document.getElementById('railfenceRailsGroup').style.display = currentEncoding === 'railfence' ? 'block' : 'none';
                document.getElementById('affineParamsGroup').style.display = currentEncoding === 'affine' ? 'block' : 'none';
                document.getElementById('sm4KeyGroup').style.display = currentEncoding === 'sm4' ? 'block' : 'none';
                document.getElementById('chacha20KeyGroup').style.display = currentEncoding === 'chacha20' ? 'block' : 'none';
            });
        });

        document.getElementById('caesarShift')?.addEventListener('input', function () {
            document.getElementById('caesarShiftValue').textContent = this.value;
        });

        document.getElementById('railfenceRails')?.addEventListener('input', function () {
            document.getElementById('railfenceRailsValue').textContent = this.value;
        });

        document.getElementById('encodingEncodeBtn')?.addEventListener('click', function () {
            const input = document.getElementById('encodingInput').value;
            if (!input) { alert('请输入文本'); return; }
            try {
                let result;
                switch (currentEncoding) {
                    case 'base32': result = base32Encode(input); break;
                    case 'base58': result = base58Encode(input); break;
                    case 'vigenere': result = vigenereEncrypt(input, document.getElementById('vigenereKey').value); break;
                    case 'railfence': result = railFenceEncrypt(input, parseInt(document.getElementById('railfenceRails').value)); break;
                    case 'bacon': result = baconEncrypt(input); break;
                    case 'atbash': result = atbash(input); break;
                    case 'affine': result = affineEncrypt(input, parseInt(document.getElementById('affineA').value), parseInt(document.getElementById('affineB').value)); break;
                    case 'morse': result = morseEncode(input); break;
                    case 'emoji': result = emojiEncode(input); break;
                    case 'pigpen': result = pigPenEncrypt(input); break;
                    case 'reverse': result = reverseText(input); break;
                    case 'binary': result = textToBinary(input); break;
                    case 'octal': result = textToOctal(input); break;
                    case 'decimal': result = textToDecimal(input); break;
                    case 'hex': result = textToHex(input); break;
                    case 'caesar': result = caesarEncrypt(input, parseInt(document.getElementById('caesarShift').value)); break;
                    case 'rot13': result = rot13(input); break;
                    case 'sm4': {
                        let keyHex = document.getElementById('sm4Key').value.trim();
                        if (!keyHex) {
                            keyHex = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('');
                            document.getElementById('sm4Key').value = keyHex;
                        }
                        const key = hexToArray(keyHex);
                        const data = new TextEncoder().encode(input);
                        const encrypted = sm4Encrypt(data, key);
                        result = `密钥: ${keyHex}\n密文(Hex): ${arrayToHex(encrypted)}`;
                        break;
                    }
                    case 'chacha20': {
                        let keyHex = document.getElementById('chacha20Key').value.trim();
                        if (!keyHex) {
                            keyHex = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('');
                            document.getElementById('chacha20Key').value = keyHex;
                        }
                        const key = hexToArray(keyHex);
                        const nonce = crypto.getRandomValues(new Uint8Array(12));
                        const data = new TextEncoder().encode(input);
                        const encrypted = chacha20Encrypt(data, key, nonce);
                        result = `密钥: ${keyHex}\nNonce: ${arrayToHex(nonce)}\n密文(Hex): ${arrayToHex(encrypted)}`;
                        break;
                    }
                    default: result = input;
                }
                document.getElementById('encodingOutput').value = result;
            } catch (e) { alert('编码失败: ' + e.message); }
        });

        document.getElementById('encodingDecodeBtn')?.addEventListener('click', function () {
            const input = document.getElementById('encodingInput').value;
            if (!input) { alert('请输入文本'); return; }
            try {
                let result;
                switch (currentEncoding) {
                    case 'base32': result = base32Decode(input); break;
                    case 'base58': result = base58Decode(input); break;
                    case 'vigenere': result = vigenereDecrypt(input, document.getElementById('vigenereKey').value); break;
                    case 'railfence': result = railFenceDecrypt(input, parseInt(document.getElementById('railfenceRails').value)); break;
                    case 'bacon': result = baconDecode(input); break;
                    case 'atbash': result = atbash(input); break;
                    case 'affine': result = affineDecrypt(input, parseInt(document.getElementById('affineA').value), parseInt(document.getElementById('affineB').value)); break;
                    case 'morse': result = morseDecode(input); break;
                    case 'emoji': result = emojiDecode(input); break;
                    case 'pigpen': result = pigPenDecode(input); break;
                    case 'reverse': result = reverseText(input); break;
                    case 'binary': result = binaryToText(input); break;
                    case 'octal': result = octalToText(input); break;
                    case 'decimal': result = decimalToText(input); break;
                    case 'hex': result = hexToText(input); break;
                    case 'caesar': result = caesarDecrypt(input, parseInt(document.getElementById('caesarShift').value)); break;
                    case 'rot13': result = rot13(input); break;
                    case 'sm4': {
                        const keyHex = document.getElementById('sm4Key').value.trim();
                        if (!keyHex) { alert('请输入SM4密钥'); return; }
                        const lines = input.split('\n');
                        const cipherLine = lines.find(l => l.startsWith('密文(Hex):'));
                        if (!cipherLine) { alert('请输入正确格式：密文(Hex): xxx'); return; }
                        const cipherHex = cipherLine.split(':')[1].trim();
                        const key = hexToArray(keyHex);
                        const cipher = hexToArray(cipherHex);
                        const decrypted = sm4Decrypt(cipher, key);
                        result = new TextDecoder().decode(decrypted);
                        break;
                    }
                    case 'chacha20': {
                        const keyHex = document.getElementById('chacha20Key').value.trim();
                        if (!keyHex) { alert('请输入ChaCha20密钥'); return; }
                        const lines = input.split('\n');
                        const nonceLine = lines.find(l => l.startsWith('Nonce:'));
                        const cipherLine = lines.find(l => l.startsWith('密文(Hex):'));
                        if (!nonceLine || !cipherLine) { alert('请输入正确格式'); return; }
                        const nonceHex = nonceLine.split(':')[1].trim();
                        const cipherHex = cipherLine.split(':')[1].trim();
                        const key = hexToArray(keyHex);
                        const nonce = hexToArray(nonceHex);
                        const cipher = hexToArray(cipherHex);
                        const decrypted = chacha20Decrypt(cipher, key, nonce);
                        result = new TextDecoder().decode(decrypted);
                        break;
                    }
                    default: result = input;
                }
                document.getElementById('encodingOutput').value = result;
            } catch (e) {
                let errorMsg = e.message;
                if (currentEncoding === 'base32') errorMsg = '无效的Base32字符串';
                if (currentEncoding === 'base58') errorMsg = '无效的Base58字符串';
                alert('解码失败: ' + errorMsg);
            }
        });

        document.getElementById('copyEncodingBtn')?.addEventListener('click', async function () {
            const output = document.getElementById('encodingOutput').value;
            if (output) {
                try { await navigator.clipboard.writeText(output); alert('已复制'); }
                catch (e) { alert('复制失败'); }
            }
        });

        document.getElementById('clearEncodingBtn')?.addEventListener('click', function () {
            document.getElementById('encodingInput').value = '';
            document.getElementById('encodingOutput').value = '';
        });

        document.querySelectorAll('#ecc-section .mode-toggle-btn').forEach(btn => {
            btn.addEventListener('click', function () {
                document.querySelectorAll('#ecc-section .mode-toggle-btn').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                const mode = this.dataset.mode;
                document.getElementById('ecc-generate-panel').style.display = mode === 'generate' ? 'block' : 'none';
                document.getElementById('ecc-encrypt-panel').style.display = mode === 'encrypt' ? 'block' : 'none';
                document.getElementById('ecc-decrypt-panel').style.display = mode === 'decrypt' ? 'block' : 'none';
            });
        });

        document.getElementById('generateECCKeysBtn')?.addEventListener('click', async function () {
            try {
                this.disabled = true;
                this.textContent = '正在生成...';
                const keys = await generateECCKeys();
                document.getElementById('eccPublicKey').value = keys.publicKey;
                document.getElementById('eccPrivateKey').value = keys.privateKey;
                document.getElementById('eccOutput').value = `公钥:\n${keys.publicKey}\n\n私钥:\n${keys.privateKey}`;
                alert('ECC密钥对生成成功！');
            } catch (e) { alert('生成失败: ' + e.message); }
            finally { this.disabled = false; this.textContent = '🔵 生成 ECC 密钥对 (P-256)'; }
        });

        document.getElementById('eccEncryptBtn')?.addEventListener('click', async function () {
            const publicKey = document.getElementById('eccRecipientPublicKey').value;
            const plaintext = document.getElementById('eccPlaintext').value;
            if (!publicKey) { alert('请输入接收方公钥'); return; }
            if (!plaintext) { alert('请输入要加密的文本'); return; }
            try {
                this.disabled = true;
                const encrypted = await eccEncrypt(plaintext, publicKey);
                document.getElementById('eccOutput').value = encrypted;
            } catch (e) { alert('加密失败: ' + e.message); }
            finally { this.disabled = false; }
        });

        document.getElementById('eccDecryptBtn')?.addEventListener('click', async function () {
            const privateKey = document.getElementById('eccDecryptPrivateKey').value;
            const ciphertext = document.getElementById('eccCiphertext').value;
            if (!privateKey) { alert('请输入私钥'); return; }
            if (!ciphertext) { alert('请输入加密文本'); return; }
            try {
                this.disabled = true;
                const decrypted = await eccDecrypt(ciphertext, privateKey);
                document.getElementById('eccOutput').value = decrypted;
            } catch (e) { alert('解密失败: ' + e.message); }
            finally { this.disabled = false; }
        });

        document.getElementById('copyECCBtn')?.addEventListener('click', async function () {
            const output = document.getElementById('eccOutput').value;
            if (output) {
                try { await navigator.clipboard.writeText(output); alert('已复制'); }
                catch (e) { alert('复制失败'); }
            }
        });

        document.getElementById('downloadECCKeysBtn')?.addEventListener('click', function () {
            const keys = document.getElementById('eccOutput').value;
            if (keys) {
                const blob = new Blob([keys], { type: 'text/plain' });
                downloadFile(blob, 'ecc_keys.txt');
            }
        });

        document.querySelectorAll('#signature-section .mode-toggle-btn').forEach(btn => {
            btn.addEventListener('click', function () {
                document.querySelectorAll('#signature-section .mode-toggle-btn').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                const mode = this.dataset.mode;
                document.getElementById('signature-generate-panel').style.display = mode === 'generate' ? 'block' : 'none';
                document.getElementById('signature-sign-panel').style.display = mode === 'sign' ? 'block' : 'none';
                document.getElementById('signature-verify-panel').style.display = mode === 'verify' ? 'block' : 'none';
                document.getElementById('signature-file-sign-panel').style.display = mode === 'file-sign' ? 'block' : 'none';
            });
        });

        document.getElementById('generateSignKeysBtn')?.addEventListener('click', async function () {
            try {
                this.disabled = true;
                this.textContent = '正在生成...';
                const keys = await generateECDSAKeyPair();
                document.getElementById('signPublicKey').value = keys.publicKey;
                document.getElementById('signPrivateKey').value = keys.privateKey;
                document.getElementById('signKeyFingerprint').value = keys.fingerprint;
                document.getElementById('signatureOutput').value = `公钥:\n${keys.publicKey}\n\n私钥:\n${keys.privateKey}\n\n指纹: ${keys.fingerprint}`;
                document.getElementById('signatureDownloadBtns').style.display = 'grid';
                alert('ECDSA签名密钥对生成成功！');
            } catch (e) { alert('生成失败: ' + e.message); }
            finally { this.disabled = false; this.textContent = '✍️ 生成 ECDSA 签名密钥对 (P-256)'; }
        });

        document.getElementById('signDataBtn')?.addEventListener('click', async function () {
            const privateKey = document.getElementById('signPrivateKeyInput').value;
            const plaintext = document.getElementById('signPlaintext').value;
            if (!privateKey) { alert('请输入私钥'); return; }
            if (!plaintext) { alert('请输入要签名的文本'); return; }
            try {
                this.disabled = true;
                const data = new TextEncoder().encode(plaintext);
                const signature = await signData(data, privateKey);
                const signatureBase64 = arrayToBase64(signature);
                document.getElementById('signatureOutput').value = signatureBase64;
                document.getElementById('signatureDownloadBtns').style.display = 'grid';
            } catch (e) { alert('签名失败: ' + e.message); }
            finally { this.disabled = false; }
        });

        document.getElementById('verifySignBtn')?.addEventListener('click', async function () {
            const publicKey = document.getElementById('verifyPublicKey').value;
            const plaintext = document.getElementById('verifyPlaintext').value;
            const signatureBase64 = document.getElementById('verifySignature').value;
            if (!publicKey) { alert('请输入公钥'); return; }
            if (!plaintext) { alert('请输入原始文本'); return; }
            if (!signatureBase64) { alert('请输入签名'); return; }
            try {
                this.disabled = true;
                const data = new TextEncoder().encode(plaintext);
                const signature = base64ToArray(signatureBase64);
                const valid = await verifySignature(data, signature, publicKey);
                if (valid) {
                    document.getElementById('signatureOutput').value = '✅ 签名验证成功！\n\n签名有效，数据未被篡改。';
                } else {
                    document.getElementById('signatureOutput').value = '❌ 签名验证失败！\n\n签名无效，数据可能已被篡改。';
                }
            } catch (e) {
                document.getElementById('signatureOutput').value = '❌ 验证出错: ' + e.message;
            }
            finally { this.disabled = false; }
        });

        document.getElementById('copySignatureBtn')?.addEventListener('click', async function () {
            const output = document.getElementById('signatureOutput').value;
            if (output) {
                try { await navigator.clipboard.writeText(output); alert('已复制'); }
                catch (e) { alert('复制失败'); }
            }
        });

        document.getElementById('downloadSignKeysBtn')?.addEventListener('click', function () {
            const keys = document.getElementById('signatureOutput').value;
            if (keys) {
                const blob = new Blob([keys], { type: 'text/plain' });
                downloadFile(blob, 'ecdsa_keys.txt');
            }
        });

        let signatureBlob = null;
        let signatureFilename = '';

        document.getElementById('fileSignInput')?.addEventListener('change', function () {
            const file = this.files[0];
            const fileInfo = document.getElementById('fileSignInfo');
            if (file) {
                fileInfo.classList.add('active');
                fileInfo.innerHTML = `<div class="file-info-row"><span class="file-info-label">文件名:</span><span class="file-info-value">${file.name}</span></div><div class="file-info-row"><span class="file-info-label">大小:</span><span class="file-info-value">${formatSize(file.size)}</span></div>`;
                updateFileUploadArea('fileSignUploadArea', file.name);
            } else {
                fileInfo.classList.remove('active');
            }
        });

        setupDragDrop('fileSignUploadArea', 'fileSignInput');
        setupDragDrop('fileVerifyUploadArea', 'fileVerifyInput');
        setupDragDrop('sigFileUploadArea', 'sigFileInput');

        document.getElementById('fileSignBtn')?.addEventListener('click', async function () {
            const file = document.getElementById('fileSignInput').files[0];
            const privateKey = document.getElementById('fileSignPrivateKey').value;
            const publicKey = document.getElementById('fileSignPublicKey')?.value;
            if (!file) { alert('请选择要签名的文件'); return; }
            if (!privateKey) { alert('请输入私钥'); return; }
            if (!publicKey) { alert('请输入公钥'); return; }
            try {
                this.disabled = true;
                this.textContent = '正在签名...';
                const result = await signFile(file, privateKey, publicKey);
                signatureBlob = result.blob;
                signatureFilename = result.filename;
                document.getElementById('signatureOutput').value = `✅ 签名文件已生成！\n\n文件名: ${result.filename}\n原始文件: ${file.name}\n大小: ${formatSize(result.blob.size)}\n\n点击下方按钮下载签名文件。`;
                document.getElementById('signatureDownloadBtns').style.display = 'grid';
            } catch (e) { alert('签名失败: ' + e.message); }
            finally { this.disabled = false; this.textContent = '✍️ 生成签名文件'; }
        });

        document.getElementById('fileVerifyBtn')?.addEventListener('click', async function () {
            const file = document.getElementById('fileVerifyInput').files[0];
            const sigFile = document.getElementById('sigFileInput').files[0];
            const publicKey = document.getElementById('fileVerifyPublicKey').value;
            if (!file) { alert('请选择原始文件'); return; }
            if (!sigFile) { alert('请选择签名文件'); return; }
            try {
                this.disabled = true;
                this.textContent = '正在验证...';
                const result = await verifyFileSignature(file, sigFile, publicKey || null);
                if (result.valid) {
                    document.getElementById('signatureOutput').value = `✅ 签名验证成功！\n\n原始文件: ${result.originalFileName}\n签名时间: ${result.timestamp}\n\n签名有效，文件未被篡改。`;
                } else {
                    document.getElementById('signatureOutput').value = `❌ 签名验证失败！\n\n签名无效，文件可能已被篡改。`;
                }
            } catch (e) {
                document.getElementById('signatureOutput').value = `❌ 验证出错: ${e.message}`;
            }
            finally { this.disabled = false; this.textContent = '✅ 验证文件签名'; }
        });

        document.getElementById('downloadSignatureFileBtn')?.addEventListener('click', function () {
            if (signatureBlob) {
                downloadFile(signatureBlob, signatureFilename);
            }
        });

        document.getElementById('pwdLength')?.addEventListener('input', function () {
            document.getElementById('pwdLengthValue').textContent = this.value;
        });

        document.getElementById('generatePwdBtn')?.addEventListener('click', function () {
            const length = parseInt(document.getElementById('pwdLength').value) || 16;
            const options = {
                upper: document.getElementById('pwdUpper').checked,
                lower: document.getElementById('pwdLower').checked,
                numbers: document.getElementById('pwdNumbers').checked,
                symbols: document.getElementById('pwdSymbols').checked,
                excludeSimilar: document.getElementById('pwdExclude').checked
            };
            const password = generatePassword(length, options);
            const resultsDiv = document.getElementById('generatedPasswords');
            resultsDiv.innerHTML = `<div class="password-item"><span class="password-value">${password}</span><button class="copy-pwd-btn" data-pwd="${password}">📋</button></div>`;

            const strengthDiv = document.getElementById('generatedPwdStrength');
            const result = evaluatePassword(password);
            strengthDiv.classList.add('active');
            strengthDiv.className = `password-strength active ${result.class}`;
            strengthDiv.innerHTML = `密码强度: ${result.label} | 离线破解时间: ${result.crackTime}`;

            resultsDiv.querySelectorAll('.copy-pwd-btn').forEach(btn => {
                btn.addEventListener('click', async function () {
                    try { await navigator.clipboard.writeText(this.dataset.pwd); alert('已复制'); }
                    catch (e) { alert('复制失败'); }
                });
            });
        });

        document.getElementById('generateMultiplePwdBtn')?.addEventListener('click', function () {
            const length = parseInt(document.getElementById('pwdLength').value) || 16;
            const options = {
                upper: document.getElementById('pwdUpper').checked,
                lower: document.getElementById('pwdLower').checked,
                numbers: document.getElementById('pwdNumbers').checked,
                symbols: document.getElementById('pwdSymbols').checked,
                excludeSimilar: document.getElementById('pwdExclude').checked
            };
            let html = '';
            for (let i = 0; i < 10; i++) {
                const password = generatePassword(length, options);
                html += `<div class="password-item"><span class="password-value">${password}</span><button class="copy-pwd-btn" data-pwd="${password}">📋</button></div>`;
            }
            const resultsDiv = document.getElementById('generatedPasswords');
            resultsDiv.innerHTML = html;
            resultsDiv.querySelectorAll('.copy-pwd-btn').forEach(btn => {
                btn.addEventListener('click', async function () {
                    try { await navigator.clipboard.writeText(this.dataset.pwd); alert('已复制'); }
                    catch (e) { alert('复制失败'); }
                });
            });
        });

        /* ============================================
           密码强度检测功能
           ============================================ */

        function evaluatePasswordDetailed(password) {
            const result = evaluatePassword(password);

            let hasUpper = /[A-Z]/.test(password);
            let hasLower = /[a-z]/.test(password);
            let hasNumber = /[0-9]/.test(password);
            let hasSymbol = /[^A-Za-z0-9]/.test(password);
            let hasRepeating = /(.+)\1{2,}/.test(password);
            let hasSequential = /(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(password);

            let charsetSize = 0;
            if (hasUpper) charsetSize += 26;
            if (hasLower) charsetSize += 26;
            if (hasNumber) charsetSize += 10;
            if (hasSymbol) charsetSize += 32;

            const entropy = password.length * Math.log2(charsetSize || 26);

            let suggestions = [];
            let warnings = [];

            if (password.length < 8) warnings.push('密码长度过短，建议至少12位');
            if (!hasUpper) suggestions.push('添加大写字母');
            if (!hasLower) suggestions.push('添加小写字母');
            if (!hasNumber) suggestions.push('添加数字');
            if (!hasSymbol) suggestions.push('添加特殊符号 (!@#$%^&*)');
            if (hasRepeating) warnings.push('避免连续重复的字符');
            if (hasSequential) warnings.push('避免连续的序列字符');

            return {
                ...result,
                length: password.length,
                hasUpper,
                hasLower,
                hasNumber,
                hasSymbol,
                hasRepeating,
                hasSequential,
                entropy: Math.round(entropy),
                charsetSize,
                suggestions,
                warnings
            };
        }

        document.getElementById('checkStrengthBtn')?.addEventListener('click', function () {
            const password = document.getElementById('strengthCheckPassword').value;
            if (!password) {
                alert('请输入要检测的密码');
                return;
            }

            const result = evaluatePasswordDetailed(password);
            const container = document.getElementById('strengthResultContainer');
            const displayDiv = document.getElementById('fullStrengthDisplay');
            const detailsDiv = document.getElementById('strengthDetails');

            container.style.display = 'block';

            displayDiv.className = `password-strength active ${result.class}`;
            displayDiv.innerHTML = `
                <div style="display:flex;justify-content:space-between;margin-bottom:8px;">
                    <span>密码强度: ${result.label}</span>
                    <span>离线破解时间: ${result.crackTime}</span>
                </div>
                <div class="strength-bar">
                    <div class="strength-fill" style="width:${((result.score + 1) * 25)}%;background:${result.score < 2 ? '#ef4444' : result.score < 3 ? '#f59e0b' : result.score < 4 ? '#10b981' : '#059669'}"></div>
                </div>
            `;

            detailsDiv.innerHTML = `
                <h4 style="margin-bottom:15px;font-weight:600;">📊 详细分析</h4>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">密码长度</span>
                        <span class="detail-value ${result.length >= 16 ? 'good' : result.length >= 12 ? 'fair' : 'weak'}">${result.length} 位</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">密码熵值</span>
                        <span class="detail-value ${result.entropy >= 80 ? 'good' : result.entropy >= 60 ? 'fair' : 'weak'}">${result.entropy} bits</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">字符集大小</span>
                        <span class="detail-value">${result.charsetSize}</span>
                    </div>
                </div>
                <h4 style="margin:20px 0 10px;font-weight:600;">✅ 字符类型检查</h4>
                <div class="check-list">
                    <div class="check-item ${result.hasUpper ? 'passed' : 'failed'}">
                        ${result.hasUpper ? '✓' : '✗'} 大写字母 (A-Z)
                    </div>
                    <div class="check-item ${result.hasLower ? 'passed' : 'failed'}">
                        ${result.hasLower ? '✓' : '✗'} 小写字母 (a-z)
                    </div>
                    <div class="check-item ${result.hasNumber ? 'passed' : 'failed'}">
                        ${result.hasNumber ? '✓' : '✗'} 数字 (0-9)
                    </div>
                    <div class="check-item ${result.hasSymbol ? 'passed' : 'failed'}">
                        ${result.hasSymbol ? '✓' : '✗'} 特殊符号 (!@#$%^&*)
                    </div>
                </div>
                ${result.warnings.length > 0 ? `
                    <h4 style="margin:20px 0 10px;font-weight:600;">⚠️ 安全警告</h4>
                    <div class="warning-list">
                        ${result.warnings.map(w => `<div class="warning-item">${w}</div>`).join('')}
                    </div>
                ` : ''}
                ${result.suggestions.length > 0 ? `
                    <h4 style="margin:20px 0 10px;font-weight:600;">💡 优化建议</h4>
                    <div class="suggestion-list">
                        ${result.suggestions.map(s => `<div class="suggestion-item">${s}</div>`).join('')}
                    </div>
                ` : ''}
            `;
        });

        /* ============================================
           随机性检测功能
           ============================================ */

        const RandomnessTests = {
            monobit(bits) {
                const n = bits.length;
                let ones = 0;
                for (let i = 0; i < n; i++) {
                    if (bits[i] === 1) ones++;
                }
                const s = Math.abs(ones - (n - ones));
                const pValue = this.erfc(s / Math.sqrt(2 * n));
                return { passed: pValue >= 0.01, pValue, statistic: s };
            },

            blockFrequency(bits, M = 128) {
                const n = bits.length;
                const N = Math.floor(n / M);
                if (N === 0) return { passed: false, pValue: 0, error: '数据太短' };

                let chiSquare = 0;
                for (let i = 0; i < N; i++) {
                    let ones = 0;
                    for (let j = 0; j < M; j++) {
                        if (bits[i * M + j] === 1) ones++;
                    }
                    const pi = ones / M;
                    chiSquare += Math.pow(pi - 0.5, 2);
                }
                chiSquare *= 4 * M;
                const pValue = this.igamc(N / 2, chiSquare / 2);
                return { passed: pValue >= 0.01, pValue, statistic: chiSquare };
            },

            poker(bits, m = 4) {
                const n = bits.length;
                const k = Math.floor(n / m);
                if (k === 0) return { passed: false, pValue: 0, error: '数据太短' };

                const counts = new Array(Math.pow(2, m)).fill(0);
                for (let i = 0; i < k; i++) {
                    let val = 0;
                    for (let j = 0; j < m; j++) {
                        val = (val << 1) | bits[i * m + j];
                    }
                    counts[val]++;
                }

                let chiSquare = 0;
                for (let i = 0; i < counts.length; i++) {
                    chiSquare += counts[i] * counts[i];
                }
                chiSquare = (Math.pow(2, m) / k) * chiSquare - k;
                const pValue = this.igamc((Math.pow(2, m) - 1) / 2, chiSquare / 2);
                return { passed: pValue >= 0.01, pValue, statistic: chiSquare };
            },

            runs(bits) {
                const n = bits.length;
                let ones = 0;
                for (let i = 0; i < n; i++) {
                    if (bits[i] === 1) ones++;
                }
                const pi = ones / n;

                if (Math.abs(pi - 0.5) >= 2 / Math.sqrt(n)) {
                    return { passed: false, pValue: 0, error: '频数不通过' };
                }

                let runs = 1;
                for (let i = 1; i < n; i++) {
                    if (bits[i] !== bits[i - 1]) runs++;
                }

                const V = runs;
                const expected = 2 * n * pi * (1 - pi) + 1;
                const std = 2 * Math.sqrt(2 * n) * pi * (1 - pi);
                const pValue = this.erfc(Math.abs(V - expected) / std);
                return { passed: pValue >= 0.01, pValue, statistic: V };
            },

            longestRunOfOnes(bits) {
                const n = bits.length;
                let M, K, N;

                if (n < 128) {
                    return { passed: false, pValue: 0, error: '数据太短，至少需要128位' };
                } else if (n < 6272) {
                    M = 8;
                    K = 3;
                    N = Math.floor(n / M);
                } else if (n < 750000) {
                    M = 128;
                    K = 5;
                    N = Math.floor(n / M);
                } else {
                    M = 10000;
                    K = 6;
                    N = Math.floor(n / M);
                }

                const v = new Array(K + 1).fill(0);
                for (let i = 0; i < N; i++) {
                    let maxRun = 0;
                    let currentRun = 0;
                    for (let j = 0; j < M; j++) {
                        if (bits[i * M + j] === 1) {
                            currentRun++;
                            if (currentRun > maxRun) maxRun = currentRun;
                        } else {
                            currentRun = 0;
                        }
                    }

                    let idx;
                    if (n < 6272) {
                        idx = maxRun <= 1 ? 0 : maxRun <= 4 ? maxRun - 1 : K;
                    } else if (n < 750000) {
                        idx = maxRun <= 4 ? 0 : maxRun <= 9 ? maxRun - 4 : K;
                    } else {
                        idx = maxRun <= 10 ? 0 : maxRun <= 16 ? maxRun - 10 : K;
                    }
                    v[Math.min(idx, K)]++;
                }

                const pi = n < 6272
                    ? [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]
                    : n < 750000
                        ? [0.1170, 0.2460, 0.2523, 0.1755, 0.1027, 0.1124]
                        : [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727];

                let chiSquare = 0;
                for (let i = 0; i <= K; i++) {
                    chiSquare += Math.pow(v[i] - N * pi[i], 2) / (N * pi[i]);
                }

                const pValue = this.igamc(K / 2, chiSquare / 2);
                return { passed: pValue >= 0.01, pValue, statistic: chiSquare };
            },

            rank(bits) {
                const n = bits.length;
                const N = Math.floor(n / (32 * 32));
                if (N === 0) return { passed: false, pValue: 0, error: '数据太短，至少需要1024位' };

                let F_32 = 0, F_31 = 0;

                for (let i = 0; i < N; i++) {
                    const matrix = [];
                    for (let row = 0; row < 32; row++) {
                        const bitsRow = [];
                        for (let col = 0; col < 32; col++) {
                            bitsRow.push(bits[i * 1024 + row * 32 + col]);
                        }
                        matrix.push(bitsRow);
                    }

                    const rank = this.binaryMatrixRank(matrix);
                    if (rank === 32) F_32++;
                    else if (rank === 31) F_31++;
                }

                const p_32 = 0.2888;
                const p_31 = 0.5776;
                const p_30 = 0.1336;

                const chiSquare =
                    Math.pow(F_32 - N * p_32, 2) / (N * p_32) +
                    Math.pow(F_31 - N * p_31, 2) / (N * p_31) +
                    Math.pow((N - F_32 - F_31) - N * p_30, 2) / (N * p_30);

                const pValue = this.igamc(1, chiSquare / 2);
                return { passed: pValue >= 0.01, pValue, statistic: chiSquare };
            },

            discreteFourierTransform(bits) {
                const n = bits.length;
                if (n < 32) return { passed: false, pValue: 0, error: '数据太短，至少需要32位' };

                const X = [];
                for (let i = 0; i < n; i++) {
                    X.push(bits[i] === 1 ? 1 : -1);
                }

                const nextPow2 = Math.pow(2, Math.ceil(Math.log2(n)));
                while (X.length < nextPow2) X.push(0);

                const S = this.fastFourierTransform(X);
                const modulus = [];
                for (let i = 0; i < Math.floor(n / 2); i++) {
                    if (S[i] && typeof S[i].re === 'number') {
                        modulus.push(Math.sqrt(S[i].re * S[i].re + S[i].im * S[i].im));
                    }
                }

                if (modulus.length === 0) {
                    return { passed: false, pValue: 0, error: 'FFT计算失败' };
                }

                const T = Math.sqrt(Math.log(1 / 0.05) * n);
                const N_0 = 0.95 * n / 2;
                let N_1 = 0;
                for (let i = 0; i < modulus.length; i++) {
                    if (modulus[i] < T) N_1++;
                }

                const d = (N_1 - N_0) / Math.sqrt(n * 0.95 * 0.05 / 4);
                const pValue = this.erfc(Math.abs(d) / Math.sqrt(2));
                return { passed: pValue >= 0.01, pValue, statistic: d };
            },

            approximateEntropy(bits, m = 10) {
                const n = bits.length;
                if (n < m + 10) return { passed: false, pValue: 0, error: '数据太短' };

                const phi_m = this.computePhi(bits, m);
                const phi_m1 = this.computePhi(bits, m + 1);
                const apen = phi_m - phi_m1;

                const chiSquare = 2 * n * (Math.log(2) - apen);
                const pValue = this.igamc(Math.pow(2, m - 1), chiSquare / 2);
                return { passed: pValue >= 0.01, pValue, statistic: apen };
            },

            cumulativeSums(bits, forward = true) {
                const n = bits.length;
                let S = 0;
                let max_S = 0;

                if (forward) {
                    for (let i = 0; i < n; i++) {
                        S += bits[i] === 1 ? 1 : -1;
                        if (Math.abs(S) > max_S) max_S = Math.abs(S);
                    }
                } else {
                    for (let i = n - 1; i >= 0; i--) {
                        S += bits[i] === 1 ? 1 : -1;
                        if (Math.abs(S) > max_S) max_S = Math.abs(S);
                    }
                }

                let sum1 = 0;
                const start = Math.floor((-n / max_S + 1) / 4);
                const end = Math.floor((n / max_S - 1) / 4);

                for (let k = start; k <= end; k++) {
                    const term = this.normalCDF((4 * k + 1) * max_S / Math.sqrt(n));
                    const term2 = this.normalCDF((4 * k - 1) * max_S / Math.sqrt(n));
                    sum1 += term - term2;
                }

                let sum2 = 0;
                const start2 = Math.floor((-n / max_S - 3) / 4);
                const end2 = Math.floor((n / max_S - 1) / 4);

                for (let k = start2; k <= end2; k++) {
                    const term = this.normalCDF((4 * k + 3) * max_S / Math.sqrt(n));
                    const term2 = this.normalCDF((4 * k + 1) * max_S / Math.sqrt(n));
                    sum2 += term - term2;
                }

                const pValue = 1 - sum1 + sum2;
                return { passed: pValue >= 0.01, pValue, statistic: max_S };
            },

            computePhi(bits, m) {
                const n = bits.length;
                const padded = bits.concat(bits.slice(0, m - 1));
                const counts = {};

                for (let i = 0; i < n; i++) {
                    let pattern = '';
                    for (let j = 0; j < m; j++) {
                        pattern += padded[i + j];
                    }
                    counts[pattern] = (counts[pattern] || 0) + 1;
                }

                let sum = 0;
                for (const key in counts) {
                    const c = counts[key] / n;
                    sum += c * Math.log(c);
                }

                return sum;
            },

            binaryMatrixRank(matrix) {
                const n = matrix.length;
                const m = matrix[0].length;
                let rank = 0;

                for (let col = 0; col < m && rank < n; col++) {
                    let pivot = -1;
                    for (let row = rank; row < n; row++) {
                        if (matrix[row][col] === 1) {
                            pivot = row;
                            break;
                        }
                    }

                    if (pivot === -1) continue;

                    [matrix[rank], matrix[pivot]] = [matrix[pivot], matrix[rank]];

                    for (let row = 0; row < n; row++) {
                        if (row !== rank && matrix[row][col] === 1) {
                            for (let c = col; c < m; c++) {
                                matrix[row][c] ^= matrix[rank][c];
                            }
                        }
                    }

                    rank++;
                }

                return rank;
            },

            fastFourierTransform(x) {
                const n = x.length;
                if (n === 0) return [];
                if (n === 1) return [{ re: typeof x[0] === 'object' ? x[0].re : (x[0] || 0), im: typeof x[0] === 'object' ? x[0].im : 0 }];

                const even = [];
                const odd = [];
                for (let i = 0; i < n; i += 2) {
                    even.push(x[i]);
                    if (i + 1 < n) odd.push(x[i + 1]);
                }

                const q = this.fastFourierTransform(even);
                const r = this.fastFourierTransform(odd);

                const X = new Array(n);
                for (let k = 0; k < n / 2; k++) {
                    const rk = r[k % r.length] || { re: 0, im: 0 };
                    const qk = q[k % q.length] || { re: 0, im: 0 };
                    const t = -2 * Math.PI * k / n;
                    const cos = Math.cos(t);
                    const sin = Math.sin(t);
                    const re = rk.re * cos - rk.im * sin;
                    const im = rk.re * sin + rk.im * cos;
                    X[k] = { re: qk.re + re, im: qk.im + im };
                    X[k + n / 2] = { re: qk.re - re, im: qk.im - im };
                }

                return X;
            },

            erfc(x) {
                const a1 = 0.254829592;
                const a2 = -0.284496736;
                const a3 = 1.421413741;
                const a4 = -1.453152027;
                const a5 = 1.061405429;
                const p = 0.3275911;

                const sign = x < 0 ? -1 : 1;
                x = Math.abs(x);

                const t = 1.0 / (1.0 + p * x);
                const y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * Math.exp(-x * x);

                return sign * y + (1 - sign);
            },

            igamc(a, x) {
                if (x <= 0) return 1;
                if (a <= 0) return 0;

                const nbits = 24;
                const epsilon = Math.pow(2, -nbits);

                if (x < 0 || a <= 0) return 0;
                if (x === 0) return 1;

                let y = a * Math.log(x) - x - this.lgamma(a);
                let p = a;
                let q = a;
                let z = 1 / q;
                let err = z;
                while (err > epsilon * z) {
                    p++;
                    q = q * x / p;
                    z = z + q;
                    err = Math.abs(q / z);
                }

                if (x < a + 1) {
                    return 1 - z * Math.exp(y);
                }
                return z * Math.exp(y);
            },

            lgamma(x) {
                const c = [
                    76.18009172947146,
                    -86.50532032941677,
                    24.01409824083091,
                    -1.231739572450155,
                    0.1208650973866179e-2,
                    -0.5395239384953e-5
                ];
                let ser = 1.000000000190015;
                for (let i = 0; i < 6; i++) {
                    ser += c[i] / (x + i);
                }
                const tmp = x + 5.5 - (x + 0.5) * Math.log(x + 5.5);
                return -tmp + Math.log(2.5066282746310005 * ser / x);
            },

            normalCDF(x) {
                const t = 1 / (1 + 0.2316419 * Math.abs(x));
                const d = 0.3989423 * Math.exp(-x * x / 2);
                const prob = d * t * (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))));
                return x > 0 ? 1 - prob : prob;
            }
        };

        function hexToBits(hex) {
            const bits = [];
            for (let i = 0; i < hex.length; i += 2) {
                const byte = parseInt(hex.substr(i, 2), 16);
                for (let j = 7; j >= 0; j--) {
                    bits.push((byte >> j) & 1);
                }
            }
            return bits;
        }

        function binaryStringToBits(str) {
            const bits = [];
            for (let i = 0; i < str.length; i++) {
                if (str[i] === '0' || str[i] === '1') {
                    bits.push(parseInt(str[i]));
                }
            }
            return bits;
        }

        function arrayBufferToBits(buffer) {
            const uint8 = new Uint8Array(buffer);
            const bits = [];
            for (let i = 0; i < uint8.length; i++) {
                for (let j = 7; j >= 0; j--) {
                    bits.push((uint8[i] >> j) & 1);
                }
            }
            return bits;
        }

        document.querySelectorAll('[data-randomness-mode]').forEach(btn => {
            btn.addEventListener('click', function () {
                document.querySelectorAll('[data-randomness-mode]').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                const mode = this.dataset.randomnessMode;
                document.getElementById('randomness-text-panel').style.display = mode === 'text' ? 'block' : 'none';
                document.getElementById('randomness-file-panel').style.display = mode === 'file' ? 'block' : 'none';
            });
        });

        document.querySelectorAll('[data-randomness-input]').forEach(btn => {
            btn.addEventListener('click', function () {
                document.querySelectorAll('[data-randomness-input]').forEach(b => b.classList.remove('selected'));
                this.classList.add('selected');
            });
        });

        document.getElementById('randomnessFileInput')?.addEventListener('change', function () {
            const file = this.files[0];
            const fileInfo = document.getElementById('randomnessFileInfo');
            if (file) {
                fileInfo.classList.add('active');
                fileInfo.innerHTML = `<div class="file-info-row"><span class="file-info-label">文件名:</span><span class="file-info-value">${file.name}</span></div><div class="file-info-row"><span class="file-info-label">大小:</span><span class="file-info-value">${formatSize(file.size)}</span></div>`;
                updateFileUploadArea('randomnessFileArea', file.name);
            } else {
                fileInfo.classList.remove('active');
            }
        });

        setupDragDrop('randomnessFileArea', 'randomnessFileInput');

        document.getElementById('runRandomnessTestsBtn')?.addEventListener('click', async function () {
            let bits = [];
            const mode = document.querySelector('[data-randomness-mode].active')?.dataset.randomnessMode;

            if (mode === 'text') {
                const inputType = document.querySelector('[data-randomness-input].selected')?.dataset.randomnessInput;
                const input = document.getElementById('randomnessInput').value.trim();

                if (!input) {
                    alert('请输入数据');
                    return;
                }

                if (inputType === 'binary') {
                    bits = binaryStringToBits(input);
                } else {
                    bits = hexToBits(input.replace(/\s/g, ''));
                }
            } else {
                const file = document.getElementById('randomnessFileInput').files[0];
                if (!file) {
                    alert('请选择文件');
                    return;
                }

                try {
                    const buffer = await file.arrayBuffer();
                    bits = arrayBufferToBits(buffer);
                } catch (e) {
                    alert('读取文件失败: ' + e.message);
                    return;
                }
            }

            if (bits.length < 128) {
                alert('数据太短，至少需要128位');
                return;
            }

            this.disabled = true;
            this.textContent = '正在执行检测...';

            const tests = [
                { id: 'testMonobit', name: '单比特频数检测', fn: 'monobit' },
                { id: 'testBlockFrequency', name: '块内频数检测', fn: 'blockFrequency' },
                { id: 'testPoker', name: '扑克检测 (m=4)', fn: 'poker' },
                { id: 'testRuns', name: '游程总数检测', fn: 'runs' },
                { id: 'testLongestRun', name: '块内最大游程检测', fn: 'longestRunOfOnes' },
                { id: 'testRank', name: '矩阵秩检测', fn: 'rank' },
                { id: 'testDFT', name: '离散傅里叶检测', fn: 'discreteFourierTransform' },
                { id: 'testApproximateEntropy', name: '近似熵检测', fn: 'approximateEntropy' },
                { id: 'testCumulativeSums', name: '累加和检测 (前向)', fn: 'cumulativeSums' }
            ];

            const results = [];
            let passedCount = 0;
            let totalCount = 0;

            for (const test of tests) {
                const checkbox = document.getElementById(test.id);
                if (!checkbox || !checkbox.checked) continue;

                totalCount++;
                try {
                    const result = RandomnessTests[test.fn](bits);
                    results.push({
                        name: test.name,
                        ...result
                    });
                    if (result.passed) passedCount++;
                } catch (e) {
                    results.push({
                        name: test.name,
                        passed: false,
                        error: e.message
                    });
                }
            }

            const resultsDiv = document.getElementById('randomnessResults');
            resultsDiv.style.display = 'block';

            let html = `
                <h3 style="margin-bottom:20px;">📋 检测结果摘要</h3>
                <div class="result-summary">
                    <div class="summary-item">
                        <span class="summary-label">数据长度</span>
                        <span class="summary-value">${bits.length} 位 (${Math.ceil(bits.length / 8)} 字节)</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">通过检测</span>
                        <span class="summary-value good">${passedCount} / ${totalCount}</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">整体评估</span>
                        <span class="summary-value ${passedCount === totalCount ? 'good' : passedCount >= totalCount * 0.7 ? 'fair' : 'weak'}">
                            ${passedCount === totalCount ? '✅ 通过' : passedCount >= totalCount * 0.7 ? '⚠️ 基本通过' : '❌ 失败'}
                        </span>
                    </div>
                </div>
                <h3 style="margin:25px 0 15px;">🔍 详细检测结果</h3>
                <div class="test-results">
            `;

            for (const result of results) {
                html += `
                    <div class="test-result-item ${result.passed ? 'passed' : 'failed'}">
                        <div class="test-name">
                            ${result.passed ? '✅' : '❌'} ${result.name}
                        </div>
                        ${result.error ? `<div class="test-error">错误: ${result.error}</div>` : `
                            <div class="test-details">
                                <span>P值: ${result.pValue !== undefined ? result.pValue.toFixed(6) : 'N/A'}</span>
                                <span>统计量: ${result.statistic !== undefined ? result.statistic.toFixed(4) : 'N/A'}</span>
                            </div>
                        `}
                    </div>
                `;
            }

            html += '</div>';
            resultsDiv.innerHTML = html;

            this.disabled = false;
            this.textContent = '🎲 执行随机性检测';
        });

        checkCryptoSupport();
    });

    window.addEventListener('load', function () {
        waitForArgon2(15000).then(ready => {
            if (!ready) {
                const algoOptions = document.querySelectorAll('.algo-option[data-kdf]');
                algoOptions.forEach(opt => {
                    if (opt.dataset.kdf === 'argon2') {
                        opt.style.opacity = '0.5';
                        opt.style.pointerEvents = 'none';
                        opt.querySelector('h4').innerHTML = '⚠️ Argon2id (加载失败)';
                    }
                });
                if (currentKdf === KDF_ARGON2) {
                    currentKdf = KDF_SCRYPT;
                    algoOptions.forEach(opt => {
                        if (opt.dataset.kdf === 'scrypt') opt.classList.add('selected');
                        if (opt.dataset.kdf === 'argon2') opt.classList.remove('selected');
                    });
                }
            }
        });
    });
})();
