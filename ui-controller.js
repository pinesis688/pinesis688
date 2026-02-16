(function () {
    'use strict';

    window.SecureFx = window.SecureFx || {};
    window.SecureFx.UIController = window.SecureFx.UIController || {};

    let operationInProgress = false;
    let currentKdf = window.SecureFx.Constants.KDF_ARGON2;
    let currentHashAlgo = 'sha256';
    let currentEncoding = 'base32';
    let keyTimer = null;
    let keyDisplayActive = false;
    let currentAsymType = 'rsa';

    function showSecurityWarning() {
        return new Promise((resolve) => {
            const acknowledged = localStorage.getItem('securefx_risk_acknowledged');
            if (acknowledged) {
                resolve(true);
            } else {
                resolve(true);
            }
        });
    }

    function checkEnvironment() {
        const isSecure = location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1' || location.protocol === 'file:';
        const warning = document.getElementById('envWarning');
        if (warning) {
            if (!isSecure) {
                warning.style.display = 'block';
            }
        }
    }

    function updateProgress(percent, status) {
        const progressFill = document.getElementById('fileProgressFill');
        const progressPercent = document.getElementById('fileProgressPercent');
        const progressStatus = document.getElementById('fileProgressStatus');
        if (progressFill) progressFill.style.width = percent + '%';
        if (progressPercent) progressPercent.textContent = Math.round(percent) + '%';
        if (progressStatus) progressStatus.textContent = status;
    }

    function resetProgress() {
        updateProgress(0, '准备中...');
    }

    function initTheme() {
        const savedTheme = localStorage.getItem('securefx-theme');
        if (savedTheme === 'dark') {
            document.documentElement.setAttribute('data-theme', 'dark');
            const themeToggle = document.getElementById('themeToggle');
            if (themeToggle) themeToggle.textContent = '☀️';
        }
    }

    function bindThemeToggle() {
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
    }

    function bindNavigation() {
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
    }

    function bindKdfSelector() {
        document.querySelectorAll('.algo-option[data-kdf]').forEach(option => {
            option.addEventListener('click', function () {
                document.querySelectorAll('.algo-option[data-kdf]').forEach(o => o.classList.remove('selected'));
                this.classList.add('selected');
                currentKdf = this.dataset.kdf === 'argon2' ? window.SecureFx.Constants.KDF_ARGON2 : window.SecureFx.Constants.KDF_SCRYPT;
            });
        });
    }

    function bindHashSelector() {
        document.querySelectorAll('.algo-option[data-hash]').forEach(option => {
            option.addEventListener('click', function () {
                document.querySelectorAll('.algo-option[data-hash]').forEach(o => o.classList.remove('selected'));
                this.classList.add('selected');
                currentHashAlgo = this.dataset.hash;
            });
        });
    }

    function bindEncodingSelector() {
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
    }

    function bindModeToggles() {
        document.querySelectorAll('.mode-toggle').forEach(toggle => {
            toggle.querySelectorAll('.mode-toggle-btn').forEach(btn => {
                btn.addEventListener('click', function () {
                    toggle.querySelectorAll('.mode-toggle-btn').forEach(b => b.classList.remove('active'));
                    this.classList.add('active');
                    const mode = this.dataset.mode;
                    const encryptType = this.dataset.encryptType;
                    const textMode = this.dataset.textMode;
                    const rsaMode = this.dataset.rsaMode;
                    const eccMode = this.dataset.eccMode;
                    const hashType = this.dataset.hashType;
                    const randomnessMode = this.dataset.randomnessMode;
                    const selftestType = this.dataset.selftestType;
                    const asymType = this.dataset.asymType;

                    if (encryptType) {
                        document.getElementById('file-encrypt-panel').style.display = encryptType === 'file' ? 'block' : 'none';
                        document.getElementById('text-encrypt-panel').style.display = encryptType === 'text' ? 'block' : 'none';
                    } else if (textMode) {
                        if (toggle.closest('#text-encrypt-panel')) {
                            document.getElementById('textEncryptBtn').style.display = textMode === 'encrypt' ? 'block' : 'none';
                            document.getElementById('textDecryptBtn').style.display = textMode === 'decrypt' ? 'block' : 'none';
                        }
                    } else if (toggle.closest('#file-encrypt-section') && mode) {
                        document.getElementById('fileEncryptBtn').style.display = mode === 'encrypt' ? 'block' : 'none';
                        document.getElementById('fileDecryptBtn').style.display = mode === 'decrypt' ? 'block' : 'none';
                    } else if (toggle.closest('#rsa-section')) {
                        if (asymType) {
                            currentAsymType = asymType;
                            document.getElementById('rsa-panel').style.display = asymType === 'rsa' ? 'block' : 'none';
                            document.getElementById('ecc-panel').style.display = asymType === 'ecc' ? 'block' : 'none';
                        } else if (rsaMode) {
                            document.getElementById('rsa-generate-panel').style.display = rsaMode === 'generate' ? 'block' : 'none';
                            document.getElementById('rsa-encrypt-panel').style.display = rsaMode === 'encrypt' ? 'block' : 'none';
                            document.getElementById('rsa-decrypt-panel').style.display = rsaMode === 'decrypt' ? 'block' : 'none';
                        } else if (eccMode) {
                            document.getElementById('ecc-generate-panel').style.display = eccMode === 'generate' ? 'block' : 'none';
                            document.getElementById('ecc-encrypt-panel').style.display = eccMode === 'encrypt' ? 'block' : 'none';
                            document.getElementById('ecc-decrypt-panel').style.display = eccMode === 'decrypt' ? 'block' : 'none';
                        }
                    } else if (toggle.closest('#signature-section') && mode) {
                        document.getElementById('signature-generate-panel').style.display = mode === 'generate' ? 'block' : 'none';
                        document.getElementById('signature-sign-panel').style.display = mode === 'sign' ? 'block' : 'none';
                        document.getElementById('signature-verify-panel').style.display = mode === 'verify' ? 'block' : 'none';
                        document.getElementById('signature-file-sign-panel').style.display = mode === 'file-sign' ? 'block' : 'none';
                    } else if (toggle.closest('#hash-section') && hashType) {
                        document.getElementById('text-hash-panel').style.display = hashType === 'text' ? 'block' : 'none';
                        document.getElementById('file-hash-panel').style.display = hashType === 'file' ? 'block' : 'none';
                    } else if (toggle.closest('#randomness-section') && randomnessMode) {
                        document.getElementById('randomness-text-panel').style.display = randomnessMode === 'text' ? 'block' : 'none';
                        document.getElementById('randomness-file-panel').style.display = randomnessMode === 'file' ? 'block' : 'none';
                    } else if (toggle.closest('#selftest-section') && selftestType) {
                        document.getElementById('selftest-panel').style.display = selftestType === 'test' ? 'block' : 'none';
                        document.getElementById('guide-panel').style.display = selftestType === 'guide' ? 'block' : 'none';
                    }
                });
            });
        });
    }

    function bindRangeInputs() {
        document.getElementById('caesarShift')?.addEventListener('input', function () {
            document.getElementById('caesarShiftValue').textContent = this.value;
        });

        document.getElementById('railfenceRails')?.addEventListener('input', function () {
            document.getElementById('railfenceRailsValue').textContent = this.value;
        });
    }

    function bindSignOption() {
        document.getElementById('enableSignEncrypt')?.addEventListener('change', function () {
            document.getElementById('signEncryptPrivateKey').style.display = this.checked ? 'block' : 'none';
        });
    }

    function bindFileUploads() {
        document.getElementById('fileUploadArea')?.addEventListener('click', function () {
            document.getElementById('fileInput').click();
        });

        document.getElementById('fileInput')?.addEventListener('change', function (e) {
            const file = e.target.files[0];
            if (file) {
                const fileInfo = document.getElementById('fileInfo');
                fileInfo.innerHTML = `
                    <div class="file-name">${file.name}</div>
                    <div class="file-size">${window.SecureFx.CryptoCore.formatSize(file.size)}</div>
                `;
            }
        });

        document.getElementById('fileHashUploadArea')?.addEventListener('click', function () {
            document.getElementById('fileHashInput').click();
        });

        document.getElementById('fileHashInput')?.addEventListener('change', function (e) {
            const file = e.target.files[0];
            if (file) {
                const fileInfo = document.getElementById('fileHashInfo');
                fileInfo.innerHTML = `
                    <div class="file-name">${file.name}</div>
                    <div class="file-size">${window.SecureFx.CryptoCore.formatSize(file.size)}</div>
                `;
            }
        });

        document.getElementById('randomnessFileArea')?.addEventListener('click', function () {
            document.getElementById('randomnessFileInput').click();
        });

        document.getElementById('randomnessFileInput')?.addEventListener('change', function (e) {
            const file = e.target.files[0];
            if (file) {
                const fileInfo = document.getElementById('randomnessFileInfo');
                fileInfo.innerHTML = `
                    <div class="file-name">${file.name}</div>
                    <div class="file-size">${window.SecureFx.CryptoCore.formatSize(file.size)}</div>
                `;
            }
        });
    }

    function bindPasswordStrength() {
        document.getElementById('filePassword')?.addEventListener('input', function () {
            const password = this.value;
            const strengthDiv = document.getElementById('filePasswordStrength');
            if (strengthDiv) {
                const result = window.SecureFx.PasswordTools.evaluatePassword(password);
                let strengthClass = '';
                let strengthText = '';
                if (result.score === 0) {
                    strengthClass = 'very-weak';
                    strengthText = '非常弱';
                } else if (result.score === 1) {
                    strengthClass = 'weak';
                    strengthText = '弱';
                } else if (result.score === 2) {
                    strengthClass = 'fair';
                    strengthText = '一般';
                } else if (result.score === 3) {
                    strengthClass = 'strong';
                    strengthText = '强';
                } else {
                    strengthClass = 'very-strong';
                    strengthText = '非常强';
                }
                strengthDiv.className = 'password-strength ' + strengthClass;
                strengthDiv.innerHTML = `<span>密码强度: ${strengthText}</span><div class="strength-bar"></div>`;
            }
        });
    }

    function bindFileEncryptBtn() {
        document.getElementById('fileEncryptBtn')?.addEventListener('click', async function () {
            const fileInput = document.getElementById('fileInput');
            const file = fileInput.files[0];
            const password = document.getElementById('filePassword').value;
            const anonymousMode = document.getElementById('anonymousMode').checked;
            const enableSign = document.getElementById('enableSignEncrypt').checked;
            const signPrivateKey = document.getElementById('signEncryptPrivateKey').value;

            if (!file) {
                alert('请选择要加密的文件');
                return;
            }

            if (!password || password.length < 8) {
                alert('密码长度至少8位');
                return;
            }

            if (enableSign && !signPrivateKey) {
                alert('请提供签名私钥');
                return;
            }

            operationInProgress = true;
            document.getElementById('fileProgress').style.display = 'block';
            document.getElementById('cancelOperationBtn').style.display = 'block';
            this.disabled = true;

            try {
                let signature = null;
                if (enableSign) {
                    signature = signPrivateKey;
                }

                const result = await window.SecureFx.FileOperations.encryptFileV2(file, password, currentKdf, anonymousMode, signature, updateProgress);
                const resultDiv = document.getElementById('fileResult');
                resultDiv.className = 'result-box success';
                resultDiv.innerHTML = `
                    <h4>✅ 加密成功！</h4>
                    <p>文件已加密，点击下方按钮下载。</p>
                `;
                const downloadBtn = document.getElementById('fileDownloadBtn');
                downloadBtn.onclick = function () {
                    const blob = new Blob([result], { type: 'application/octet-stream' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = anonymousMode ? 'encrypted_' + Date.now() + '.sfx' : file.name + '.sfx';
                    a.click();
                    URL.revokeObjectURL(url);
                };
                document.getElementById('fileDownloadBtns').style.display = 'flex';
            } catch (e) {
                const resultDiv = document.getElementById('fileResult');
                resultDiv.className = 'result-box error';
                resultDiv.innerHTML = `<h4>❌ 加密失败</h4><p>${e.message}</p>`;
            } finally {
                operationInProgress = false;
                document.getElementById('cancelOperationBtn').style.display = 'none';
                this.disabled = false;
            }
        });
    }

    function bindFileDecryptBtn() {
        document.getElementById('fileDecryptBtn')?.addEventListener('click', async function () {
            const fileInput = document.getElementById('fileInput');
            const file = fileInput.files[0];
            const password = document.getElementById('filePassword').value;

            if (!file) {
                alert('请选择要解密的文件');
                return;
            }

            if (!password) {
                alert('请输入密码');
                return;
            }

            operationInProgress = true;
            document.getElementById('fileProgress').style.display = 'block';
            document.getElementById('cancelOperationBtn').style.display = 'block';
            this.disabled = true;

            try {
                const result = await window.SecureFx.FileOperations.decryptFileV2(file, password, updateProgress);
                const resultDiv = document.getElementById('fileResult');
                resultDiv.className = 'result-box success';
                resultDiv.innerHTML = `
                    <h4>✅ 解密成功！</h4>
                    <p>文件已解密，点击下方按钮下载。</p>
                `;
                const downloadBtn = document.getElementById('fileDownloadBtn');
                downloadBtn.onclick = function () {
                    const blob = new Blob([result.data], { type: 'application/octet-stream' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = result.filename;
                    a.click();
                    URL.revokeObjectURL(url);
                };
                document.getElementById('fileDownloadBtns').style.display = 'flex';
            } catch (e) {
                const resultDiv = document.getElementById('fileResult');
                resultDiv.className = 'result-box error';
                resultDiv.innerHTML = `<h4>❌ 解密失败</h4><p>${e.message}</p>`;
            } finally {
                operationInProgress = false;
                document.getElementById('cancelOperationBtn').style.display = 'none';
                this.disabled = false;
            }
        });
    }

    function bindCancelBtn() {
        document.getElementById('cancelOperationBtn')?.addEventListener('click', function () {
            window.SecureFx.WorkerManager.cancelCurrentOperation();
            this.style.display = 'none';
        });
    }

    function bindTextEncryptBtn() {
        document.getElementById('textEncryptBtn')?.addEventListener('click', async function () {
            const text = document.getElementById('textInput').value;
            const password = document.getElementById('textPassword').value;

            if (!text) {
                alert('请输入要加密的文本');
                return;
            }

            if (!password || password.length < 8) {
                alert('密码长度至少8位');
                return;
            }

            try {
                const textBytes = new TextEncoder().encode(text);
                const keyBytes = await window.SecureFx.CryptoCore.deriveKeyBytes(password, window.SecureFx.Constants.MAGIC_V2, currentKdf);
                const nonce = crypto.getRandomValues(new Uint8Array(window.SecureFx.Constants.NONCE_LENGTH));
                const encrypted = await window.SecureFx.CryptoCore.encryptGCM(keyBytes, textBytes, nonce);
                const combined = window.SecureFx.CryptoCore.concatArrays(nonce, encrypted);
                document.getElementById('textOutput').value = window.SecureFx.CryptoCore.arrayToBase64(combined);
            } catch (e) {
                alert('加密失败: ' + e.message);
            }
        });
    }

    function bindTextDecryptBtn() {
        document.getElementById('textDecryptBtn')?.addEventListener('click', async function () {
            const text = document.getElementById('textInput').value;
            const password = document.getElementById('textPassword').value;

            if (!text) {
                alert('请输入要解密的文本');
                return;
            }

            if (!password) {
                alert('请输入密码');
                return;
            }

            try {
                const combined = window.SecureFx.CryptoCore.base64ToArray(text);
                const nonce = combined.slice(0, window.SecureFx.Constants.NONCE_LENGTH);
                const encrypted = combined.slice(window.SecureFx.Constants.NONCE_LENGTH);
                const keyBytes = await window.SecureFx.CryptoCore.deriveKeyBytes(password, window.SecureFx.Constants.MAGIC_V2, currentKdf);
                const decrypted = await window.SecureFx.CryptoCore.decryptGCM(keyBytes, encrypted, nonce);
                document.getElementById('textOutput').value = new TextDecoder().decode(decrypted);
            } catch (e) {
                alert('解密失败: ' + e.message);
            }
        });
    }

    function bindTextCopyBtn() {
        document.getElementById('copyTextBtn')?.addEventListener('click', function () {
            const output = document.getElementById('textOutput');
            output.select();
            document.execCommand('copy');
            alert('已复制到剪贴板');
        });
    }

    function bindTextClearBtn() {
        document.getElementById('clearTextBtn')?.addEventListener('click', function () {
            document.getElementById('textInput').value = '';
            document.getElementById('textOutput').value = '';
        });
    }

    function bindGenerateRSAKeysBtn() {
        document.getElementById('generateRSAKeysBtn')?.addEventListener('click', async function () {
            const keySize = parseInt(document.getElementById('rsaKeySize').value);
            try {
                const keys = await window.SecureFx.AsymmetricCrypto.generateRSAKeyPair(keySize);
                document.getElementById('rsaOutput').value = `公钥:\n${keys.publicKey}\n\n私钥:\n${keys.privateKey}`;
                document.getElementById('rsaDownloadBtns').style.display = 'flex';
                document.getElementById('copyRSABtn').onclick = function () {
                    const output = document.getElementById('rsaOutput');
                    output.select();
                    document.execCommand('copy');
                };
                document.getElementById('downloadRSAKeysBtn').onclick = function () {
                    const blob = new Blob([`公钥:\n${keys.publicKey}\n\n私钥:\n${keys.privateKey}`], { type: 'text/plain' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'rsa_keys.txt';
                    a.click();
                    URL.revokeObjectURL(url);
                };
            } catch (e) {
                alert('生成密钥失败: ' + e.message);
            }
        });
    }

    function bindRSAEncryptBtn() {
        document.getElementById('rsaEncryptBtn')?.addEventListener('click', async function () {
            const publicKey = document.getElementById('rsaPublicKey').value;
            const plaintext = document.getElementById('rsaPlaintext').value;

            if (!publicKey || !plaintext) {
                alert('请输入公钥和要加密的文本');
                return;
            }

            try {
                const encrypted = await window.SecureFx.AsymmetricCrypto.encryptRSA(publicKey, plaintext);
                document.getElementById('rsaOutput').value = encrypted;
                document.getElementById('rsaDownloadBtns').style.display = 'flex';
            } catch (e) {
                alert('加密失败: ' + e.message);
            }
        });
    }

    function bindRSADecryptBtn() {
        document.getElementById('rsaDecryptBtn')?.addEventListener('click', async function () {
            const privateKey = document.getElementById('rsaPrivateKey').value;
            const ciphertext = document.getElementById('rsaCiphertext').value;

            if (!privateKey || !ciphertext) {
                alert('请输入私钥和要解密的文本');
                return;
            }

            try {
                const decrypted = await window.SecureFx.AsymmetricCrypto.decryptRSA(privateKey, ciphertext);
                document.getElementById('rsaOutput').value = decrypted;
                document.getElementById('rsaDownloadBtns').style.display = 'flex';
            } catch (e) {
                alert('解密失败: ' + e.message);
            }
        });
    }

    function bindGenerateECCKeysBtn() {
        document.getElementById('generateECCKeysBtn')?.addEventListener('click', async function () {
            try {
                const keys = await window.SecureFx.FileOperations.generateECDSAKeyPair();
                document.getElementById('eccPublicKey').value = keys.publicKey;
                document.getElementById('eccPrivateKey').value = keys.privateKey;
                document.getElementById('downloadECCKeysBtn').style.display = 'flex';
                document.getElementById('downloadECCKeysBtn').onclick = function () {
                    const blob = new Blob([`公钥:\n${keys.publicKey}\n\n私钥:\n${keys.privateKey}`], { type: 'text/plain' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'ecc_keys.txt';
                    a.click();
                    URL.revokeObjectURL(url);
                };
            } catch (e) {
                alert('生成密钥失败: ' + e.message);
            }
        });
    }

    function bindECCEncryptBtn() {
        document.getElementById('eccEncryptBtn')?.addEventListener('click', async function () {
            const publicKey = document.getElementById('eccRecipientPublicKey').value;
            const plaintext = document.getElementById('eccPlaintext').value;

            if (!publicKey || !plaintext) {
                alert('请输入公钥和要加密的文本');
                return;
            }

            try {
                const encrypted = await window.SecureFx.AsymmetricCrypto.hybridEncrypt(publicKey, plaintext);
                document.getElementById('eccOutput').value = encrypted;
            } catch (e) {
                alert('加密失败: ' + e.message);
            }
        });
    }

    function bindECCDecryptBtn() {
        document.getElementById('eccDecryptBtn')?.addEventListener('click', async function () {
            const privateKey = document.getElementById('eccDecryptPrivateKey').value;
            const ciphertext = document.getElementById('eccCiphertext').value;

            if (!privateKey || !ciphertext) {
                alert('请输入私钥和要解密的文本');
                return;
            }

            try {
                const decrypted = await window.SecureFx.AsymmetricCrypto.hybridDecrypt(privateKey, ciphertext);
                document.getElementById('eccOutput').value = decrypted;
            } catch (e) {
                alert('解密失败: ' + e.message);
            }
        });
    }

    function bindCalculateHashBtn() {
        document.getElementById('calculateHashBtn')?.addEventListener('click', async function () {
            const input = document.getElementById('hashInput').value;
            if (!input) {
                alert('请输入要计算哈希的文本');
                return;
            }

            try {
                const hash = await window.SecureFx.HashTools.calculateHash(input, currentHashAlgo);
                const resultsDiv = document.getElementById('hashResults');
                resultsDiv.innerHTML = `
                    <div class="hash-result">
                        <span class="hash-label">${currentHashAlgo.toUpperCase()}</span>
                        <span class="hash-value">${hash}</span>
                    </div>
                `;
            } catch (e) {
                alert('计算哈希失败: ' + e.message);
            }
        });
    }

    function bindCalculateFileHashBtn() {
        document.getElementById('calculateFileHashBtn')?.addEventListener('click', async function () {
            const fileInput = document.getElementById('fileHashInput');
            const file = fileInput.files[0];
            const algo = document.getElementById('fileHashAlgo').value;
            const expectedHash = document.getElementById('verifyHash').value;

            if (!file) {
                alert('请选择文件');
                return;
            }

            try {
                const hash = await window.SecureFx.HashTools.calculateFileHash(file, algo);
                const resultsDiv = document.getElementById('fileHashResults');
                resultsDiv.innerHTML = `
                    <div class="hash-result">
                        <span class="hash-label">${algo.toUpperCase()}</span>
                        <span class="hash-value">${hash}</span>
                    </div>
                `;

                if (expectedHash) {
                    const verifyDiv = document.getElementById('hashVerifyResult');
                    if (hash.toLowerCase() === expectedHash.toLowerCase()) {
                        verifyDiv.className = 'result-box success';
                        verifyDiv.innerHTML = '<h4>✅ 哈希匹配！</h4>';
                    } else {
                        verifyDiv.className = 'result-box error';
                        verifyDiv.innerHTML = '<h4>❌ 哈希不匹配</h4>';
                    }
                }
            } catch (e) {
                alert('计算哈希失败: ' + e.message);
            }
        });
    }

    function bindEncodingEncodeBtn() {
        document.getElementById('encodingEncodeBtn')?.addEventListener('click', function () {
            const input = document.getElementById('encodingInput').value;
            if (!input) {
                alert('请输入要编码的文本');
                return;
            }

            try {
                let result = '';
                switch (currentEncoding) {
                    case 'base32':
                        result = window.SecureFx.EncodingTools.base32Encode(input);
                        break;
                    case 'base58':
                        result = window.SecureFx.EncodingTools.base58Encode(input);
                        break;
                    case 'vigenere':
                        const vKey = document.getElementById('vigenereKey').value;
                        if (!vKey) { alert('请输入维吉尼亚密钥'); return; }
                        result = window.SecureFx.EncodingTools.vigenereEncrypt(input, vKey);
                        break;
                    case 'railfence':
                        const rails = parseInt(document.getElementById('railfenceRails').value);
                        result = window.SecureFx.EncodingTools.railFenceEncrypt(input, rails);
                        break;
                    case 'bacon':
                        result = window.SecureFx.EncodingTools.baconEncrypt(input);
                        break;
                    case 'atbash':
                        result = window.SecureFx.EncodingTools.atbash(input);
                        break;
                    case 'affine':
                        const a = parseInt(document.getElementById('affineA').value);
                        const b = parseInt(document.getElementById('affineB').value);
                        result = window.SecureFx.EncodingTools.affineEncrypt(input, a, b);
                        break;
                    case 'morse':
                        result = window.SecureFx.EncodingTools.morseEncode(input);
                        break;
                    case 'emoji':
                        result = window.SecureFx.EncodingTools.emojiEncode(input);
                        break;
                    case 'pigpen':
                        result = window.SecureFx.EncodingTools.pigPenEncrypt(input);
                        break;
                    case 'reverse':
                        result = window.SecureFx.EncodingTools.reverseText(input);
                        break;
                    case 'binary':
                        result = window.SecureFx.EncodingTools.textToBinary(input);
                        break;
                    case 'octal':
                        result = window.SecureFx.EncodingTools.textToOctal(input);
                        break;
                    case 'decimal':
                        result = window.SecureFx.EncodingTools.textToDecimal(input);
                        break;
                    case 'hex':
                        result = window.SecureFx.EncodingTools.textToHex(input);
                        break;
                    case 'caesar':
                        const shift = parseInt(document.getElementById('caesarShift').value);
                        result = window.SecureFx.EncodingTools.caesarEncrypt(input, shift);
                        break;
                    case 'rot13':
                        result = window.SecureFx.EncodingTools.rot13(input);
                        break;
                    case 'sm4':
                        let sm4Key = document.getElementById('sm4Key').value;
                        if (!sm4Key) {
                            sm4Key = window.SecureFx.CryptoCore.arrayToHex(crypto.getRandomValues(new Uint8Array(16)));
                            document.getElementById('sm4Key').value = sm4Key;
                        }
                        result = window.SecureFx.HashTools.sm4Encrypt(input, sm4Key);
                        break;
                    case 'chacha20':
                        let chachaKey = document.getElementById('chacha20Key').value;
                        if (!chachaKey) {
                            chachaKey = window.SecureFx.CryptoCore.arrayToHex(crypto.getRandomValues(new Uint8Array(32)));
                            document.getElementById('chacha20Key').value = chachaKey;
                        }
                        result = window.SecureFx.HashTools.chacha20Encrypt(input, chachaKey);
                        break;
                    default:
                        alert('未知的编码方式');
                        return;
                }
                document.getElementById('encodingOutput').value = result;
            } catch (e) {
                alert('编码失败: ' + e.message);
            }
        });
    }

    function bindEncodingDecodeBtn() {
        document.getElementById('encodingDecodeBtn')?.addEventListener('click', function () {
            const input = document.getElementById('encodingInput').value;
            if (!input) {
                alert('请输入要解码的文本');
                return;
            }

            try {
                let result = '';
                switch (currentEncoding) {
                    case 'base32':
                        result = window.SecureFx.EncodingTools.base32Decode(input);
                        break;
                    case 'base58':
                        result = window.SecureFx.EncodingTools.base58Decode(input);
                        break;
                    case 'vigenere':
                        const vKey = document.getElementById('vigenereKey').value;
                        if (!vKey) { alert('请输入维吉尼亚密钥'); return; }
                        result = window.SecureFx.EncodingTools.vigenereDecrypt(input, vKey);
                        break;
                    case 'railfence':
                        const rails = parseInt(document.getElementById('railfenceRails').value);
                        result = window.SecureFx.EncodingTools.railFenceDecrypt(input, rails);
                        break;
                    case 'bacon':
                        result = window.SecureFx.EncodingTools.baconDecode(input);
                        break;
                    case 'atbash':
                        result = window.SecureFx.EncodingTools.atbash(input);
                        break;
                    case 'affine':
                        const a = parseInt(document.getElementById('affineA').value);
                        const b = parseInt(document.getElementById('affineB').value);
                        result = window.SecureFx.EncodingTools.affineDecrypt(input, a, b);
                        break;
                    case 'morse':
                        result = window.SecureFx.EncodingTools.morseDecode(input);
                        break;
                    case 'emoji':
                        result = window.SecureFx.EncodingTools.emojiDecode(input);
                        break;
                    case 'pigpen':
                        result = window.SecureFx.EncodingTools.pigPenDecode(input);
                        break;
                    case 'reverse':
                        result = window.SecureFx.EncodingTools.reverseText(input);
                        break;
                    case 'binary':
                        result = window.SecureFx.EncodingTools.textToHex(input);
                        break;
                    case 'octal':
                        result = window.SecureFx.EncodingTools.textToHex(input);
                        break;
                    case 'decimal':
                        result = window.SecureFx.EncodingTools.textToHex(input);
                        break;
                    case 'hex':
                        result = window.SecureFx.EncodingTools.textToHex(input);
                        break;
                    case 'caesar':
                        const shift = parseInt(document.getElementById('caesarShift').value);
                        result = window.SecureFx.EncodingTools.caesarDecrypt(input, shift);
                        break;
                    case 'rot13':
                        result = window.SecureFx.EncodingTools.rot13(input);
                        break;
                    case 'sm4':
                        const sm4Key = document.getElementById('sm4Key').value;
                        if (!sm4Key) { alert('请输入SM4密钥'); return; }
                        result = window.SecureFx.HashTools.sm4Decrypt(input, sm4Key);
                        break;
                    case 'chacha20':
                        const chachaKey = document.getElementById('chacha20Key').value;
                        if (!chachaKey) { alert('请输入ChaCha20密钥'); return; }
                        result = window.SecureFx.HashTools.chacha20Decrypt(input, chachaKey);
                        break;
                    default:
                        alert('未知的解码方式');
                        return;
                }
                document.getElementById('encodingOutput').value = result;
            } catch (e) {
                alert('解码失败: ' + e.message);
            }
        });
    }

    function bindEncodingCopyBtn() {
        document.getElementById('copyEncodingBtn')?.addEventListener('click', function () {
            const output = document.getElementById('encodingOutput');
            output.select();
            document.execCommand('copy');
            alert('已复制到剪贴板');
        });
    }

    function bindEncodingClearBtn() {
        document.getElementById('clearEncodingBtn')?.addEventListener('click', function () {
            document.getElementById('encodingInput').value = '';
            document.getElementById('encodingOutput').value = '';
        });
    }

    function bindGenerateSignKeysBtn() {
        document.getElementById('generateSignKeysBtn')?.addEventListener('click', async function () {
            try {
                const keys = await window.SecureFx.FileOperations.generateECDSAKeyPair();
                document.getElementById('signPublicKey').value = keys.publicKey;
                document.getElementById('signPrivateKey').value = keys.privateKey;
                const fingerprint = await window.SecureFx.FileOperations.getKeyFingerprint(keys.publicKey);
                document.getElementById('signKeyFingerprint').value = fingerprint;
                document.getElementById('downloadSignKeysBtn').style.display = 'flex';
                document.getElementById('downloadSignKeysBtn').onclick = function () {
                    const blob = new Blob([`公钥:\n${keys.publicKey}\n\n私钥:\n${keys.privateKey}\n\n指纹:${fingerprint}`], { type: 'text/plain' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'ecdsa_keys.txt';
                    a.click();
                    URL.revokeObjectURL(url);
                };
            } catch (e) {
                alert('生成密钥失败: ' + e.message);
            }
        });
    }

    function bindSignDataBtn() {
        document.getElementById('signDataBtn')?.addEventListener('click', async function () {
            const privateKey = document.getElementById('signPrivateKeyInput').value;
            const plaintext = document.getElementById('signPlaintext').value;

            if (!privateKey || !plaintext) {
                alert('请输入私钥和要签名的文本');
                return;
            }

            try {
                const signature = await window.SecureFx.FileOperations.signData(privateKey, plaintext);
                document.getElementById('signOutput').value = signature;
            } catch (e) {
                alert('签名失败: ' + e.message);
            }
        });
    }

    function bindVerifySignBtn() {
        document.getElementById('verifySignBtn')?.addEventListener('click', async function () {
            const publicKey = document.getElementById('verifyPublicKey').value;
            const plaintext = document.getElementById('verifyPlaintext').value;
            const signature = document.getElementById('verifySignature').value;

            if (!publicKey || !plaintext || !signature) {
                alert('请输入公钥、原始文本和签名');
                return;
            }

            try {
                const valid = await window.SecureFx.FileOperations.verifySignature(publicKey, plaintext, signature);
                if (valid) {
                    alert('✅ 签名有效！');
                } else {
                    alert('❌ 签名无效');
                }
            } catch (e) {
                alert('验证失败: ' + e.message);
            }
        });
    }

    function bindGenerateKeyBtn() {
        document.getElementById('generateKeyBtn')?.addEventListener('click', function () {
            const keyLength = parseInt(document.getElementById('keyLength').value);
            const key = window.SecureFx.CryptoCore.generateRandomKey(keyLength);
            const keyContent = document.getElementById('keyContent');
            keyContent.textContent = window.SecureFx.CryptoCore.arrayToHex(key);
            const keyDisplay = document.getElementById('keyDisplay');
            keyDisplay.classList.add('active');
            keyDisplayActive = true;
            let countdown = 5;
            const timerSpan = document.getElementById('keyTimer');
            timerSpan.textContent = countdown + '秒后清除';
            keyTimer = setInterval(function () {
                countdown--;
                if (countdown <= 0) {
                    clearInterval(keyTimer);
                    keyTimer = null;
                    keyContent.textContent = '*** 已清除 ***';
                    keyDisplay.classList.remove('active');
                    keyDisplayActive = false;
                    window.SecureFx.SecurityUtils.attemptMemoryClear(key);
                } else {
                    timerSpan.textContent = countdown + '秒后清除';
                }
            }, 1000);
        });
    }

    function bindCheckStrengthBtn() {
        document.getElementById('checkStrengthBtn')?.addEventListener('click', function () {
            const password = document.getElementById('strengthCheckPassword').value;
            if (!password) {
                alert('请输入要检测的密码');
                return;
            }

            const result = window.SecureFx.PasswordTools.evaluatePasswordDetailed(password);
            const container = document.getElementById('strengthResultContainer');
            container.style.display = 'block';
            const strengthDiv = document.getElementById('fullStrengthDisplay');
            let strengthClass = '';
            let strengthText = '';
            if (result.score === 0) { strengthClass = 'very-weak'; strengthText = '非常弱'; }
            else if (result.score === 1) { strengthClass = 'weak'; strengthText = '弱'; }
            else if (result.score === 2) { strengthClass = 'fair'; strengthText = '一般'; }
            else if (result.score === 3) { strengthClass = 'strong'; strengthText = '强'; }
            else { strengthClass = 'very-strong'; strengthText = '非常强'; }
            strengthDiv.className = 'password-strength active ' + strengthClass;
            strengthDiv.innerHTML = `<span>密码强度: ${strengthText}</span><div class="strength-bar"></div>`;
            const detailsDiv = document.getElementById('strengthDetails');
            let detailsHtml = '<h4>详细分析</h4>';
            if (result.feedback.warning) detailsHtml += `<p class="warning">⚠️ ${result.feedback.warning}</p>`;
            if (result.feedback.suggestions.length > 0) {
                detailsHtml += '<ul>';
                result.feedback.suggestions.forEach(s => detailsHtml += `<li>💡 ${s}</li>`);
                detailsHtml += '</ul>';
            }
            detailsHtml += `<p><strong>猜测时间:</strong> ${result.crack_times_display.offline_slow_hashing_1e4_per_second}</p>`;
            detailsDiv.innerHTML = detailsHtml;
        });
    }

    function bindRunRandomnessTestsBtn() {
        document.getElementById('runRandomnessTestsBtn')?.addEventListener('click', async function () {
            const modeToggle = document.querySelector('#randomness-section .mode-toggle-btn.active');
            const mode = modeToggle.dataset.randomnessMode;
            const inputToggle = document.querySelector('#randomness-section .algo-option[data-randomness-input].selected');
            const inputType = inputToggle ? inputToggle.dataset.randomnessInput : 'binary';

            let bits;

            try {
                if (mode === 'text') {
                    const input = document.getElementById('randomnessInput').value;
                    if (!input) { alert('请输入数据'); return; }
                    if (inputType === 'hex') {
                        bits = window.SecureFx.RandomnessTests.hexToBits(input);
                    } else {
                        bits = window.SecureFx.RandomnessTests.binaryStringToBits(input);
                    }
                } else {
                    const fileInput = document.getElementById('randomnessFileInput');
                    const file = fileInput.files[0];
                    if (!file) { alert('请选择文件'); return; }
                    const arrayBuffer = await file.arrayBuffer();
                    bits = window.SecureFx.RandomnessTests.arrayBufferToBits(arrayBuffer);
                }

                const tests = [];
                const resultsDiv = document.getElementById('randomnessResults');
                resultsDiv.style.display = 'block';
                resultsDiv.innerHTML = '<h4>执行检测中...</h4>';

                if (document.getElementById('testMonobit').checked) tests.push('monobit');
                if (document.getElementById('testBlockFrequency').checked) tests.push('blockFrequency');
                if (document.getElementById('testPoker').checked) tests.push('poker');
                if (document.getElementById('testRuns').checked) tests.push('runs');
                if (document.getElementById('testLongestRun').checked) tests.push('longestRunOfOnes');
                if (document.getElementById('testRank').checked) tests.push('rank');
                if (document.getElementById('testDFT').checked) tests.push('discreteFourierTransform');
                if (document.getElementById('testApproximateEntropy').checked) tests.push('approximateEntropy');
                if (document.getElementById('testCumulativeSums').checked) tests.push('cumulativeSums');

                let html = '<h4>检测结果</h4><table class="guide-table"><tr><th>检测项目</th><th>P值</th><th>结果</th></tr>';
                let passedCount = 0;

                for (const testName of tests) {
                    let result;
                    try {
                        switch (testName) {
                            case 'monobit':
                                result = window.SecureFx.RandomnessTests.monobit(bits);
                                break;
                            case 'blockFrequency':
                                result = window.SecureFx.RandomnessTests.blockFrequency(bits);
                                break;
                            case 'poker':
                                result = window.SecureFx.RandomnessTests.poker(bits);
                                break;
                            case 'runs':
                                result = window.SecureFx.RandomnessTests.runs(bits);
                                break;
                            case 'longestRunOfOnes':
                                result = window.SecureFx.RandomnessTests.longestRunOfOnes(bits);
                                break;
                            case 'rank':
                                result = window.SecureFx.RandomnessTests.rank(bits);
                                break;
                            case 'discreteFourierTransform':
                                result = window.SecureFx.RandomnessTests.discreteFourierTransform(bits);
                                break;
                            case 'approximateEntropy':
                                result = window.SecureFx.RandomnessTests.approximateEntropy(bits);
                                break;
                            case 'cumulativeSums':
                                result = window.SecureFx.RandomnessTests.cumulativeSums(bits);
                                break;
                            default:
                                continue;
                        }

                        const passed = result.pValue >= 0.01;
                        if (passed) passedCount++;
                        const testNames = {
                            monobit: '单比特频数检测',
                            blockFrequency: '块内频数检测',
                            poker: '扑克检测',
                            runs: '游程总数检测',
                            longestRunOfOnes: '块内最大游程检测',
                            rank: '矩阵秩检测',
                            discreteFourierTransform: '离散傅里叶检测',
                            approximateEntropy: '近似熵检测',
                            cumulativeSums: '累加和检测'
                        };
                        html += `<tr><td>${testNames[testName]}</td><td>${result.pValue.toFixed(6)}</td><td class="${passed ? 'test-passed' : 'test-failed'}">${passed ? '✅ 通过' : '❌ 失败'}</td></tr>`;
                    } catch (e) {
                        html += `<tr><td>${testName}</td><td>-</td><td class="test-failed">❌ 错误: ${e.message}</td></tr>`;
                    }
                }

                html += '</table>';
                html += `<p><strong>总计: ${passedCount}/${tests.length} 通过</strong></p>`;
                if (passedCount === tests.length) {
                    html += '<p class="result-box success">✅ 通过所有检测！数据具有良好的随机性。</p>';
                } else if (passedCount >= tests.length * 0.8) {
                    html += '<p class="result-box warning">⚠️ 大部分检测通过，数据随机性一般。</p>';
                } else {
                    html += '<p class="result-box error">❌ 多项检测失败，数据随机性较差。</p>';
                }
                resultsDiv.innerHTML = html;
            } catch (e) {
                alert('检测失败: ' + e.message);
            }
        });
    }

    function bindRunSelfTestBtn() {
        document.getElementById('runSelfTestBtn')?.addEventListener('click', async function () {
            const resultDiv = document.getElementById('selfTestResult');
            resultDiv.innerHTML = '';
            let errorCount = 0;
            const tests = [];

            function log(text) {
                resultDiv.innerHTML += text.replace(/\n/g, '<br>');
            }

            log('SecureFx 自检开始...\n\n');

            try {
                log('测试 1/10: 常量定义... ');
                if (window.SecureFx.Constants.MAGIC_V2 && window.SecureFx.Constants.KEY_LENGTH === 32) {
                    tests.push({ name: '常量定义', passed: true });
                    log('✅ 通过\n');
                } else {
                    tests.push({ name: '常量定义', passed: false });
                    log('❌ 失败\n');
                    errorCount++;
                }
            } catch (e) {
                tests.push({ name: '常量定义', passed: false });
                log(`❌ 失败: ${e.message}\n`);
                errorCount++;
            }

            try {
                log('测试 2/10: 安全工具函数... ');
                const a = new Uint8Array([1, 2, 3]);
                const b = new Uint8Array([1, 2, 3]);
                const c = new Uint8Array([1, 2, 4]);
                if (window.SecureFx.SecurityUtils.constantTimeCompare(a, b) && !window.SecureFx.SecurityUtils.constantTimeCompare(a, c)) {
                    tests.push({ name: '安全工具函数', passed: true });
                    log('✅ 通过\n');
                } else {
                    tests.push({ name: '安全工具函数', passed: false });
                    log('❌ 失败\n');
                    errorCount++;
                }
            } catch (e) {
                tests.push({ name: '安全工具函数', passed: false });
                log(`❌ 失败: ${e.message}\n`);
                errorCount++;
            }

            try {
                log('测试 3/10: 加密核心 (Base64)... ');
                const testData = new Uint8Array([72, 101, 108, 108, 111]);
                const base64 = window.SecureFx.CryptoCore.arrayToBase64(testData);
                const decoded = window.SecureFx.CryptoCore.base64ToArray(base64);
                if (window.SecureFx.SecurityUtils.constantTimeCompare(testData, decoded)) {
                    tests.push({ name: 'Base64编码', passed: true });
                    log('✅ 通过\n');
                } else {
                    tests.push({ name: 'Base64编码', passed: false });
                    log('❌ 失败\n');
                    errorCount++;
                }
            } catch (e) {
                tests.push({ name: 'Base64编码', passed: false });
                log(`❌ 失败: ${e.message}\n`);
                errorCount++;
            }

            try {
                log('测试 4/10: 密码工具... ');
                const pwResult = window.SecureFx.PasswordTools.evaluatePassword('TestPassword123!');
                if (pwResult.score >= 2) {
                    tests.push({ name: '密码工具', passed: true });
                    log('✅ 通过\n');
                } else {
                    tests.push({ name: '密码工具', passed: false });
                    log('❌ 失败\n');
                    errorCount++;
                }
            } catch (e) {
                tests.push({ name: '密码工具', passed: false });
                log(`❌ 失败: ${e.message}\n`);
                errorCount++;
            }

            try {
                log('测试 5/10: 编码工具 (Base32)... ');
                const testStr = 'Hello World';
                const encoded = window.SecureFx.EncodingTools.base32Encode(testStr);
                const decoded = window.SecureFx.EncodingTools.base32Decode(encoded);
                if (testStr === decoded) {
                    tests.push({ name: 'Base32编码', passed: true });
                    log('✅ 通过\n');
                } else {
                    tests.push({ name: 'Base32编码', passed: false });
                    log('❌ 失败\n');
                    errorCount++;
                }
            } catch (e) {
                tests.push({ name: 'Base32编码', passed: false });
                log(`❌ 失败: ${e.message}\n`);
                errorCount++;
            }

            try {
                log('测试 6/10: 哈希工具 (SHA-256)... ');
                const hash = await window.SecureFx.HashTools.calculateHash('test', 'sha256');
                if (hash && hash.length === 64) {
                    tests.push({ name: 'SHA-256哈希', passed: true });
                    log('✅ 通过\n');
                } else {
                    tests.push({ name: 'SHA-256哈希', passed: false });
                    log('❌ 失败\n');
                    errorCount++;
                }
            } catch (e) {
                tests.push({ name: 'SHA-256哈希', passed: false });
                log(`❌ 失败: ${e.message}\n`);
                errorCount++;
            }

            try {
                log('测试 7/10: 随机性检测 (Monobit)... ');
                const randomBits = crypto.getRandomValues(new Uint8Array(1000)).map(b => b % 2);
                const result = window.SecureFx.RandomnessTests.monobit(randomBits);
                if (result.pValue >= 0.01 && result.pValue <= 0.99) {
                    tests.push({ name: '随机性检测', passed: true });
                    log('✅ 通过\n');
                } else {
                    tests.push({ name: '随机性检测', passed: false });
                    log('❌ 失败 (这可能是偶然的)\n');
                    errorCount++;
                }
            } catch (e) {
                tests.push({ name: '随机性检测', passed: false });
                log(`❌ 失败: ${e.message}\n`);
                errorCount++;
            }

            try {
                log('测试 8/10: AES-GCM加密解密... ');
                const key = crypto.getRandomValues(new Uint8Array(32));
                const nonce = crypto.getRandomValues(new Uint8Array(12));
                const plaintext = new TextEncoder().encode('Hello SecureFx!');
                const encrypted = await window.SecureFx.CryptoCore.encryptGCM(key, plaintext, nonce);
                const decrypted = await window.SecureFx.CryptoCore.decryptGCM(key, encrypted, nonce);
                if (window.SecureFx.SecurityUtils.constantTimeCompare(plaintext, decrypted)) {
                    tests.push({ name: 'AES-GCM', passed: true });
                    log('✅ 通过\n');
                } else {
                    tests.push({ name: 'AES-GCM', passed: false });
                    log('❌ 失败\n');
                    errorCount++;
                }
            } catch (e) {
                tests.push({ name: 'AES-GCM', passed: false });
                log(`❌ 失败: ${e.message}\n`);
                errorCount++;
            }

            try {
                log('测试 9/10: Scrypt密钥派生... ');
                const salt = crypto.getRandomValues(new Uint8Array(16));
                const derivedKey = await window.SecureFx.CryptoCore.deriveKeyScrypt('password123', salt);
                if (derivedKey && derivedKey.length === 32) {
                    tests.push({ name: 'Scrypt', passed: true });
                    log('✅ 通过\n');
                } else {
                    tests.push({ name: 'Scrypt', passed: false });
                    log('❌ 失败\n');
                    errorCount++;
                }
            } catch (e) {
                tests.push({ name: 'Scrypt', passed: false });
                log(`❌ 失败: ${e.message}\n`);
                errorCount++;
            }

            try {
                log('测试 10/10: 数字签名... ');
                const keys = await window.SecureFx.FileOperations.generateECDSAKeyPair();
                const signature = await window.SecureFx.FileOperations.signData(keys.privateKey, 'test message');
                const valid = await window.SecureFx.FileOperations.verifySignature(keys.publicKey, 'test message', signature);
                if (valid) {
                    tests.push({ name: '数字签名', passed: true });
                    log('✅ 通过\n');
                } else {
                    tests.push({ name: '数字签名', passed: false });
                    log('❌ 失败\n');
                    errorCount++;
                }
            } catch (e) {
                tests.push({ name: '数字签名', passed: false });
                log(`❌ 失败: ${e.message}\n`);
                errorCount++;
            }

            log('\n' + '─'.repeat(30) + '\n');
            const criticalPassed = tests.filter(t => ['Scrypt', 'Base64编码', 'AES-GCM'].includes(t.name)).every(t => t.passed);

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
        });
    }

    function bindBeforeUnload() {
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
    }

    function bindVisibilityChange() {
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
    }

    function bindPasswordGenerator() {
        document.getElementById('pwdLength')?.addEventListener('input', function () {
            document.getElementById('pwdLengthValue').textContent = this.value;
        });

        document.getElementById('generatePwdBtn')?.addEventListener('click', function () {
            const length = parseInt(document.getElementById('pwdLength').value);
            const options = {
                lowercase: document.getElementById('pwdLower').checked,
                uppercase: document.getElementById('pwdUpper').checked,
                numbers: document.getElementById('pwdNumbers').checked,
                symbols: document.getElementById('pwdSymbols').checked,
                excludeSimilar: document.getElementById('pwdExclude').checked
            };

            let lowercase = 'abcdefghijklmnopqrstuvwxyz';
            let uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            let numbers = '0123456789';
            let symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

            if (options.excludeSimilar) {
                lowercase = lowercase.replace(/[il]/g, '');
                uppercase = uppercase.replace(/[IO]/g, '');
                numbers = numbers.replace(/[01]/g, '');
            }

            let charset = '';
            if (options.lowercase) charset += lowercase;
            if (options.uppercase) charset += uppercase;
            if (options.numbers) charset += numbers;
            if (options.symbols) charset += symbols;

            if (charset === '') {
                alert('请至少选择一种字符类型');
                return;
            }

            let password = '';
            const array = new Uint32Array(length);
            crypto.getRandomValues(array);

            for (let i = 0; i < length; i++) {
                password += charset[array[i] % charset.length];
            }

            const passwordsDiv = document.getElementById('generatedPasswords');
            passwordsDiv.innerHTML = `
                <div class="password-item">
                    <span class="password-text">${password}</span>
                    <div class="password-actions">
                        <button class="btn btn-sm copy-pwd-btn">📋</button>
                    </div>
                </div>
            `;

            const result = window.SecureFx.PasswordTools.evaluatePassword(password);
            const strengthDiv = document.getElementById('generatedPwdStrength');
            let strengthClass = '';
            let strengthText = '';
            if (result.score === 0) { strengthClass = 'very-weak'; strengthText = '非常弱'; }
            else if (result.score === 1) { strengthClass = 'weak'; strengthText = '弱'; }
            else if (result.score === 2) { strengthClass = 'fair'; strengthText = '一般'; }
            else if (result.score === 3) { strengthClass = 'strong'; strengthText = '强'; }
            else { strengthClass = 'very-strong'; strengthText = '非常强'; }
            strengthDiv.className = 'password-strength active ' + strengthClass;
            strengthDiv.innerHTML = `<span>密码强度: ${strengthText}</span><div class="strength-bar"></div>`;

            passwordsDiv.querySelector('.copy-pwd-btn')?.addEventListener('click', function () {
                navigator.clipboard.writeText(password).then(() => {
                    alert('已复制到剪贴板');
                });
            });
        });

        document.getElementById('generateMultiplePwdBtn')?.addEventListener('click', function () {
            const length = parseInt(document.getElementById('pwdLength').value);
            const options = {
                lowercase: document.getElementById('pwdLower').checked,
                uppercase: document.getElementById('pwdUpper').checked,
                numbers: document.getElementById('pwdNumbers').checked,
                symbols: document.getElementById('pwdSymbols').checked,
                excludeSimilar: document.getElementById('pwdExclude').checked
            };

            let lowercase = 'abcdefghijklmnopqrstuvwxyz';
            let uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            let numbers = '0123456789';
            let symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

            if (options.excludeSimilar) {
                lowercase = lowercase.replace(/[il]/g, '');
                uppercase = uppercase.replace(/[IO]/g, '');
                numbers = numbers.replace(/[01]/g, '');
            }

            let charset = '';
            if (options.lowercase) charset += lowercase;
            if (options.uppercase) charset += uppercase;
            if (options.numbers) charset += numbers;
            if (options.symbols) charset += symbols;

            if (charset === '') {
                alert('请至少选择一种字符类型');
                return;
            }

            const passwords = [];
            for (let j = 0; j < 10; j++) {
                let password = '';
                const array = new Uint32Array(length);
                crypto.getRandomValues(array);

                for (let i = 0; i < length; i++) {
                    password += charset[array[i] % charset.length];
                }
                passwords.push(password);
            }

            const passwordsDiv = document.getElementById('generatedPasswords');
            passwordsDiv.innerHTML = passwords.map((pwd, idx) => `
                <div class="password-item">
                    <span class="password-text">${pwd}</span>
                    <div class="password-actions">
                        <button class="btn btn-sm copy-pwd-btn" data-pwd="${pwd}">📋</button>
                    </div>
                </div>
            `).join('');

            passwordsDiv.querySelectorAll('.copy-pwd-btn').forEach(btn => {
                btn.addEventListener('click', function () {
                    navigator.clipboard.writeText(this.dataset.pwd).then(() => {
                        alert('已复制到剪贴板');
                    });
                });
            });

            document.getElementById('generatedPwdStrength').className = 'password-strength';
            document.getElementById('generatedPwdStrength').innerHTML = '';
        });
    }

    function bindDragAndDrop() {
        const uploadAreas = [
            { area: 'fileUploadArea', input: 'fileInput' },
            { area: 'fileHashUploadArea', input: 'fileHashInput' },
            { area: 'randomnessFileArea', input: 'randomnessFileInput' }
        ];

        uploadAreas.forEach(({ area, input }) => {
            const areaEl = document.getElementById(area);
            const inputEl = document.getElementById(input);

            if (!areaEl || !inputEl) return;

            areaEl.addEventListener('dragover', function (e) {
                e.preventDefault();
                e.stopPropagation();
                this.classList.add('dragover');
            });

            areaEl.addEventListener('dragleave', function (e) {
                e.preventDefault();
                e.stopPropagation();
                this.classList.remove('dragover');
            });

            areaEl.addEventListener('drop', function (e) {
                e.preventDefault();
                e.stopPropagation();
                this.classList.remove('dragover');

                if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                    inputEl.files = e.dataTransfer.files;
                    const event = new Event('change', { bubbles: true });
                    inputEl.dispatchEvent(event);
                }
            });
        });
    }

    function init() {
        initTheme();
        bindThemeToggle();
        bindNavigation();
        bindKdfSelector();
        bindHashSelector();
        bindEncodingSelector();
        bindModeToggles();
        bindRangeInputs();
        bindSignOption();
        bindFileUploads();
        bindDragAndDrop();
        bindPasswordStrength();
        bindPasswordGenerator();
        bindFileEncryptBtn();
        bindFileDecryptBtn();
        bindCancelBtn();
        bindTextEncryptBtn();
        bindTextDecryptBtn();
        bindTextCopyBtn();
        bindTextClearBtn();
        bindGenerateRSAKeysBtn();
        bindRSAEncryptBtn();
        bindRSADecryptBtn();
        bindGenerateECCKeysBtn();
        bindECCEncryptBtn();
        bindECCDecryptBtn();
        bindCalculateHashBtn();
        bindCalculateFileHashBtn();
        bindEncodingEncodeBtn();
        bindEncodingDecodeBtn();
        bindEncodingCopyBtn();
        bindEncodingClearBtn();
        bindGenerateSignKeysBtn();
        bindSignDataBtn();
        bindVerifySignBtn();
        bindGenerateKeyBtn();
        bindCheckStrengthBtn();
        bindRunRandomnessTestsBtn();
        bindRunSelfTestBtn();
        bindBeforeUnload();
        bindVisibilityChange();
    }

    window.SecureFx.UIController = {
        showSecurityWarning,
        checkEnvironment,
        updateProgress,
        resetProgress,
        init
    };
})();
