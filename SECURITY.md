# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.0.x   | :white_check_mark: |
| < 3.0   | :x:                |

## Reporting a Vulnerability

We take the security of SecureFx seriously. If you have discovered a security vulnerability, we appreciate your help in disclosing it to us in a responsible manner.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via:

1. **GitHub Security Advisory** (Preferred)
   - Go to the "Security" tab in our GitHub repository
   - Click "Report a vulnerability"
   - Fill in the details of the vulnerability

2. **Email** (Alternative)
   - Send an email to the project maintainers
   - Include "SECURITY" in the subject line

### What to Include

Please include the following information:

- Type of vulnerability (e.g., XSS, injection, cryptographic weakness)
- Full paths of source file(s) related to the vulnerability
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability

### Response Timeline

| Stage | Timeframe |
|-------|-----------|
| Initial Response | Within 7 days |
| Vulnerability Confirmation | Within 14 days |
| Fix Development | Within 30 days (critical) / 90 days (others) |
| Patch Release | After fix is verified |

### Disclosure Policy

- We follow responsible disclosure practices
- We ask that you give us reasonable time to fix the vulnerability before public disclosure
- We will credit you in the security advisory (unless you prefer to remain anonymous)

## Security Best Practices

### For Users

1. **Always use the latest version** - Security patches are included in new releases
2. **Use strong passwords** - Minimum 12 characters with mixed character types
3. **Keep your browser updated** - We use Web Crypto API which requires modern browsers
4. **Verify file integrity** - Check file hashes after encryption/decryption
5. **Secure your environment** - Ensure your device is free from malware

### For Developers

1. **Never commit secrets** - API keys, passwords, or private keys should never be in the repository
2. **Use secure dependencies** - Run `npm audit` regularly
3. **Follow cryptographic best practices** - Use Web Crypto API, not custom implementations
4. **Review code changes** - All PRs should be reviewed before merging

## Known Security Considerations

### JavaScript Environment Limitations

This tool runs entirely in the browser using JavaScript. Please be aware of these inherent limitations:

1. **Memory Security**: JavaScript has automatic garbage collection and cannot securely erase sensitive data from memory
2. **Side-Channel Attacks**: Browser environments may be vulnerable to timing attacks
3. **Malware Threats**: This tool cannot protect against keyloggers, screen capture, or other malware
4. **Extension Access**: Browser extensions may have access to page content and data

### What This Tool Does NOT Protect Against

- Malware on your device
- Browser extensions that can read page content
- Network-level attacks (use HTTPS)
- Physical access to your device
- Compromised operating systems

## Prohibited Use Cases

This tool is **NOT** approved for:

- National/state secrets
- Financial core systems data
- Level 3+ classified data protection
- Any legally prohibited scenarios

## Security Features

| Feature | Implementation |
|---------|---------------|
| Encryption | AES-256-GCM (default), AES-256-CBC |
| Key Derivation | Argon2id, Scrypt |
| Hashing | SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512 |
| Asymmetric | RSA-OAEP (2048/4096), ECDSA P-256 |
| Random Number Generation | Web Crypto API (cryptographically secure) |

## Security Audit

This project includes a self-test suite with 28 automated security checks. You can run these tests from the "Self-Test" section in the application.

## Contact

For security-related questions or concerns, please use the reporting channels above.

---

Thank you for helping keep SecureFx and its users safe!
