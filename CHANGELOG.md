# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2025-02-16

### Added
- **Password Strength Checker** - Standalone tool for detailed password analysis
  - Entropy calculation
  - Character type verification
  - Security warnings and suggestions
  - Offline crack time estimation
- **Randomness Testing Suite** - NIST SP 800-22 compliant tests
  - Monobit frequency test
  - Block frequency test
  - Poker test
  - Runs test
  - Longest run test
  - Matrix rank test
  - Discrete Fourier Transform test
  - Approximate entropy test
  - Cumulative sums test
- **Security Modal** - Risk acknowledgment dialog on startup
  - Two-checkbox confirmation
  - localStorage-based persistence
  - Keyboard shortcut to reset (Ctrl+Shift+S)
- **Enhanced UI** - Improved navigation and visual design
  - New sidebar entries for password strength and randomness testing
  - Mobile-friendly bottom navigation updates

### Changed
- Improved FFT implementation for randomness testing
- Refactored security warning handling
- Better error handling in cryptographic operations

### Fixed
- Fixed security modal display issues
- Fixed button click handlers in security dialog
- Fixed FFT boundary conditions

## [2.0.0] - 2024-12-01

### Added
- **Argon2id Support** - Memory-hard key derivation function
- **SHA-3 Hashing** - SHA3-256 and SHA3-512 support
- **SM4 Encryption** - Chinese national encryption standard
- **SM3 Hashing** - Chinese national hash algorithm
- **ChaCha20** - Stream cipher implementation
- **Enhanced Self-Test Suite** - 28 automated security tests
- **Audit Logging** - Optional operation logging (disabled by default for privacy)

### Changed
- Migrated to Web Crypto API for all cryptographic operations
- Improved large file handling with chunked encryption
- Enhanced password generation with rejection sampling

### Fixed
- Memory management improvements
- UI responsiveness on mobile devices

## [1.0.0] - 2024-06-01

### Added
- **File Encryption** - AES-256-GCM/CBC with Argon2id/Scrypt KDF
- **Text Encryption** - Symmetric encryption for text
- **RSA Encryption** - RSA-OAEP 2048/4096 bit
- **ECC Encryption** - ECDSA P-256 with AES-GCM (ECIES)
- **Digital Signatures** - Text and file signing
- **Hash Calculator** - SHA-256, SHA-384, SHA-512, MD5
- **Password Generator** - Configurable length and character sets
- **Key Management** - RSA/ECC key pair generation
- **Classical Ciphers** - Vigenère, Caesar, ROT13, Rail Fence, etc.
- **Encoding Tools** - Base64, Base32, Base58, Morse, Hex, Binary
- **Dark/Light Theme** - System-aware theme switching
- **Responsive Design** - Mobile-friendly interface
- **Offline Support** - Works without internet connection

### Security Features
- All operations run locally in the browser
- No data sent to any server
- Uses Web Crypto API for cryptographic operations
- Cryptographically secure random number generation

---

## Version History Summary

| Version | Date | Key Features |
|---------|------|--------------|
| 3.0.0 | 2025-02-16 | Password strength checker, Randomness testing |
| 2.0.0 | 2024-12-01 | Argon2id, SHA-3, SM4, ChaCha20 |
| 1.0.0 | 2024-06-01 | Initial release with core encryption features |

---

[3.0.0]: https://github.com/pinesis/SecureFx/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/pinesis/SecureFx/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/pinesis/SecureFx/releases/tag/v1.0.0
