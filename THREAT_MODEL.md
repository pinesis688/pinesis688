# Threat Model

This document describes the threat model for SecureFx, including identified threats, trust boundaries, and security mitigations.

## System Overview

SecureFx is a browser-based encryption toolkit that operates entirely client-side. It provides:

- File and text encryption/decryption
- Key management (RSA, ECC)
- Digital signatures
- Hash calculations
- Password generation
- Classical ciphers and encoding tools

## Trust Boundaries

### Boundary Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           UNTRUSTED ZONE                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐          │
│  │   User Input    │  │  Uploaded Files │  │    Network      │          │
│  │  (Passwords,    │  │  (Potentially   │  │   (Internet)    │          │
│  │   Text, etc.)   │  │   malicious)    │  │                 │          │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘          │
│           │                    │                    │                    │
└───────────┼────────────────────┼────────────────────┼────────────────────┘
            │                    │                    │
            ▼                    ▼                    ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                          TRUST BOUNDARY                                    │
│  ═════════════════════════════════════════════════════════════════════════ │
└───────────────────────────────────────────────────────────────────────────┘
            │                    │                    │
            ▼                    ▼                    ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                            TRUSTED ZONE                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │                     Browser Environment                              │  │
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐           │  │
│  │  │  SecureFx App │  │  Web Crypto   │  │   Web Workers │           │  │
│  │  │  (app.js)     │  │  API          │  │   (encrypt/   │           │  │
│  │  │               │  │               │  │   decrypt)    │           │  │
│  │  └───────────────┘  └───────────────┘  └───────────────┘           │  │
│  │         │                  │                   │                   │  │
│  │         └──────────────────┴───────────────────┘                   │  │
│  │                            │                                       │  │
│  │                            ▼                                       │  │
│  │  ┌─────────────────────────────────────────────────────────────┐   │  │
│  │  │                    Memory (RAM)                              │   │  │
│  │  │  • Encryption keys                                          │   │  │
│  │  │  • Passwords (temporary)                                    │   │  │
│  │  │  • File data (during processing)                            │   │  │
│  │  └─────────────────────────────────────────────────────────────┘   │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────┘
```

## Assets

### Primary Assets

| Asset | Sensitivity | Location | Protection |
|-------|-------------|----------|------------|
| User passwords | Critical | Memory (temporary) | Never stored, cleared after use |
| Encryption keys | Critical | Memory (temporary) | Generated on-demand, never persisted |
| Encrypted files | High | User's device | AES-256-GCM encryption |
| Private keys | Critical | Memory / User export | RSA/ECC keys, user-controlled |

### Secondary Assets

| Asset | Sensitivity | Location | Protection |
|-------|-------------|----------|------------|
| Application code | Low | Browser | Open source, auditable |
| User preferences | Low | localStorage | Non-sensitive settings |
| UI state | Low | Memory | Non-sensitive |

## Threat Actors

### High Capability

| Actor | Motivation | Capability | Likelihood |
|-------|------------|------------|------------|
| Nation-state | Intelligence gathering | Advanced malware, network interception | Low |
| Organized crime | Financial gain | Malware, phishing | Medium |

### Medium Capability

| Actor | Motivation | Capability | Likelihood |
|-------|------------|------------|------------|
| Malware author | Data theft | Browser extensions, keyloggers | High |
| Insider | Various | Direct access | Low |

### Low Capability

| Actor | Motivation | Capability | Likelihood |
|-------|------------|------------|------------|
| Script kiddie | Curiosity | Basic tools | Medium |
| Casual user | Accidental | N/A | N/A |

## Threat Scenarios

### STRIDE Analysis

| Threat Type | Scenario | Impact | Mitigation |
|-------------|----------|--------|------------|
| **Spoofing** | Attacker creates fake SecureFx site | High | Code signing, HTTPS |
| **Tampering** | Malware modifies app.js in transit | Critical | HTTPS, SRI |
| **Repudiation** | User denies performing encryption | Low | Audit logging (optional) |
| **Information Disclosure** | Keylogger captures password | Critical | User warning, environment check |
| **Denial of Service** | Browser crashes during encryption | Low | Error handling, recovery |
| **Elevation of Privilege** | Browser extension reads memory | Critical | Documented limitation |

### Detailed Threat Analysis

#### T1: Malware on User Device

| Attribute | Value |
|-----------|-------|
| **Threat ID** | T1 |
| **Description** | Malware (keylogger, screen recorder) on user's device captures passwords or encrypted data |
| **Likelihood** | High |
| **Impact** | Critical |
| **Risk** | High (Accepted) |
| **Mitigation** | Security warning modal, user education |
| **Residual Risk** | Cannot be fully mitigated in browser environment |

#### T2: Malicious Browser Extension

| Attribute | Value |
|-----------|-------|
| **Threat ID** | T2 |
| **Description** | Browser extension accesses DOM to steal passwords or keys |
| **Likelihood** | Medium |
| **Impact** | Critical |
| **Risk** | High (Accepted) |
| **Mitigation** | Warning in security modal, user education |
| **Residual Risk** | Cannot be mitigated without extension API changes |

#### T3: Memory Dump Attack

| Attribute | Value |
|-----------|-------|
| **Threat ID** | T3 |
| **Description** | Attacker obtains memory dump containing encryption keys |
| **Likelihood** | Low |
| **Impact** | Critical |
| **Risk** | Medium (Accepted) |
| **Mitigation** | Best-effort memory clearing, keys in memory only briefly |
| **Residual Risk** | JavaScript cannot guarantee secure memory erasure |

#### T4: Weak Password

| Attribute | Value |
|-----------|-------|
| **Threat ID** | T4 |
| **Description** | User chooses weak password that can be brute-forced |
| **Likelihood** | High |
| **Impact** | High |
| **Risk** | High (Mitigated) |
| **Mitigation** | Password strength checker, warnings, Argon2id KDF |
| **Residual Risk** | Low if user follows recommendations |

#### T5: Timing Attack

| Attribute | Value |
|-----------|-------|
| **Threat ID** | T5 |
| **Description** | Attacker uses timing analysis to extract key information |
| **Likelihood** | Very Low |
| **Impact** | Medium |
| **Risk** | Low (Mitigated) |
| **Mitigation** | Constant-time comparison for HMAC verification |
| **Residual Risk** | Minimal |

#### T6: XSS Attack

| Attribute | Value |
|-----------|-------|
| **Threat ID** | T6 |
| **Description** | Cross-site scripting attack injects malicious code |
| **Likelihood** | Low |
| **Impact** | Critical |
| **Risk** | Low (Mitigated) |
| **Mitigation** | No server-side code, CSP headers, input sanitization |
| **Residual Risk** | Minimal |

## Security Assumptions

### Trusted

1. **Browser**: The web browser correctly implements Web Crypto API
2. **HTTPS**: TLS provides secure transport
3. **User Device**: User's device is not compromised (user responsibility)
4. **Source Code**: User has obtained authentic, unmodified code

### Untrusted

1. **Network**: All network communication is potentially monitored
2. **User Input**: All user input is potentially malicious
3. **Uploaded Files**: All uploaded files are potentially malicious

## Security Requirements

### Confidentiality

- User data must remain confidential
- Encryption keys must never be transmitted
- Passwords must never be stored persistently

### Integrity

- Encrypted data must detect tampering
- HMAC verification must be performed
- File signatures must be verified

### Availability

- Application must function offline
- No external dependencies required for core functionality
- Graceful error handling

## Out of Scope

The following are explicitly out of scope for this threat model:

1. **Physical security** of user's device
2. **Operating system** security
3. **Browser vulnerabilities**
4. **Social engineering** attacks
5. **Nation-state level** adversaries with physical access

## Conclusion

SecureFx provides strong cryptographic protection for user data within the constraints of a browser environment. Users must understand the inherent limitations and should not use this tool for protecting data that requires protection beyond what a browser environment can provide.

For the complete security posture, see [SECURITY_REVIEW.md](SECURITY_REVIEW.md).
