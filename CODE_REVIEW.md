# Code Review Standards

This document defines the code review requirements and standards for the SecureFx project.

## Overview

All code changes must be reviewed before being merged into the main branch. This ensures code quality, security, and maintainability.

## Review Process

### 1. Pre-Review Checklist (Author)

Before requesting a review, ensure:

- [ ] Code follows the [Coding Standards](#coding-standards)
- [ ] All tests pass locally (`npm test`)
- [ ] No ESLint warnings (`npm run lint`)
- [ ] Documentation is updated if needed
- [ ] CHANGELOG.md is updated
- [ ] Self-test suite passes (28 tests in the application)

### 2. Review Requirements

| Change Type | Minimum Reviewers | Requirements |
|-------------|-------------------|--------------|
| Documentation | 1 | Content accuracy |
| Bug fix | 1 | Test coverage, no regressions |
| New feature | 2 | Design review, security review |
| Security-related | 2 | Security team approval required |
| Breaking change | 2 | Migration guide required |

### 3. Review Timeline

| Stage | Target Time |
|-------|-------------|
| Initial response | 24 hours |
| Full review | 3 business days |
| Follow-up reviews | 1 business day |

## What Reviewers Check

### Code Quality

- [ ] Code is readable and well-organized
- [ ] Functions are focused and not too long (< 50 lines preferred)
- [ ] Variable and function names are descriptive
- [ ] Comments explain "why" not "what"
- [ ] No code duplication

### Security

- [ ] No hardcoded secrets or credentials
- [ ] Input validation is present
- [ ] Cryptographic operations use Web Crypto API
- [ ] No eval() or similar dangerous patterns
- [ ] Error messages don't expose sensitive information
- [ ] Memory is cleared after handling sensitive data (best effort)

### Performance

- [ ] No unnecessary computations
- [ ] Large file handling uses streaming
- [ ] No memory leaks
- [ ] UI remains responsive during operations

### Testing

- [ ] New code has corresponding tests
- [ ] Edge cases are tested
- [ ] Tests are meaningful (not just for coverage)

### Documentation

- [ ] Public APIs are documented
- [ ] README is updated if needed
- [ ] Complex logic is explained

## Coding Standards

### JavaScript

```javascript
// Good: Use const/let, descriptive names
const encryptionKey = await deriveKey(password, salt, 'argon2id');

// Bad: Use var, cryptic names
var k = await deriveKey(p, s, 'argon2id');

// Good: Early return for clarity
function validateInput(data) {
    if (!data) return null;
    if (data.length === 0) return null;
    return processData(data);
}

// Bad: Deeply nested conditions
function validateInput(data) {
    if (data) {
        if (data.length > 0) {
            return processData(data);
        } else {
            return null;
        }
    } else {
        return null;
    }
}
```

### Security Patterns

```javascript
// Good: Use Web Crypto API
const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
);

// Bad: Custom crypto implementation
function customEncrypt(data, key) {
    // Never do this!
    return data.split('').reverse().join('');
}

// Good: Constant-time comparison
function constantTimeCompare(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
    }
    return result === 0;
}

// Bad: Timing attack vulnerable
function insecureCompare(a, b) {
    return a === b; // Short-circuits on first difference
}
```

### Error Handling

```javascript
// Good: Specific error messages, no sensitive data
try {
    await decryptFile(encryptedData, password);
} catch (error) {
    if (error.name === 'OperationError') {
        showUserError('Decryption failed. Please check your password.');
    } else {
        showUserError('An unexpected error occurred.');
        console.error('Decryption error:', error.message);
    }
}

// Bad: Exposing internal details
try {
    await decryptFile(encryptedData, password);
} catch (error) {
    alert('Error: ' + error.stack); // Don't expose stack traces
}
```

## Review Feedback Guidelines

### For Reviewers

1. **Be constructive**: Suggest improvements, don't just criticize
2. **Be specific**: Point to exact lines and explain why
3. **Prioritize**: Distinguish between must-fix and nice-to-have
4. **Explain**: Help the author understand the reasoning

### For Authors

1. **Respond to all comments**: Acknowledge each point
2. **Ask questions**: If feedback is unclear, ask for clarification
3. **Don't take it personally**: Reviews are about code quality
4. **Learn**: Use feedback to improve future contributions

## Approval Criteria

A PR can be merged when:

1. All required reviewers have approved
2. All CI checks pass
3. All conversations are resolved
4. No merge conflicts exist
5. Branch is up to date with main

## Reviewer Selection

- Reviews are automatically assigned based on code ownership
- You can request specific reviewers
- At least one reviewer must be different from the author

## Exceptions

Emergency fixes may bypass some requirements:

1. Critical security vulnerabilities
2. Breaking production issues

These must be followed up with a post-merge review within 24 hours.

---

Questions? Ask in [Discussions](../../discussions) or open an issue.
