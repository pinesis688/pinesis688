# Contributing to SecureFx

Thank you for your interest in contributing to SecureFx! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Testing](#testing)
- [Security](#security)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

1. Fork the repository
2. Clone your fork locally
   ```bash
   git clone https://github.com/YOUR_USERNAME/SecureFx.git
   cd SecureFx
   ```
3. Create a branch for your changes
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Prerequisites

- Modern web browser (Chrome 60+, Firefox 60+, Safari 14+, or Edge 79+)
- A local web server (for development)
- Basic knowledge of JavaScript and Web Crypto API

### Running Locally

Simply open `index.html` in your browser, or use a local server:

```bash
# Using Python
python -m http.server 8000

# Using Node.js (npx)
npx serve .

# Using PHP
php -S localhost:8000
```

Then open `http://localhost:8000` in your browser.

### Project Structure

```
SecureFx/
├── index.html          # Main HTML file
├── app.js              # Main application logic
├── style.css           # Styles
├── zxcvbn.js           # Password strength library
├── argon2-bundled.min.js # Argon2 KDF implementation
├── encrypt-worker.js   # Web Worker for encryption
├── decrypt-worker.js   # Web Worker for decryption
├── SECURITY.md         # Security policy
├── CONTRIBUTING.md     # This file
├── CODE_OF_CONDUCT.md  # Code of conduct
├── CHANGELOG.md        # Version history
└── README.md           # Project documentation
```

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](../../issues)
2. If not, create a new issue using the Bug Report template
3. Include:
   - Browser and version
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Screenshots (if applicable)

### Suggesting Features

1. Check existing issues for similar suggestions
2. Create a new issue using the Feature Request template
3. Describe the feature and its use case

### Submitting Code

1. Create a feature branch from `main`
2. Make your changes
3. Test thoroughly
4. Submit a Pull Request

## Coding Standards

### JavaScript Style Guide

- Use ES6+ features where appropriate
- Use `const` and `let` instead of `var`
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions small and focused

```javascript
// Good
const encryptData = async (data, password, options = {}) => {
    const salt = generateSalt();
    const key = await deriveKey(password, salt, options.kdf);
    return encrypt(data, key, salt);
};

// Avoid
function enc(d, p, o) {
    var s = genSalt();
    var k = deriveKey(p, s, o ? o.kdf : 'scrypt');
    return enc(d, k, s);
}
```

### Security Considerations

When contributing code that involves cryptography:

1. **Use Web Crypto API** - Never implement custom cryptographic algorithms
2. **No hardcoded secrets** - Never commit API keys, passwords, or private keys
3. **Validate inputs** - Always validate user inputs
4. **Handle errors securely** - Don't expose sensitive information in error messages
5. **Use constant-time comparison** - For security-sensitive comparisons

### CSS Guidelines

- Use CSS custom properties (variables) for theming
- Follow the existing naming conventions
- Ensure responsive design works on mobile devices

### HTML Guidelines

- Use semantic HTML elements
- Ensure accessibility (ARIA labels, keyboard navigation)
- Keep the document structure clean and organized

## Commit Guidelines

We follow conventional commits:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### Examples

```
feat(encryption): add support for AES-256-GCM

fix(decryption): handle corrupted file headers correctly

docs(readme): update installation instructions

refactor(key-derivation): simplify Argon2 parameter handling
```

## Pull Request Process

1. **Update Documentation** - Update README.md if needed
2. **Update CHANGELOG.md** - Add your changes to the changelog
3. **Test Thoroughly** - Ensure all features work correctly
4. **Run Self-Tests** - Use the built-in self-test feature
5. **Request Review** - Wait for a maintainer to review your PR

### PR Checklist

- [ ] Code follows the project's coding standards
- [ ] All existing functionality still works
- [ ] New features are tested
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated
- [ ] No security vulnerabilities introduced

## Testing

### Manual Testing

1. Open the application in your browser
2. Navigate to the "Self-Test" section
3. Run all 28 automated tests
4. Verify your changes work as expected

### Test Cases to Consider

- File encryption/decryption with various sizes
- Text encryption/decryption
- Password generation
- Hash calculations
- Key generation
- Digital signatures

## Security

If you discover a security vulnerability, please follow our [Security Policy](SECURITY.md).

**Do NOT**:
- Commit sensitive data
- Create public issues for security vulnerabilities
- Share credentials or keys

## Questions?

If you have questions, feel free to:
- Open an issue with the "question" label
- Start a discussion in the Discussions section

---

Thank you for contributing to SecureFx! 🔐
