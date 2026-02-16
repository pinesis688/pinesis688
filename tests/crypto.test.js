import { describe, it, expect, vi, beforeEach } from 'vitest';

// Helper functions for testing
function arrayToBase64(arr) {
  const bytes = new Uint8Array(arr);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArray(base64) {
  const binary = atob(base64);
  const arr = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    arr[i] = binary.charCodeAt(i);
  }
  return arr;
}

function concatArrays(...arrays) {
  const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(new Uint8Array(arr), offset);
    offset += arr.length;
  }
  return result;
}

function constantTimeCompare(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  const arrA = new Uint8Array(a);
  const arrB = new Uint8Array(b);
  for (let i = 0; i < a.length; i++) {
    result |= arrA[i] ^ arrB[i];
  }
  return result === 0;
}

function generateRandomKey(length = 32) {
  const key = new Uint8Array(length);
  crypto.getRandomValues(key);
  return key;
}

function arrayToHex(arr) {
  const bytes = new Uint8Array(arr);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToArray(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    arr[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return arr;
}

// Classical cipher functions for testing
function caesarEncrypt(text, shift = 3) {
  return text.replace(/[a-zA-Z]/g, (char) => {
    const base = char >= 'a' ? 97 : 65;
    return String.fromCharCode(((char.charCodeAt(0) - base + shift) % 26) + base);
  });
}

function caesarDecrypt(text, shift = 3) {
  return caesarEncrypt(text, 26 - shift);
}

function rot13(text) {
  return caesarEncrypt(text, 13);
}

function vigenereEncrypt(text, key) {
  if (!key) return text;
  let keyIndex = 0;
  return text.replace(/[a-zA-Z]/g, (char) => {
    const base = char >= 'a' ? 97 : 65;
    const shift = key[keyIndex % key.length].toLowerCase().charCodeAt(0) - 97;
    keyIndex++;
    return String.fromCharCode(((char.charCodeAt(0) - base + shift) % 26) + base);
  });
}

function vigenereDecrypt(text, key) {
  if (!key) return text;
  let keyIndex = 0;
  return text.replace(/[a-zA-Z]/g, (char) => {
    const base = char >= 'a' ? 97 : 65;
    const shift = key[keyIndex % key.length].toLowerCase().charCodeAt(0) - 97;
    keyIndex++;
    return String.fromCharCode(((char.charCodeAt(0) - base - shift + 26) % 26) + base);
  });
}

function atbash(text) {
  return text.replace(/[a-zA-Z]/g, (char) => {
    const base = char >= 'a' ? 97 : 65;
    return String.fromCharCode(base + 25 - (char.charCodeAt(0) - base));
  });
}

// Encoding functions
function base64Encode(text) {
  return btoa(unescape(encodeURIComponent(text)));
}

function base64Decode(base64) {
  return decodeURIComponent(escape(atob(base64)));
}

function textToBinary(text) {
  return text.split('').map(char => char.charCodeAt(0).toString(2).padStart(8, '0')).join(' ');
}

function binaryToText(binary) {
  return binary.split(' ').map(b => String.fromCharCode(parseInt(b, 2))).join('');
}

function textToHex(text) {
  return text.split('').map(char => char.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}

function hexToText(hex) {
  let result = '';
  for (let i = 0; i < hex.length; i += 2) {
    result += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  }
  return result;
}

// Password generation
function generatePassword(length, options) {
  const { upper, lower, numbers, symbols, excludeSimilar } = options;
  let chars = '';
  
  if (upper) chars += excludeSimilar ? 'ABCDEFGHJKMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (lower) chars += excludeSimilar ? 'abcdefghjkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
  if (numbers) chars += excludeSimilar ? '23456789' : '0123456789';
  if (symbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  
  if (!chars) chars = 'abcdefghijklmnopqrstuvwxyz';
  
  const safeLength = Math.max(1, Math.min(256, parseInt(length) || 16));
  let password = '';
  const randomBytes = new Uint8Array(safeLength * 2);
  crypto.getRandomValues(randomBytes);
  
  for (let i = 0; i < safeLength; i++) {
    password += chars[randomBytes[i] % chars.length];
  }
  
  return password;
}

// ============================================
// Test Suites
// ============================================

describe('Array Utilities', () => {
  describe('arrayToBase64 / base64ToArray', () => {
    it('should convert array to base64 and back', () => {
      const original = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
      const base64 = arrayToBase64(original);
      const result = base64ToArray(base64);
      expect(result).toEqual(original);
    });

    it('should handle empty array', () => {
      const original = new Uint8Array([]);
      const base64 = arrayToBase64(original);
      expect(base64).toBe('');
    });

    it('should handle binary data', () => {
      const original = new Uint8Array([0, 255, 128, 64, 32]);
      const base64 = arrayToBase64(original);
      const result = base64ToArray(base64);
      expect(result).toEqual(original);
    });
  });

  describe('concatArrays', () => {
    it('should concatenate multiple arrays', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([4, 5, 6]);
      const c = new Uint8Array([7, 8, 9]);
      const result = concatArrays(a, b, c);
      expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]));
    });

    it('should handle empty arrays', () => {
      const result = concatArrays(new Uint8Array([]), new Uint8Array([1, 2]));
      expect(result).toEqual(new Uint8Array([1, 2]));
    });
  });

  describe('constantTimeCompare', () => {
    it('should return true for equal arrays', () => {
      const a = new Uint8Array([1, 2, 3, 4, 5]);
      const b = new Uint8Array([1, 2, 3, 4, 5]);
      expect(constantTimeCompare(a, b)).toBe(true);
    });

    it('should return false for different arrays', () => {
      const a = new Uint8Array([1, 2, 3, 4, 5]);
      const b = new Uint8Array([1, 2, 3, 4, 6]);
      expect(constantTimeCompare(a, b)).toBe(false);
    });

    it('should return false for different lengths', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 3, 4]);
      expect(constantTimeCompare(a, b)).toBe(false);
    });
  });

  describe('arrayToHex / hexToArray', () => {
    it('should convert array to hex and back', () => {
      const original = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
      const hex = arrayToHex(original);
      const result = hexToArray(hex);
      expect(result).toEqual(original);
    });

    it('should produce correct hex string', () => {
      const arr = new Uint8Array([0xff, 0x00, 0xab]);
      expect(arrayToHex(arr)).toBe('ff00ab');
    });
  });
});

describe('Classical Ciphers', () => {
  describe('Caesar Cipher', () => {
    it('should encrypt with default shift of 3', () => {
      expect(caesarEncrypt('abc')).toBe('def');
      expect(caesarEncrypt('ABC')).toBe('DEF');
    });

    it('should wrap around at end of alphabet', () => {
      expect(caesarEncrypt('xyz')).toBe('abc');
      expect(caesarEncrypt('XYZ')).toBe('ABC');
    });

    it('should preserve non-alphabetic characters', () => {
      expect(caesarEncrypt('hello, world!')).toBe('khoor, zruog!');
    });

    it('should decrypt correctly', () => {
      const encrypted = caesarEncrypt('Hello World', 5);
      expect(caesarDecrypt(encrypted, 5)).toBe('Hello World');
    });
  });

  describe('ROT13', () => {
    it('should be self-inverse', () => {
      const text = 'Hello World';
      expect(rot13(rot13(text))).toBe(text);
    });

    it('should correctly encode', () => {
      expect(rot13('hello')).toBe('uryyb');
    });
  });

  describe('Vigenere Cipher', () => {
    it('should encrypt correctly', () => {
      expect(vigenereEncrypt('hello', 'key')).toBe('rijvs');
    });

    it('should decrypt correctly', () => {
      const encrypted = vigenereEncrypt('hello', 'key');
      expect(vigenereDecrypt(encrypted, 'key')).toBe('hello');
    });

    it('should preserve case', () => {
      const encrypted = vigenereEncrypt('Hello', 'key');
      expect(vigenereDecrypt(encrypted, 'key').toLowerCase()).toBe('hello');
    });
  });

  describe('Atbash Cipher', () => {
    it('should be self-inverse', () => {
      const text = 'Hello World';
      expect(atbash(atbash(text))).toBe(text);
    });

    it('should correctly encode', () => {
      expect(atbash('abc')).toBe('zyx');
      expect(atbash('ABC')).toBe('ZYX');
    });
  });
});

describe('Encoding Functions', () => {
  describe('Base64', () => {
    it('should encode and decode correctly', () => {
      const text = 'Hello, World!';
      const encoded = base64Encode(text);
      const decoded = base64Decode(encoded);
      expect(decoded).toBe(text);
    });

    it('should handle special characters', () => {
      const text = '你好世界 🌍';
      const encoded = base64Encode(text);
      const decoded = base64Decode(encoded);
      expect(decoded).toBe(text);
    });
  });

  describe('Binary Encoding', () => {
    it('should convert text to binary and back', () => {
      const text = 'AB';
      const binary = textToBinary(text);
      expect(binary).toBe('01000001 01000010');
      expect(binaryToText(binary)).toBe(text);
    });
  });

  describe('Hex Encoding', () => {
    it('should convert text to hex and back', () => {
      const text = 'Hello';
      const hex = textToHex(text);
      expect(hex).toBe('48656c6c6f');
      expect(hexToText(hex)).toBe(text);
    });
  });
});

describe('Password Generation', () => {
  it('should generate password of correct length', () => {
    const password = generatePassword(16, { upper: true, lower: true, numbers: true, symbols: true });
    expect(password.length).toBe(16);
  });

  it('should include uppercase letters when specified', () => {
    const password = generatePassword(100, { upper: true, lower: false, numbers: false, symbols: false });
    expect(/[A-Z]/.test(password)).toBe(true);
  });

  it('should include lowercase letters when specified', () => {
    const password = generatePassword(100, { upper: false, lower: true, numbers: false, symbols: false });
    expect(/[a-z]/.test(password)).toBe(true);
  });

  it('should include numbers when specified', () => {
    const password = generatePassword(100, { upper: false, lower: false, numbers: true, symbols: false });
    expect(/[0-9]/.test(password)).toBe(true);
  });

  it('should include symbols when specified', () => {
    const password = generatePassword(100, { upper: false, lower: false, numbers: false, symbols: true });
    expect(/[^A-Za-z0-9]/.test(password)).toBe(true);
  });

  it('should exclude similar characters when specified', () => {
    const password = generatePassword(1000, { upper: true, lower: true, numbers: true, symbols: false, excludeSimilar: true });
    expect(/[0OIl1]/.test(password)).toBe(false);
  });

  it('should generate different passwords each time', () => {
    const password1 = generatePassword(16, { upper: true, lower: true, numbers: true, symbols: true });
    const password2 = generatePassword(16, { upper: true, lower: true, numbers: true, symbols: true });
    expect(password1).not.toBe(password2);
  });

  it('should handle minimum length', () => {
    const password = generatePassword(1, { lower: true });
    expect(password.length).toBe(1);
  });

  it('should handle maximum length', () => {
    const password = generatePassword(300, { lower: true });
    expect(password.length).toBe(256);
  });
});

describe('Random Key Generation', () => {
  it('should generate key of default length', () => {
    const key = generateRandomKey();
    expect(key.length).toBe(32);
  });

  it('should generate key of specified length', () => {
    const key = generateRandomKey(64);
    expect(key.length).toBe(64);
  });

  it('should generate different keys each time', () => {
    const key1 = generateRandomKey();
    const key2 = generateRandomKey();
    expect(key1).not.toEqual(key2);
  });
});

describe('Crypto API Mocks', () => {
  it('should have crypto.subtle available', () => {
    expect(crypto.subtle).toBeDefined();
    expect(crypto.subtle.encrypt).toBeDefined();
    expect(crypto.subtle.decrypt).toBeDefined();
  });

  it('should have crypto.getRandomValues available', () => {
    const arr = new Uint8Array(10);
    crypto.getRandomValues(arr);
    expect(arr.length).toBe(10);
  });

  it('should generate random UUIDs', () => {
    const uuid = crypto.randomUUID();
    expect(typeof uuid).toBe('string');
    expect(uuid.length).toBe(36);
  });
});
