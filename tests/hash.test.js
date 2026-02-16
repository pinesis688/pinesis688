import { describe, it, expect, vi, beforeEach } from 'vitest';

// ============================================
// Hash Functions Tests
// ============================================

// SHA-256 implementation for testing
async function sha256(data) {
  const encoder = new TextEncoder();
  const dataBuffer = typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  return new Uint8Array(hashBuffer);
}

// SHA-512 implementation for testing
async function sha512(data) {
  const encoder = new TextEncoder();
  const dataBuffer = typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data);
  const hashBuffer = await crypto.subtle.digest('SHA-512', dataBuffer);
  return new Uint8Array(hashBuffer);
}

// Simple MD5 implementation for testing (not for production)
function md5(string) {
  function md5cycle(x, k) {
    var a = x[0], b = x[1], c = x[2], d = x[3];
    a = ff(a, b, c, d, k[0], 7, -680876936);
    d = ff(d, a, b, c, k[1], 12, -389564586);
    c = ff(c, d, a, b, k[2], 17, 606105819);
    b = ff(b, c, d, a, k[3], 22, -1044525330);
    a = ff(a, b, c, d, k[4], 7, -176418897);
    d = ff(d, a, b, c, k[5], 12, 1200080426);
    c = ff(c, d, a, b, k[6], 17, -1473231341);
    b = ff(b, c, d, a, k[7], 22, -45705983);
    a = ff(a, b, c, d, k[8], 7, 1770035416);
    d = ff(d, a, b, c, k[9], 12, -1958414417);
    c = ff(c, d, a, b, k[10], 17, -42063);
    b = ff(b, c, d, a, k[11], 22, -1990404162);
    a = ff(a, b, c, d, k[12], 7, 1804603682);
    d = ff(d, a, b, c, k[13], 12, -40341101);
    c = ff(c, d, a, b, k[14], 17, -1502002290);
    b = ff(b, c, d, a, k[15], 22, 1236535329);
    a = gg(a, b, c, d, k[1], 5, -165796510);
    d = gg(d, a, b, c, k[6], 9, -1069501632);
    c = gg(c, d, a, b, k[11], 14, 643717713);
    b = gg(b, c, d, a, k[0], 20, -373897302);
    a = gg(a, b, c, d, k[5], 5, -701558691);
    d = gg(d, a, b, c, k[10], 9, 38016083);
    c = gg(c, d, a, b, k[15], 14, -660478335);
    b = gg(b, c, d, a, k[4], 20, -405537848);
    a = gg(a, b, c, d, k[9], 5, 568446438);
    d = gg(d, a, b, c, k[14], 9, -1019803690);
    c = gg(c, d, a, b, k[3], 14, -187363961);
    b = gg(b, c, d, a, k[8], 20, 1163531501);
    a = gg(a, b, c, d, k[13], 5, -1444681467);
    d = gg(d, a, b, c, k[2], 9, -51403784);
    c = gg(c, d, a, b, k[7], 14, 1735328473);
    b = gg(b, c, d, a, k[12], 20, -1926607734);
    a = hh(a, b, c, d, k[5], 4, -378558);
    d = hh(d, a, b, c, k[8], 11, -2022574463);
    c = hh(c, d, a, b, k[11], 16, 1839030562);
    b = hh(b, c, d, a, k[14], 23, -35309556);
    a = hh(a, b, c, d, k[1], 4, -1530992060);
    d = hh(d, a, b, c, k[4], 11, 1272893353);
    c = hh(c, d, a, b, k[7], 16, -155497632);
    b = hh(b, c, d, a, k[10], 23, -1094730640);
    a = hh(a, b, c, d, k[13], 4, 681279174);
    d = hh(d, a, b, c, k[0], 11, -358537222);
    c = hh(c, d, a, b, k[3], 16, -722521979);
    b = hh(b, c, d, a, k[6], 23, 76029189);
    a = hh(a, b, c, d, k[9], 4, -640364487);
    d = hh(d, a, b, c, k[12], 11, -421815835);
    c = hh(c, d, a, b, k[15], 16, 530742520);
    b = hh(b, c, d, a, k[2], 23, -995338651);
    a = ii(a, b, c, d, k[0], 6, -198630844);
    d = ii(d, a, b, c, k[7], 10, 1126891415);
    c = ii(c, d, a, b, k[14], 15, -1416354905);
    b = ii(b, c, d, a, k[5], 21, -57434055);
    a = ii(a, b, c, d, k[12], 6, 1700485571);
    d = ii(d, a, b, c, k[3], 10, -1894986606);
    c = ii(c, d, a, b, k[10], 15, -1051523);
    b = ii(b, c, d, a, k[1], 21, -2054922799);
    a = ii(a, b, c, d, k[8], 6, 1873313359);
    d = ii(d, a, b, c, k[15], 10, -30611744);
    c = ii(c, d, a, b, k[6], 15, -1560198380);
    b = ii(b, c, d, a, k[13], 21, 1309151649);
    a = ii(a, b, c, d, k[4], 6, -145523070);
    d = ii(d, a, b, c, k[11], 10, -1120210379);
    c = ii(c, d, a, b, k[2], 15, 718787259);
    b = ii(b, c, d, a, k[9], 21, -343485551);
    x[0] = add32(a, x[0]);
    x[1] = add32(b, x[1]);
    x[2] = add32(c, x[2]);
    x[3] = add32(d, x[3]);
  }

  function cmn(q, a, b, x, s, t) {
    a = add32(add32(a, q), add32(x, t));
    return add32((a << s) | (a >>> (32 - s)), b);
  }

  function ff(a, b, c, d, x, s, t) {
    return cmn((b & c) | ((~b) & d), a, b, x, s, t);
  }

  function gg(a, b, c, d, x, s, t) {
    return cmn((b & d) | (c & (~d)), a, b, x, s, t);
  }

  function hh(a, b, c, d, x, s, t) {
    return cmn(b ^ c ^ d, a, b, x, s, t);
  }

  function ii(a, b, c, d, x, s, t) {
    return cmn(c ^ (b | (~d)), a, b, x, s, t);
  }

  function md51(s) {
    var n = s.length,
      state = [1732584193, -271733879, -1732584194, 271733878], i;
    for (i = 64; i <= s.length; i += 64) {
      md5cycle(state, md5blk(s.substring(i - 64, i)));
    }
    s = s.substring(i - 64);
    var tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for (i = 0; i < s.length; i++)
      tail[i >> 2] |= s.charCodeAt(i) << ((i % 4) << 3);
    tail[i >> 2] |= 0x80 << ((i % 4) << 3);
    if (i > 55) {
      md5cycle(state, tail);
      for (i = 0; i < 16; i++) tail[i] = 0;
    }
    tail[14] = n * 8;
    md5cycle(state, tail);
    return state;
  }

  function md5blk(s) {
    var md5blks = [], i;
    for (i = 0; i < 64; i += 4) {
      md5blks[i >> 2] = s.charCodeAt(i) +
        (s.charCodeAt(i + 1) << 8) +
        (s.charCodeAt(i + 2) << 16) +
        (s.charCodeAt(i + 3) << 24);
    }
    return md5blks;
  }

  var hex_chr = '0123456789abcdef'.split('');

  function rhex(n) {
    var s = '', j = 0;
    for (; j < 4; j++)
      s += hex_chr[(n >> (j * 8 + 4)) & 0x0F] + hex_chr[(n >> (j * 8)) & 0x0F];
    return s;
  }

  function hex(x) {
    for (var i = 0; i < x.length; i++)
      x[i] = rhex(x[i]);
    return x.join('');
  }

  function add32(a, b) {
    return (a + b) & 0xFFFFFFFF;
  }

  return hex(md51(string));
}

// Format size utility
function formatSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// PKCS7 padding
function pkcs7Pad(data, blockSize) {
  const padLen = blockSize - (data.length % blockSize);
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data);
  padded.fill(padLen, data.length);
  return padded;
}

function pkcs7Unpad(data) {
  const padLen = data[data.length - 1];
  if (padLen === 0 || padLen > data.length) {
    throw new Error('Invalid PKCS7 padding');
  }
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) {
      throw new Error('Invalid PKCS7 padding');
    }
  }
  return data.slice(0, data.length - padLen);
}

// PEM formatting
function formatPEM(base64, label) {
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

function parsePEM(pem) {
  const lines = pem.split('\n');
  const base64Lines = [];
  let inBlock = false;
  let label = '';
  
  for (const line of lines) {
    if (line.includes('-----BEGIN ')) {
      inBlock = true;
      label = line.replace('-----BEGIN ', '').replace('-----', '').trim();
      continue;
    }
    if (line.includes('-----END ')) {
      inBlock = false;
      continue;
    }
    if (inBlock) {
      base64Lines.push(line.trim());
    }
  }
  
  return { label, data: base64Lines.join('') };
}

// ============================================
// Test Suites
// ============================================

describe('Hash Functions', () => {
  describe('SHA-256', () => {
    it('should produce consistent hash for same input', async () => {
      const hash1 = await sha256('test');
      const hash2 = await sha256('test');
      expect(hash1).toEqual(hash2);
    });

    it('should produce different hashes for different inputs', async () => {
      const hash1 = await sha256('test1');
      const hash2 = await sha256('test2');
      expect(hash1).not.toEqual(hash2);
    });

    it('should produce 32-byte hash', async () => {
      const hash = await sha256('test');
      expect(hash.length).toBe(32);
    });

    it('should handle empty string', async () => {
      const hash = await sha256('');
      expect(hash.length).toBe(32);
    });

    it('should handle binary data', async () => {
      const data = new Uint8Array([0, 1, 2, 3, 4, 5]);
      const hash = await sha256(data);
      expect(hash.length).toBe(32);
    });
  });

  describe('SHA-512', () => {
    it('should produce 64-byte hash', async () => {
      const hash = await sha512('test');
      expect(hash.length).toBe(64);
    });

    it('should be deterministic', async () => {
      const hash1 = await sha512('test');
      const hash2 = await sha512('test');
      expect(hash1).toEqual(hash2);
    });
  });

  describe('MD5', () => {
    it('should produce correct hash for known input', () => {
      expect(md5('')).toBe('d41d8cd98f00b204e9800998ecf8427e');
    });

    it('should produce correct hash for "hello"', () => {
      expect(md5('hello')).toBe('5d41402abc4b2a76b9719d911017c592');
    });

    it('should produce 32-character hex string', () => {
      const hash = md5('test');
      expect(hash.length).toBe(32);
      expect(/^[a-f0-9]+$/.test(hash)).toBe(true);
    });
  });
});

describe('Utility Functions', () => {
  describe('formatSize', () => {
    it('should format bytes correctly', () => {
      expect(formatSize(0)).toBe('0 B');
      expect(formatSize(500)).toBe('500 B');
      expect(formatSize(1024)).toBe('1 KB');
      expect(formatSize(1536)).toBe('1.5 KB');
      expect(formatSize(1048576)).toBe('1 MB');
      expect(formatSize(1073741824)).toBe('1 GB');
    });

    it('should handle large numbers', () => {
      expect(formatSize(1099511627776)).toBe('1 TB');
    });
  });

  describe('PKCS7 Padding', () => {
    it('should pad data to block size', () => {
      const data = new Uint8Array([1, 2, 3]);
      const padded = pkcs7Pad(data, 16);
      expect(padded.length).toBe(16);
      expect(padded[3]).toBe(13); // padding byte
    });

    it('should add full block when data is aligned', () => {
      const data = new Uint8Array(16);
      const padded = pkcs7Pad(data, 16);
      expect(padded.length).toBe(32);
      expect(padded[16]).toBe(16); // padding byte
    });

    it('should unpad correctly', () => {
      const original = new Uint8Array([1, 2, 3, 4, 5]);
      const padded = pkcs7Pad(original, 16);
      const unpadded = pkcs7Unpad(padded);
      expect(unpadded).toEqual(original);
    });

    it('should throw on invalid padding', () => {
      const invalid = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0]);
      expect(() => pkcs7Unpad(invalid)).toThrow();
    });
  });

  describe('PEM Formatting', () => {
    it('should format base64 as PEM', () => {
      const base64 = 'SGVsbG8gV29ybGQ=';
      const pem = formatPEM(base64, 'PRIVATE KEY');
      expect(pem).toContain('-----BEGIN PRIVATE KEY-----');
      expect(pem).toContain('-----END PRIVATE KEY-----');
      expect(pem).toContain(base64);
    });

    it('should parse PEM correctly', () => {
      const base64 = 'SGVsbG8gV29ybGQ=';
      const pem = formatPEM(base64, 'CERTIFICATE');
      const parsed = parsePEM(pem);
      expect(parsed.label).toBe('CERTIFICATE');
      expect(parsed.data).toBe(base64);
    });

    it('should handle multi-line PEM', () => {
      const longBase64 = 'A'.repeat(200);
      const pem = formatPEM(longBase64, 'PUBLIC KEY');
      const parsed = parsePEM(pem);
      expect(parsed.data).toBe(longBase64);
    });
  });
});

describe('Input Validation', () => {
  function isValidPassword(password) {
    if (!password || typeof password !== 'string') return false;
    if (password.length < 8) return false;
    return true;
  }

  function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  function sanitizeFilename(filename) {
    return filename.replace(/[<>:"/\\|?*\x00-\x1f]/g, '_');
  }

  describe('Password Validation', () => {
    it('should reject empty password', () => {
      expect(isValidPassword('')).toBe(false);
    });

    it('should reject short password', () => {
      expect(isValidPassword('short')).toBe(false);
    });

    it('should accept valid password', () => {
      expect(isValidPassword('validpassword')).toBe(true);
    });

    it('should reject null/undefined', () => {
      expect(isValidPassword(null)).toBe(false);
      expect(isValidPassword(undefined)).toBe(false);
    });
  });

  describe('Email Validation', () => {
    it('should accept valid email', () => {
      expect(isValidEmail('test@example.com')).toBe(true);
    });

    it('should reject invalid email', () => {
      expect(isValidEmail('invalid')).toBe(false);
      expect(isValidEmail('invalid@')).toBe(false);
      expect(isValidEmail('@example.com')).toBe(false);
    });
  });

  describe('Filename Sanitization', () => {
    it('should remove dangerous characters', () => {
      expect(sanitizeFilename('file<name>.txt')).toBe('file_name_.txt');
      expect(sanitizeFilename('file|name?.txt')).toBe('file_name_.txt');
    });

    it('should preserve valid filename', () => {
      expect(sanitizeFilename('valid_file-name.txt')).toBe('valid_file-name.txt');
    });
  });
});

describe('Error Handling', () => {
  function safeDivide(a, b) {
    if (b === 0) {
      throw new Error('Division by zero');
    }
    return a / b;
  }

  function parseJSONSafe(str) {
    try {
      return JSON.parse(str);
    } catch (e) {
      return null;
    }
  }

  describe('Safe Operations', () => {
    it('should throw on division by zero', () => {
      expect(() => safeDivide(10, 0)).toThrow('Division by zero');
    });

    it('should return result for valid division', () => {
      expect(safeDivide(10, 2)).toBe(5);
    });

    it('should return null for invalid JSON', () => {
      expect(parseJSONSafe('invalid')).toBeNull();
    });

    it('should parse valid JSON', () => {
      expect(parseJSONSafe('{"key":"value"}')).toEqual({ key: 'value' });
    });
  });
});

describe('Random Generation', () => {
  it('should generate random bytes', () => {
    const bytes1 = new Uint8Array(32);
    const bytes2 = new Uint8Array(32);
    crypto.getRandomValues(bytes1);
    crypto.getRandomValues(bytes2);
    expect(bytes1).not.toEqual(bytes2);
  });

  it('should generate correct length', () => {
    const bytes = new Uint8Array(64);
    crypto.getRandomValues(bytes);
    expect(bytes.length).toBe(64);
  });

  it('should generate UUID', () => {
    const uuid = crypto.randomUUID();
    expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });
});

describe('Mathematical Functions', () => {
  function gcd(a, b) {
    return b === 0 ? a : gcd(b, a % b);
  }

  function modInverse(a, m) {
    for (let x = 1; x < m; x++) {
      if ((a * x) % m === 1) return x;
    }
    return null;
  }

  function isPrime(n) {
    if (n < 2) return false;
    if (n === 2) return true;
    if (n % 2 === 0) return false;
    for (let i = 3; i <= Math.sqrt(n); i += 2) {
      if (n % i === 0) return false;
    }
    return true;
  }

  describe('GCD', () => {
    it('should calculate GCD correctly', () => {
      expect(gcd(48, 18)).toBe(6);
      expect(gcd(17, 13)).toBe(1);
      expect(gcd(100, 25)).toBe(25);
    });
  });

  describe('Modular Inverse', () => {
    it('should find modular inverse', () => {
      expect(modInverse(3, 7)).toBe(5);
      expect((3 * 5) % 7).toBe(1);
    });

    it('should return null if no inverse exists', () => {
      expect(modInverse(2, 4)).toBeNull();
    });
  });

  describe('Prime Check', () => {
    it('should identify primes', () => {
      expect(isPrime(2)).toBe(true);
      expect(isPrime(17)).toBe(true);
      expect(isPrime(97)).toBe(true);
    });

    it('should identify non-primes', () => {
      expect(isPrime(1)).toBe(false);
      expect(isPrime(4)).toBe(false);
      expect(isPrime(100)).toBe(false);
    });
  });
});

describe('Buffer Operations', () => {
  it('should create ArrayBuffer from Uint8Array', () => {
    const arr = new Uint8Array([1, 2, 3, 4]);
    const buffer = arr.buffer;
    expect(buffer instanceof ArrayBuffer).toBe(true);
    expect(buffer.byteLength).toBe(4);
  });

  it('should create DataView', () => {
    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);
    view.setInt32(0, 123456);
    expect(view.getInt32(0)).toBe(123456);
  });

  it('should slice array correctly', () => {
    const arr = new Uint8Array([1, 2, 3, 4, 5]);
    const slice = arr.slice(1, 4);
    expect(slice).toEqual(new Uint8Array([2, 3, 4]));
  });
});
