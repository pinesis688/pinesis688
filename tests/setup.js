import { vi } from 'vitest';

// Mock Web Crypto API
const mockCrypto = {
  subtle: {
    generateKey: vi.fn().mockResolvedValue({
      type: 'secret',
      algorithm: { name: 'AES-GCM' },
      extractable: true,
      usages: ['encrypt', 'decrypt']
    }),
    deriveKey: vi.fn().mockResolvedValue({
      type: 'secret',
      algorithm: { name: 'AES-GCM' },
      extractable: false,
      usages: ['encrypt', 'decrypt']
    }),
    encrypt: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
    decrypt: vi.fn().mockResolvedValue(new TextEncoder().encode('test data')),
    importKey: vi.fn().mockResolvedValue({
      type: 'secret',
      algorithm: { name: 'AES-GCM' }
    }),
    exportKey: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
    digest: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
    sign: vi.fn().mockResolvedValue(new ArrayBuffer(64)),
    verify: vi.fn().mockResolvedValue(true)
  },
  getRandomValues: vi.fn((arr) => {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = Math.floor(Math.random() * 256);
    }
    return arr;
  }),
  randomUUID: vi.fn().mockReturnValue('xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx')
};

Object.defineProperty(global, 'crypto', {
  value: mockCrypto,
  writable: true
});

// Mock localStorage
const localStorageMock = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn()
};

Object.defineProperty(global, 'localStorage', {
  value: localStorageMock,
  writable: true
});

// Mock TextEncoder/TextDecoder
global.TextEncoder = class TextEncoder {
  encode(str) {
    const arr = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
      arr[i] = str.charCodeAt(i);
    }
    return arr;
  }
};

global.TextDecoder = class TextDecoder {
  decode(arr) {
    return String.fromCharCode.apply(null, new Uint8Array(arr));
  }
};

// Mock Blob and File
global.Blob = class Blob {
  constructor(parts) {
    this.parts = parts;
    this.size = parts.reduce((acc, p) => acc + (p.length || p.size || 0), 0);
  }
  
  arrayBuffer() {
    return Promise.resolve(new ArrayBuffer(this.size));
  }
  
  text() {
    return Promise.resolve(this.parts.join(''));
  }
};

global.File = class File extends Blob {
  constructor(parts, name, options = {}) {
    super(parts);
    this.name = name;
    this.type = options.type || '';
    this.lastModified = options.lastModified || Date.now();
  }
};

// Mock FileReader
global.FileReader = class FileReader {
  constructor() {
    this.result = null;
    this.onload = null;
    this.onerror = null;
  }
  
  readAsArrayBuffer(file) {
    setTimeout(() => {
      this.result = new ArrayBuffer(file.size || 10);
      if (this.onload) this.onload({ target: this });
    }, 0);
  }
  
  readAsText(file) {
    setTimeout(() => {
      this.result = 'test content';
      if (this.onload) this.onload({ target: this });
    }, 0);
  }
};

// Mock URL
global.URL.createObjectURL = vi.fn(() => 'blob:test-url');
global.URL.revokeObjectURL = vi.fn();

// Mock document
global.document = {
  getElementById: vi.fn().mockReturnValue({
    textContent: '',
    innerHTML: '',
    value: '',
    checked: false,
    style: {},
    classList: {
      add: vi.fn(),
      remove: vi.fn(),
      contains: vi.fn().mockReturnValue(false)
    },
    addEventListener: vi.fn(),
    removeEventListener: vi.fn()
  }),
  querySelector: vi.fn().mockReturnValue(null),
  querySelectorAll: vi.fn().mockReturnValue([]),
  createElement: vi.fn().mockReturnValue({
    appendChild: vi.fn(),
    setAttribute: vi.fn(),
    addEventListener: vi.fn()
  }),
  addEventListener: vi.fn(),
  body: {
    innerHTML: ''
  }
};

// Mock window
global.window = {
  addEventListener: vi.fn(),
  removeEventListener: vi.fn(),
  crypto: mockCrypto,
  localStorage: localStorageMock,
  location: {
    href: 'http://localhost/',
    protocol: 'http:'
  }
};

console.log('Test setup complete');
