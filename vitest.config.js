import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom',
    globals: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['app.js'],
      exclude: [
        'argon2-bundled.min.js',
        'zxcvbn.js',
        'encrypt-worker.js',
        'decrypt-worker.js'
      ]
    },
    setupFiles: ['./tests/setup.js']
  }
});
