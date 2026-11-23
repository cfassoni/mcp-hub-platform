import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    conditions: ['@mcphub/source', 'node', 'import', 'default'],
  },
  ssr: {
    resolve: {
      conditions: ['@mcphub/source', 'node', 'import', 'default'],
    },
  },
  test: {
    server: {
      deps: {
        inline: [/^@mcphub\//],
      },
    },
    include: [
      'packages/*/test/**/*.test.ts',
      'apps/*/test/**/*.test.ts',
      'plugins/*/test/**/*.test.ts',
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['packages/*/src/**/*.ts', 'apps/mcp-gateway/src/**/*.ts', 'plugins/*/src/**/*.ts'],
      exclude: ['**/*.d.ts', '**/test/**'],
      thresholds: {
        statements: 100,
      },
    },
  },
});
