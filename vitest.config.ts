import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        environment: 'node',
        include: ['src/**/__tests__/**/*.test.ts'],
        setupFiles: ['./vitest.setup.ts'],
        coverage: {
            provider: 'v8',
            include: ['src/**/*.ts'],
            exclude: [
                'src/**/*.d.ts',
                'src/**/index.ts',
                'src/**/__tests__/**',
            ],
        },
    },
});
