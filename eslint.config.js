// @ts-check
import tseslint from 'typescript-eslint';
import { createTypeScriptImportResolver } from 'eslint-import-resolver-typescript';
import importX from 'eslint-plugin-import-x';
import unicorn from 'eslint-plugin-unicorn';
import prettierConfig from 'eslint-plugin-prettier/recommended';
import packageJsonPlugin from 'eslint-plugin-package-json';

export default tseslint.config(
    // 1. Global ignores
    {
        ignores: ['**/dist/**', '**/node_modules/**', '**/examples/**'],
    },

    // 2. TypeScript base — type-aware recommended rules
    {
        files: ['**/*.ts'],
        extends: [...tseslint.configs.recommendedTypeChecked],
        languageOptions: {
            parserOptions: {
                project: true,
            },
        },
        rules: {
            '@typescript-eslint/consistent-type-imports': [
                'error',
                {
                    prefer: 'type-imports',
                    fixStyle: 'separate-type-imports',
                },
            ],
            '@typescript-eslint/no-unused-vars': [
                'error',
                { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
            ],
        },
    },

    // 3. import-x — import validation and ordering
    {
        files: ['**/*.ts'],
        plugins: { 'import-x': importX },
        settings: {
            'import-x/resolver-next': [createTypeScriptImportResolver()],
        },
        rules: {
            'import-x/no-duplicates': 'error',
            'import-x/no-extraneous-dependencies': 'error',
            'import-x/order': [
                'error',
                {
                    groups: [
                        'builtin',
                        'external',
                        'internal',
                        'parent',
                        'sibling',
                        'index',
                    ],
                    'newlines-between': 'never',
                    alphabetize: { order: 'asc', caseInsensitive: true },
                },
            ],
        },
    },

    // 4. Unicorn — opinionated best practices
    {
        files: ['**/*.ts'],
        plugins: { unicorn },
        rules: {
            ...unicorn.configs.recommended.rules,
            'unicorn/prevent-abbreviations': 'off',
            'unicorn/no-null': 'off',
            'unicorn/import-style': 'off',
        },
    },

    // 5. Source file overrides
    {
        files: ['src/**/*.ts'],
        ignores: ['src/**/__tests__/**'],
        rules: {
            // Async interface implementations legitimately have no await
            '@typescript-eslint/require-await': 'off',
        },
    },

    // 6. Test file overrides
    {
        files: ['**/__tests__/**/*.ts', '**/*.test.ts', '**/*.spec.ts'],
        rules: {
            '@typescript-eslint/no-explicit-any': 'off',
            '@typescript-eslint/no-unsafe-assignment': 'off',
            '@typescript-eslint/no-unsafe-call': 'off',
            '@typescript-eslint/no-unsafe-member-access': 'off',
            '@typescript-eslint/no-unsafe-return': 'off',
            '@typescript-eslint/no-unsafe-argument': 'off',
            '@typescript-eslint/no-unnecessary-type-assertion': 'off',
            '@typescript-eslint/require-await': 'off',
            'import-x/no-extraneous-dependencies': 'off',
            'unicorn/no-await-expression-member': 'off',
        },
    },

    // 6. package.json
    packageJsonPlugin.configs.recommended,
    packageJsonPlugin.configs.stylistic,

    // 7. Prettier — must be last
    prettierConfig,
);
