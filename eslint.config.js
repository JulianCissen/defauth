import eslintPluginPrettier from 'eslint-plugin-prettier/recommended';
import globals from 'globals';
import jsdoc from 'eslint-plugin-jsdoc';
import js from '@eslint/js';
import ts from 'typescript-eslint';

// Common rule sets that can be reused across configurations
const commonJsRules = {
    'sort-imports': 'error',
};

const commonTsRules = {
    '@typescript-eslint/consistent-type-imports': [
        'error',
        {
            prefer: 'type-imports',
            fixStyle: 'separate-type-imports',
        },
    ],
    '@typescript-eslint/no-unused-vars': [
        'off',
        {
            args: 'all',
            argsIgnorePattern: '^_',
            caughtErrors: 'all',
            caughtErrorsIgnorePattern: '^_',
            destructuredArrayIgnorePattern: '^_',
            varsIgnorePattern: '^_',
            ignoreRestSiblings: true,
        },
    ],
};

// Limit TypeScript configs to TypeScript files only
const tsConfigs = ts.configs.recommended.map((config) =>
    !config.files ? { ...config, files: ['**/*.ts'] } : config,
);

const config = [
    // Files to exclude from linting
    {
        ignores: ['**/dist/**', '**/node_modules/**'],
    },

    // Common globals for all files
    {
        languageOptions: {
            ecmaVersion: 2021,
            globals: {
                ...globals.commonjs,
            },
        },
    },

    // Base configurations
    js.configs.recommended,
    ...tsConfigs,
    jsdoc.configs['flat/recommended'],
    jsdoc.configs['flat/recommended-typescript'],
    eslintPluginPrettier,

    // JavaScript-specific configuration
    {
        files: ['**/*.js'],
        rules: {
            ...commonJsRules,
        },
    },

    // TypeScript-specific configuration
    {
        files: ['**/*.ts'],
        plugins: {
            '@typescript-eslint': ts.plugin,
        },
        languageOptions: {
            parser: ts.parser,
            parserOptions: {
                project: true,
            },
        },
        rules: {
            ...commonJsRules,
            ...commonTsRules,
        },
    },

    // Test files configuration - allow explicit any types
    {
        files: ['**/__tests__/**/*.ts', '**/*.test.ts', '**/*.spec.ts'],
        rules: {
            '@typescript-eslint/no-explicit-any': 'off',
        },
    },
];

export default config;
