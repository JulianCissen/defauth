const js = require('@eslint/js');
const ts = require('typescript-eslint');
const prettier = require('eslint-plugin-prettier/recommended');
const jsdoc = require('eslint-plugin-jsdoc');
const globals = require('globals');

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

module.exports = [
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
    prettier,

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
];
