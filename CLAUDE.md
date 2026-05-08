# defauth — Claude Instructions

## After every change, verify these three checks pass

```bash
npm run lint        # zero errors, zero warnings
npx tsc --noEmit    # zero TypeScript errors
npm test            # all tests green
```

If any check fails, fix it before considering the task complete.

## Project overview

ESM-only TypeScript library (`"type": "module"`, NodeNext module resolution). No CommonJS build.

**Runtime deps**: `jose`, `openid-client`, `zod`
**Node requirement**: `^22.12.0`

## Build

```bash
npm run build       # tsc -p tsconfig.build.json → dist/
```

`tsconfig.json` — IDE + type-checking, includes tests, `noEmit: true`
`tsconfig.build.json` — emit only, excludes `__tests__`, outputs to `dist/`

## Testing

Vitest with global mocks in `vitest.setup.ts`. All `jose` and `openid-client` calls are mocked there — test files get typed references via `vi.mocked()`.

## Linting

ESLint with `typescript-eslint` (type-aware), `eslint-plugin-import-x`, `eslint-plugin-unicorn`, `eslint-plugin-package-json`, and Prettier.

Run `npm run lint:fix` to auto-fix formatting and import ordering before checking manually.
