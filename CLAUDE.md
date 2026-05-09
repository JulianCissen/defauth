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

## Code style

### Orchestrator pattern
Public methods and complex functions should read as a sequence of steps, not contain business logic directly. The top-level method calls small, focused private helpers in order — each helper has a single responsibility. Keep orchestrators thin; keep helpers small.

```typescript
// Good
async authenticate(token: string): Promise<User> {
    const tokenType = this.classifyToken(token);
    const claims = await this.verifyClaims(token, tokenType);
    return this.buildUser(claims);
}

// Avoid — logic and orchestration mixed together
async authenticate(token: string): Promise<User> {
    const parts = token.split('.');
    if (parts.length === 3) { /* ... jwt logic ... */ }
    // ...
}
```

### Guard clauses and early returns
Handle error conditions and edge cases at the top of a function. The happy path should read linearly without nesting.

```typescript
// Good
if (!token) return null;
if (token.expired) throw new TokenExpiredError();
return this.processToken(token);

// Avoid
if (token) {
    if (!token.expired) {
        return this.processToken(token);
    }
}
```

### Naming
Method and variable names should express intent, not implementation. A reader should understand what a method does from its name without reading its body. Private helpers should be named for what they produce or check (`isTokenExpired`, `buildUserClaims`), not how they do it.

### No defensive programming inside the library
Do not validate invariants the type system already guarantees. Trust TypeScript and internal code. Only validate at public API boundaries where external, untyped input enters (user-supplied config, HTTP responses, etc.).

### Test structure
`describe`/`it` blocks should form a readable sentence: `describe('authenticate') > it('should return null when token is expired')`. Each test should cover one logical scenario. Multiple `expect` calls are fine when they all verify the same outcome.
