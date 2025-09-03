# DefAuth - OIDC Authentication Library

A TypeScript library for handling OIDC authentication with support for both JWT and opaque tokens, intelligent caching, and customizable storage adapters.

## Features

- 🔐 **Dual Token Support**: Handles both JWT and opaque tokens seamlessly
- 🚀 **Intelligent Caching**: Configurable refresh conditions to minimize API calls
- 🧩 **Hybrid Approach**: Combines signature validation, introspection, and UserInfo
- 🔧 **Pluggable Storage**: Comes with in-memory adapter, easily extend with your own
- ✅ **JWT Verification**: Built-in signature verification using openid-client
- 👤 **UserInfo Integration**: Enriches tokens with data from UserInfo endpoint
- 🔒 **Validation**: Robust input validation using Zod
- 📝 **TypeScript**: Full TypeScript support with comprehensive type definitions

## Migration Guide (v2.0)

### Breaking Changes

DefAuth v2.0 introduces **two major breaking changes** that require code updates:

#### 1. **Class Rename**: `Authenticator` → `Defauth`

The main class has been renamed from `Authenticator` to `Defauth` to avoid naming conflicts with user implementations.

**Before (v1.x)**
```typescript
import { Authenticator, AuthenticatorConfig } from 'defauth';

const auth = new Authenticator(config);
// or
const auth = await Authenticator.create(config);
```

**After (v2.0+)**
```typescript
import { Defauth, DefauthConfig } from 'defauth';

const auth = await Defauth.create(config);
```

#### 2. **Constructor is Private**: Use `Defauth.create()` Only

The constructor is now private and can only be accessed through the `Defauth.create()` static method. This ensures all instances are properly initialized.

**Before (v1.x)**
```typescript
// ❌ Old way - constructor (synchronous)
const auth = new Authenticator({
  issuer: 'https://example.com',
  clientId: 'client-id',
  clientSecret: 'client-secret'
});

// Had to wait for async initialization or handle race conditions
const user = await auth.getUser(token);
```

**After (v2.0+)**
```typescript
// ✅ New way - async factory method (constructor is private)
const auth = await Defauth.create({
  issuer: 'https://example.com',
  clientId: 'client-id',
  clientSecret: 'client-secret'
});

// Ready to use immediately, no race conditions
const user = await auth.getUser(token);
```

### Quick Migration Steps

1. **Update imports**: Change `Authenticator` to `Defauth` in all import statements
2. **Update types**: Change `AuthenticatorConfig` to `DefauthConfig` if using TypeScript
3. **Replace constructor calls**: Change `new Authenticator()` or `new Defauth()` to `await Defauth.create()` (constructor is now private)
4. **Replace static calls**: Change `Authenticator.create()` to `Defauth.create()`
5. **Update variable names**: Optionally rename variables for consistency (e.g., `authenticator` → `defauth`)

### Why These Changes?

- **Class rename**: Prevents naming conflicts with user-defined authenticator classes
- **Private constructor**: Enforces proper async initialization, eliminating race conditions and ensuring OIDC client setup
- **Explicit error handling**: Clear failure modes during initialization
- **Modern API patterns**: Consistent with Promise-based initialization patterns

### Benefits of Migration

- **No naming conflicts**: Avoid conflicts with your own authenticator implementations
- **No race conditions**: Guaranteed ready state after Promise resolves  
- **Better error messages**: Clearer failure modes during initialization
- **Explicit initialization**: Clear error handling during setup
- **Modern API**: Consistent with Promise-based patterns

## Installation

```bash
npm install defauth
```

## Quick Start

```typescript
import { Defauth } from 'defauth';

// Create and initialize an authenticator (recommended approach)
const auth = await Defauth.create({
  issuer: 'https://your-oidc-provider.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret' // Optional for public clients
});

// Get user from any token type
const user = await auth.getUser(token);

// Force introspection (for high-security scenarios)
const validatedUser = await auth.getUser(token, { forceIntrospection: true });

console.log(user.sub, user.email, user.name);
```

> **Breaking Change Notice**: v2.0 introduces major breaking changes including class rename (`Authenticator` → `Defauth`) and private constructor (must use `Defauth.create()`). See the [Migration Guide](#migration-guide-v20) above for complete upgrade instructions.

## Configuration

### Basic Configuration

#### Confidential Client (with client secret)

```typescript
const auth = await Defauth.create({
  issuer: 'https://your-oidc-provider.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret'
});
```

#### Public Client (without client secret)

```typescript
const auth = await Defauth.create({
  issuer: 'https://your-oidc-provider.com',
  clientId: 'your-public-client-id'
  // No client secret needed for public clients like SPAs or mobile apps
});
```

### Initialization

The `Defauth.create()` static method is the **only recommended way** to create a Defauth instance. It returns a Promise that resolves with a fully initialized Defauth:

```typescript
try {
  const auth = await Defauth.create({
    issuer: 'https://your-oidc-provider.com',
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret'
  });
  
  // Defauth is guaranteed to be fully initialized and ready to use
  const user = await auth.getUser(token);
  console.log('User:', user);
} catch (error) {
  // Handle initialization failures explicitly
  console.error('Failed to initialize authenticator:', error.message);
}
```

**Key benefits of `Defauth.create()`:**
- ✅ Explicit error handling during initialization
- ✅ No race conditions when calling `getUser()` immediately
- ✅ Promise-based API consistent with modern JavaScript patterns
- ✅ Clear initialization lifecycle
- ✅ Built-in validation of OIDC configuration

> **⚠️ Constructor Deprecation**: The `new Defauth()` constructor is deprecated and will be removed in the next major version. It does not properly initialize the OIDC client and can lead to runtime errors. All code should migrate to using `Defauth.create()`.

### Advanced Configuration

```typescript
import { 
  Defauth, 
  InMemoryStorageAdapter,
  ConsoleLogger,
  defaultUserInfoRefreshCondition 
} from 'defauth';
import type { Logger, LogLevel } from 'defauth';

// Custom logger implementation
class CustomLogger implements Logger {
  log(level: LogLevel, message: string, context?: Record<string, unknown>): void {
    const timestamp = new Date().toISOString();
    const contextStr = context ? ` [Context: ${JSON.stringify(context)}]` : '';
    console.log(`[${timestamp}] [${level.toUpperCase()}] ${message}${contextStr}`);
  }
}

const auth = await Defauth.create({
  issuer: 'https://your-oidc-provider.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  
  // Optional: Custom storage adapter
  storageAdapter: new InMemoryStorageAdapter(),
  
  // Optional: Custom logger (defaults to ConsoleLogger)
  logger: new CustomLogger(),
  
  // Optional: Throw on UserInfo failure instead of logging warnings (defaults to false)
  throwOnUserInfoFailure: true,
  
  // Optional: Custom refresh condition
  userInfoRefreshCondition: (user, metadata) => {
    // Refresh user info every 30 minutes instead of default 1 hour
    const thirtyMinutesAgo = new Date(Date.now() - (30 * 60 * 1000));
    return !metadata.lastUserInfoRefresh || metadata.lastUserInfoRefresh <= thirtyMinutesAgo;
  }
});
```

## Token Handling

The library automatically detects token types and handles them with a hybrid approach:

### JWT Tokens
- Verifies signature using OIDC provider's keys
- Extracts user info from token claims
- Checks storage for cached user data
- Fetches additional data from UserInfo endpoint when conditions are met
- Optionally introspects when explicitly requested with `forceIntrospection: true`
- Merges claims from all sources with priority to UserInfo data

### Opaque Tokens
- Always introspects with the OIDC provider for validation
- Enhances with UserInfo endpoint data when available
- Caches results in storage adapter
- Updates both introspection and UserInfo refresh timestamps

## Custom Logging

The library supports custom logging implementations for better integration with your application's logging system:

```typescript
import { Defauth, Logger, LogLevel } from 'defauth';

// Custom logger that integrates with your logging framework
class MyAppLogger implements Logger {
  log(level: LogLevel, message: string, context?: Record<string, unknown>): void {
    // Integration with your preferred logging library (Winston, Pino, etc.)
    myAppLoggingFramework.log({
      level,
      message,
      context,
      timestamp: new Date().toISOString(),
      service: 'defauth'
    });
  }
}

const auth = new Defauth({
  // ... other config
  logger: new MyAppLogger(),
  
  // Control error handling behavior
  throwOnUserInfoFailure: false // Log warnings instead of throwing errors
});
```

### Error Handling Options

You can configure how the library handles UserInfo endpoint failures:

- **`throwOnUserInfoFailure: false`** (default): Logs warnings and continues with available data
- **`throwOnUserInfoFailure: true`**: Throws errors when UserInfo endpoint fails

```typescript
// Strict mode - throws on any UserInfo failure
const strictAuth = new Defauth({
  // ... config
  throwOnUserInfoFailure: true
});

// Resilient mode - logs warnings and continues (default)
const resilientAuth = new Defauth({
  // ... config
  throwOnUserInfoFailure: false
});
```

## Custom Storage Adapters

Implement the `StorageAdapter` interface for your own storage solution:

```typescript
import { StorageAdapter, StorageMetadata, TokenContext, UserClaims } from 'defauth';

class DatabaseStorageAdapter<TUser = UserClaims> implements StorageAdapter<TUser> {
  async findUser(context: TokenContext): Promise<{
    user: TUser;
    metadata: StorageMetadata;
  } | null> {
    // Your database lookup logic
    const result = await db.users.findOne({ sub: context.sub });
    if (!result) return null;
    
    return {
      user: result.user,
      metadata: result.metadata
    };
  }

  async storeUser(
    user: TUser | null,
    newClaims: UserClaims,
    metadata: StorageMetadata
  ): Promise<TUser> {
    // Create or update user record
    const updatedUser = user 
      ? { ...user, ...newClaims } as TUser
      : newClaims as unknown as TUser;
    
    // Your database storage logic
    await db.users.upsert(
      { sub: newClaims.sub }, 
      { user: updatedUser, metadata }
    );
    
    return updatedUser;
  }
}

const auth = new Defauth({
  // ... other config
  storageAdapter: new DatabaseStorageAdapter()
});
```

## Custom UserInfo Refresh Conditions

Control when the library should refresh user information:

```typescript
import { UserInfoRefreshCondition } from 'defauth';

// Never refresh UserInfo (rely only on token/cached data)
const neverRefresh: UserInfoRefreshCondition = () => false;

// Always refresh UserInfo
const alwaysRefresh: UserInfoRefreshCondition = () => true;

// Custom time-based condition
const customCondition: UserInfoRefreshCondition = (user, metadata) => {
  if (!metadata.lastUserInfoRefresh) return true;
  
  // Refresh every 15 minutes
  const fifteenMinutesAgo = new Date(Date.now() - (15 * 60 * 1000));
  return metadata.lastUserInfoRefresh <= fifteenMinutesAgo;
};

const auth = new Defauth({
  // ... other config
  userInfoRefreshCondition: customCondition
});
```

## API Reference

### Defauth Class

#### Static Factory Method
```typescript
static async create<TUser>(config: DefauthConfig<TUser>): Promise<Defauth<TUser>>
```
Creates and initializes a new Defauth instance. This is the only way to create instances since the constructor is private.

#### Methods

##### `getUser(token: string, options?: { forceIntrospection?: boolean }): Promise<UserClaims>`
Main method to extract user information from any token type, with option to force introspection.

##### `clearCache(): Promise<void>`
Clears all cached user data (useful for testing).

### Types

#### `UserClaims`
Standard OIDC user claims interface.

#### `StorageMetadata`
Metadata stored alongside user data in storage adapters.
- `lastUserInfoRefresh?: Date` - Timestamp of last UserInfo endpoint refresh
- `lastIntrospection?: Date` - Timestamp of last token introspection

#### `UserRecord`
**Deprecated**: Extended user record that combines user claims and metadata. Use separate `user` and `metadata` objects instead.

#### `DefauthConfig`
Configuration object for the authenticator.

#### `StorageAdapter<TUser>`
Generic interface for implementing custom storage solutions. Methods:
- `findUser(context: TokenContext): Promise<{user: TUser; metadata: StorageMetadata} | null>`
- `storeUser(user: TUser | null, newClaims: UserClaims, metadata: StorageMetadata): Promise<TUser>`

#### `TokenContext`
Context object containing token validation information passed to storage adapters.

#### `UserInfoRefreshCondition<TUser>`
Function type `(user: TUser, metadata: StorageMetadata) => boolean` for determining when to refresh user information from UserInfo endpoint.

#### `Logger`
Interface for implementing custom logging solutions.

#### `LogLevel`
Type for log levels: 'error' | 'warn' | 'info' | 'debug'.

#### `IntrospectionCondition`
Deprecated alias for `UserInfoRefreshCondition`.

#### Zod Schemas

The library exports Zod schemas for validation:

- `UserClaimsSchema`: Validates user claims (requires only `sub` field)
- `UserRecordSchema`: Validates deprecated user records (includes `Date` objects for timestamps)
- `IntrospectionResponseSchema`: Validates introspection responses from OIDC providers

## Error Handling

The library provides structured error handling with custom error classes for different scenarios:

### Error Types

DefAuth exports the following custom error classes:

- **`DefAuthError`**: Base error class for all DefAuth errors
- **`InitializationError`**: Thrown when OIDC client initialization fails
- **`TokenValidationError`**: Thrown when token validation fails
- **`JwtVerificationError`**: Thrown when JWT signature verification fails (extends TokenValidationError)
- **`UserInfoError`**: Thrown when UserInfo endpoint fails (when `throwOnUserInfoFailure: true`)
- **`IntrospectionError`**: Thrown when token introspection fails

### Usage Examples

```typescript
import { 
  Defauth, 
  InitializationError, 
  TokenValidationError, 
  JwtVerificationError,
  UserInfoError,
  IntrospectionError 
} from 'defauth';

try {
  const user = await auth.getUser(token);
} catch (error) {
  if (error instanceof InitializationError) {
    // Handle OIDC client initialization failure
    console.error('Failed to initialize OIDC client:', error.message);
  } else if (error instanceof JwtVerificationError) {
    // Handle JWT signature verification failure
    console.error('JWT signature verification failed:', error.message);
  } else if (error instanceof UserInfoError) {
    // Handle UserInfo endpoint failure
    console.error('UserInfo fetch failed:', error.message);
  } else if (error instanceof IntrospectionError) {
    // Handle introspection failure
    console.error('Token introspection failed:', error.message);
  } else if (error instanceof TokenValidationError) {
    // Handle general token validation failure
    console.error('Token validation failed:', error.message);
  } else {
    // Handle other errors
    console.error('Unexpected error:', error.message);
  }
}
```

### Error Context

All custom errors preserve the original error as the `cause` property and include it in the error message for better debugging:

```typescript
try {
  const user = await auth.getUser(token);
} catch (error) {
  console.error('Error:', error.message); // Includes cause message
  console.error('Original cause:', error.cause); // Access original error
}
```

## License

MIT
