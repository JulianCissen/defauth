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

## Installation

```bash
npm install defauth
```

## Quick Start

```typescript
import { Authenticator } from 'defauth';

// For confidential clients (with client secret)
const auth = new Authenticator({
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

## Configuration

### Basic Configuration

#### Confidential Client (with client secret)

```typescript
const auth = new Authenticator({
  issuer: 'https://your-oidc-provider.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret'
});
```

#### Public Client (without client secret)

```typescript
const auth = new Authenticator({
  issuer: 'https://your-oidc-provider.com',
  clientId: 'your-public-client-id'
  // No client secret needed for public clients like SPAs or mobile apps
});
```

### Advanced Configuration

```typescript
import { 
  Authenticator, 
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

const auth = new Authenticator({
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
  userInfoRefreshCondition: (user) => {
    // Refresh user info every 30 minutes instead of default 1 hour
    const thirtyMinutesAgo = Date.now() - (30 * 60 * 1000);
    return !user.lastUserInfoRefresh || user.lastUserInfoRefresh < thirtyMinutesAgo;
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
import { Authenticator, Logger, LogLevel } from 'defauth';

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

const auth = new Authenticator({
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
const strictAuth = new Authenticator({
  // ... config
  throwOnUserInfoFailure: true
});

// Resilient mode - logs warnings and continues (default)
const resilientAuth = new Authenticator({
  // ... config
  throwOnUserInfoFailure: false
});
```

## Custom Storage Adapters

Implement the `StorageAdapter` interface for your own storage solution:

```typescript
import { StorageAdapter, UserRecord } from 'defauth';

class DatabaseStorageAdapter implements StorageAdapter {
  async findUser(sub: string): Promise<UserRecord | null> {
    // Your database lookup logic
    return await db.users.findOne({ sub });
  }

  async storeUser(user: UserRecord): Promise<void> {
    // Your database storage logic
    await db.users.upsert({ sub: user.sub }, user);
  }
}

const auth = new Authenticator({
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
const customCondition: UserInfoRefreshCondition = (user) => {
  if (!user.lastUserInfoRefresh) return true;
  
  // Refresh every 15 minutes
  const fifteenMinutesAgo = Date.now() - (15 * 60 * 1000);
  return user.lastUserInfoRefresh < fifteenMinutesAgo;
};

const auth = new Authenticator({
  // ... other config
  userInfoRefreshCondition: customCondition
});
```

## API Reference

### Authenticator Class

#### Constructor
```typescript
constructor(config: AuthenticatorConfig)
```

#### Methods

##### `getUser(token: string, options?: { forceIntrospection?: boolean }): Promise<UserClaims>`
Main method to extract user information from any token type, with option to force introspection.

##### `clearCache(): Promise<void>`
Clears all cached user data (useful for testing).

### Types

#### `UserClaims`
Standard OIDC user claims interface.

#### `UserRecord`
Extended user record stored in adapters (includes `lastUserInfoRefresh` and deprecated `lastIntrospection`).

#### `AuthenticatorConfig`
Configuration object for the authenticator.

#### `StorageAdapter`
Interface for implementing custom storage solutions.

#### `UserInfoRefreshCondition`
Function type for determining when to refresh user information from UserInfo endpoint.

#### `Logger`
Interface for implementing custom logging solutions.

#### `LogLevel`
Type for log levels: 'error' | 'warn' | 'info' | 'debug'.

#### `IntrospectionCondition`
Deprecated alias for `UserInfoRefreshCondition`.

#### Zod Schemas

The library exports Zod schemas for validation:

- `UserClaimsSchema`: Validates user claims
- `UserRecordSchema`: Validates user records
- `IntrospectionResponseSchema`: Validates introspection responses

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
  Authenticator, 
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
