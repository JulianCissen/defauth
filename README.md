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
  defaultUserInfoRefreshCondition 
} from 'defauth';

const auth = new Authenticator({
  issuer: 'https://your-oidc-provider.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  
  // Optional: Custom storage adapter
  storageAdapter: new InMemoryStorageAdapter(),
  
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

#### `IntrospectionCondition`
Deprecated alias for `UserInfoRefreshCondition`.

#### Zod Schemas

The library exports Zod schemas for validation:

- `UserClaimsSchema`: Validates user claims
- `UserRecordSchema`: Validates user records
- `IntrospectionResponseSchema`: Validates introspection responses

## Error Handling

The library throws descriptive errors for various scenarios:

```typescript
try {
  const user = await auth.getUser(token);
} catch (error) {
  if (error.message.includes('Token is not active')) {
    // Handle expired/invalid token
  } else if (error.message.includes('JWT token is missing sub claim')) {
    // Handle malformed JWT
  } else {
    // Handle other errors
  }
}
```

## License

MIT
