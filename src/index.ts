// Main export - the Defauth class
export { Defauth } from './authenticator/index.js';

// Type exports for consumers of the library
export type {
    UserClaims,
    UserRecord,
    DefauthConfig,
    StorageAdapter,
    StorageMetadata,
    TokenContext,
    UserInfoRefreshCondition,
    UserInfoStrategy,
    Logger,
    LogLevel,
} from './types/index.js';

// Error exports
export {
    DefAuthError,
    InitializationError,
    TokenValidationError,
    UserInfoError,
    IntrospectionError,
    JwtVerificationError,
} from './types/index.js';

// Storage adapter exports
export { InMemoryStorageAdapter } from './storage/index.js';

// Utility exports for advanced usage
export {
    isJwtToken,
    getTokenType,
    defaultUserInfoRefreshCondition,
    ConsoleLogger,
} from './utils/index.js';

export {
    TokenType,
    UserClaimsSchema,
    UserRecordSchema,
    IntrospectionResponseSchema,
} from './types/index.js';
