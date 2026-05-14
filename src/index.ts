// Main export - the Defauth class
export { Defauth } from './authenticator/index.js';

// Type exports for consumers of the library
export type {
    UserClaims,
    UserRecord,
    CustomValidator,
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
    CustomValidationError,
    DefauthError,
    InitializationError,
    IntrospectionError,
    JwtVerificationError,
    StorageError,
    TokenValidationError,
    UserInfoError,
} from './errors.js';

// Storage adapter exports
export { InMemoryStorageAdapter } from './storage/index.js';

// Utility exports for advanced usage
export {
    isJwtToken,
    getTokenType,
    defaultUserInfoRefreshCondition,
    ConsoleLogger,
    DEFAULT_JWT_ALGORITHMS,
} from './utils/index.js';

export {
    TokenType,
    UserClaimsSchema,
    UserRecordSchema,
    IntrospectionResponseSchema,
} from './types/index.js';
