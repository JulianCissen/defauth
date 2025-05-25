// Main export - the Authenticator class
export { Authenticator } from './authenticator/index.js';

// Type exports for consumers of the library
export type {
    UserClaims,
    UserRecord,
    AuthenticatorConfig,
    StorageAdapter,
    UserInfoRefreshCondition,
} from './types/index.js';

// Storage adapter exports
export { InMemoryStorageAdapter } from './storage/index.js';

// Utility exports for advanced usage
export {
    isJwtToken,
    getTokenType,
    defaultUserInfoRefreshCondition,
} from './utils/index.js';

export {
    TokenType,
    UserClaimsSchema,
    UserRecordSchema,
    IntrospectionResponseSchema,
} from './types/index.js';
