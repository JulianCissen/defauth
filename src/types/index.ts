import type { IntrospectionResponse } from 'oauth4webapi';
import { z } from 'zod';

// Re-export error classes
export {
    DefAuthError,
    InitializationError,
    TokenValidationError,
    UserInfoError,
    IntrospectionError,
    JwtVerificationError,
} from '../errors/index.js';

/**
 * Log levels for the logger interface
 */
export type LogLevel = 'error' | 'warn' | 'info' | 'debug';

/**
 * Logger interface for custom logging implementations
 */
export interface Logger {
    /**
     * Log a message with the specified level
     * @param level - The log level
     * @param message - The log message
     * @param context - Optional context object with additional information
     */
    log(
        level: LogLevel,
        message: string,
        context?: Record<string, unknown>,
    ): void;
}

/**
 * Zod schema for user claims validation
 * Only requires the 'sub' claim, all other claims are optional
 */
export const UserClaimsSchema = z
    .object({
        // Only the subject identifier is required
        sub: z.string(),
    })
    .catchall(z.unknown()); // Allow any other claims

/**
 * User claims interface representing the standardized user information
 * Only requires the 'sub' claim, all other claims are handled dynamically
 */
export interface UserClaims {
    /** Subject identifier - unique user ID (required) */
    sub: string;
    /**
     * Additional claims from tokens or introspection
     * This allows for any standard OIDC claims (email, name, etc.)
     * as well as custom claims from identity providers
     */
    [key: string]: unknown;
}

/**
 * Metadata claims for internal storage management
 */
export interface StorageMetadata {
    /** Timestamp of last user info refresh (in milliseconds) */
    lastUserInfoRefresh?: number;
    /** Timestamp of last introspection (in milliseconds) */
    lastIntrospection?: number;
}

/**
 * Internal user record stored in the adapter
 */
export type UserRecord = UserClaims & StorageMetadata;

/**
 * Zod schema for user record validation
 */
export const UserRecordSchema = UserClaimsSchema.extend({
    lastUserInfoRefresh: z.number().optional(),
    lastIntrospection: z.number().optional(),
});

/**
 * Type for OAuth2 introspection response
 * Re-exported from oauth4webapi for convenience
 */
export type { IntrospectionResponse } from 'oauth4webapi';

/**
 * Zod schema for introspection response validation
 * Only requires the 'active' field, all other fields are optional
 */
export const IntrospectionResponseSchema = z
    .object({
        // The only required field from introspection is the 'active' status
        active: z.boolean(),
        // Subject identifier is optional in the response but required for our use
        sub: z.string().optional(),
    })
    .catchall(z.unknown()); // Allow any other fields from the introspection response

/**
 * Function type for determining when to refresh user info
 * This determines when user info should be refreshed from the OIDC provider
 */
export type UserInfoRefreshCondition<
    TUser extends StorageMetadata = StorageMetadata,
> = (user: TUser) => boolean;

/**
 * Strategy for when to fetch UserInfo during the authentication process
 */
export type UserInfoStrategy = 'afterUserRetrieval' | 'beforeUserRetrieval';

/**
 * JWT validation options
 */
export interface JwtValidationOptions {
    /** Force token introspection even for valid JWTs */
    forceIntrospection?: boolean;
    /** Clock tolerance for token expiration validation (default: '1 minute') */
    clockTolerance?: string;
    /** Required claims that must be present in the JWT (default: ['sub', 'exp']) */
    requiredClaims?: string[];
}

/**
 * Configuration options for the authenticator
 */
export interface AuthenticatorConfig<TUser extends StorageMetadata> {
    /** OIDC issuer URL */
    issuer: string;
    /** Client ID */
    clientId: string;
    /** Client secret (optional for public clients) */
    clientSecret?: string;
    /** Storage adapter (defaults to in-memory) */
    storageAdapter?: StorageAdapter<TUser>;
    /**
     * Function to determine when to refresh user info (defaults to 1 hour check)
     * This determines when the UserInfo endpoint should be called
     */
    userInfoRefreshCondition?: UserInfoRefreshCondition<TUser>;
    /**
     * Strategy for when to fetch UserInfo during authentication (defaults to 'afterUserRetrieval')
     * - 'afterUserRetrieval': Fetch UserInfo after finding user in storage (original behavior)
     * - 'beforeUserRetrieval': Fetch UserInfo before storage lookup and include in TokenContext
     */
    userInfoStrategy?: UserInfoStrategy;
    /**
     * Logger implementation for custom logging (defaults to console-based logger)
     */
    logger?: Logger;
    /**
     * Whether to throw errors when UserInfo endpoint fails (defaults to false)
     * When false, UserInfo failures are logged and the method continues with available data
     */
    throwOnUserInfoFailure?: boolean;
    /**
     * Global JWT validation options (can be overridden per getUser call)
     */
    jwtValidationOptions?: JwtValidationOptions;
}

/**
 * Context for token validation containing information from validation process
 */
export interface TokenContext {
    /** The subject identifier from the token */
    sub: string;
    /** The full validated JWT payload (present when token is JWT) */
    jwtPayload?: UserClaims;
    /** The full introspection response (present when introspection was performed) */
    introspectionResponse?: IntrospectionResponse;
    /** UserInfo result (present when UserInfo was fetched before user retrieval) */
    userInfoResult?: UserClaims;
    /** Additional metadata about the validation process */
    metadata?: {
        /** Timestamp when this validation occurred */
        validatedAt?: number;
        /** Whether introspection was forced for a JWT token */
        forcedIntrospection?: boolean;
    };
}

/**
 * Storage adapter interface for persisting user data
 */
export interface StorageAdapter<TUser extends StorageMetadata> {
    /**
     * Find a user by their token context
     * @param context - The token validation context with full token information
     * @returns Promise resolving to user record or null if not found
     */
    findUser(context: TokenContext): Promise<TUser | null>;

    /**
     * Store or update user data
     * @param user - The user record to store (null for new users)
     * @param newClaims - The new claims to merge with the user record
     * @param metadata - Storage metadata (timestamps, etc.)
     * @returns Promise resolving when storage is complete
     */
    storeUser(
        user: TUser | null,
        newClaims: UserClaims,
        metadata: StorageMetadata,
    ): Promise<TUser>;
}

/**
 * Token type enumeration
 */
export enum TokenType {
    JWT = 'jwt',
    OPAQUE = 'opaque',
}
