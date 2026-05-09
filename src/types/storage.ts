import type { IntrospectionResponse } from 'oauth4webapi';
import type { UserClaims } from './user.js';

/**
 * Metadata claims for internal storage management
 */
export interface StorageMetadata {
    /** Timestamp of last user info refresh */
    lastUserInfoRefresh?: Date;
    /** Timestamp of last introspection */
    lastIntrospection?: Date;
}

/**
 * Internal user record stored in the adapter
 */
export type UserRecord = UserClaims & StorageMetadata;

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
        validatedAt?: Date;
        /** Whether introspection was forced for a JWT token */
        forcedIntrospection?: boolean;
    };
}

/**
 * Storage adapter interface for persisting user data
 */
export interface StorageAdapter<TUser> {
    /**
     * Find a user by their token context
     * @param context - The token validation context with full token information
     * @returns Promise resolving to user record and metadata, or null if not found
     */
    findUser(context: TokenContext): Promise<{
        user: TUser;
        metadata: StorageMetadata;
    } | null>;

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
