import type { IntrospectionResponse } from 'oauth4webapi';
import { z } from 'zod';

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
 * Internal user record stored in the adapter
 */
export interface UserRecord extends UserClaims {
    /** Timestamp of last user info refresh (in milliseconds) */
    lastUserInfoRefresh?: number;
    /** Timestamp of last introspection (in milliseconds) */
    lastIntrospection?: number;
}

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
export type UserInfoRefreshCondition = (user: UserRecord) => boolean;

/**
 * Configuration options for the authenticator
 */
export interface AuthenticatorConfig {
    /** OIDC issuer URL */
    issuer: string;
    /** Client ID */
    clientId: string;
    /** Client secret (optional for public clients) */
    clientSecret?: string;
    /** Storage adapter (defaults to in-memory) */
    storageAdapter?: StorageAdapter;
    /**
     * Function to determine when to refresh user info (defaults to 1 hour check)
     * This determines when the UserInfo endpoint should be called
     */
    userInfoRefreshCondition?: UserInfoRefreshCondition;
    /**
     * Logger implementation for custom logging (defaults to console-based logger)
     */
    logger?: Logger;
    /**
     * Whether to throw errors when UserInfo endpoint fails (defaults to false)
     * When false, UserInfo failures are logged and the method continues with available data
     */
    throwOnUserInfoFailure?: boolean;
}

/**
 * Context for token validation - discriminated union based on validation type
 */
export type TokenContext =
    | {
          /** The subject identifier from the token */
          sub: string;
          /** The type of token validation that occurred */
          type: 'jwt';
          /** The full validated JWT payload */
          jwtPayload: UserClaims;
          /** Additional metadata about the validation process */
          metadata?: {
              /** Timestamp when this validation occurred */
              validatedAt: number;
          };
      }
    | {
          /** The subject identifier from the token */
          sub: string;
          /** The type of token validation that occurred */
          type: 'introspection';
          /** The full introspection response */
          introspectionResponse: IntrospectionResponse;
          /** Additional metadata about the validation process */
          metadata?: {
              /** Whether introspection was forced for a JWT token */
              forcedIntrospection?: boolean;
              /** Timestamp when this validation occurred */
              validatedAt: number;
          };
      };

/**
 * Storage adapter interface for persisting user data
 */
export interface StorageAdapter {
    /**
     * Find a user by their token context
     * @param context - The token validation context with full token information
     * @returns Promise resolving to user record or null if not found
     */
    findUser(context: TokenContext): Promise<UserRecord | null>;

    /**
     * Store or update user data
     * @param user - The user record to store
     * @returns Promise resolving when storage is complete
     */
    storeUser(user: UserRecord): Promise<void>;
}

/**
 * Token type enumeration
 */
export enum TokenType {
    JWT = 'jwt',
    OPAQUE = 'opaque',
}
