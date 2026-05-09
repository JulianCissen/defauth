import type { Logger } from './logger.js';
import type { StorageAdapter, StorageMetadata } from './storage.js';
import type { UserClaims } from './user.js';

/**
 * Function type for determining when to refresh user info
 * This determines when user info should be refreshed from the OIDC provider
 */
export type UserInfoRefreshCondition<TUser> = (
    user: TUser,
    metadata: StorageMetadata,
) => boolean;

/**
 * Strategy for when to fetch UserInfo during the authentication process
 */
export type UserInfoStrategy =
    | 'afterUserRetrieval'
    | 'beforeUserRetrieval'
    | 'none';

/**
 * Authentication mechanisms supported by OIDC providers
 */
export type AuthenticationMethod =
    | 'client_secret_post'
    | 'client_secret_basic'
    | 'client_secret_jwt'
    | 'none';

/**
 * Custom validator function type for adding custom authentication/authorization logic
 * @param userClaims - The user claims extracted from the token
 * @returns Promise resolving to void if validation passes
 * @throws {Error} if validation fails
 */
export type CustomValidator = (userClaims: UserClaims) => Promise<void> | void;

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
    /** Custom validator function to apply additional authentication/authorization logic */
    customValidator?: CustomValidator;
}

/**
 * Base configuration options for the authenticator
 */
interface BaseDefauthConfig<TUser> {
    /** OIDC issuer URL */
    issuer: string;
    /** Client ID */
    clientId: string;
    /**
     * Audience for JWT verification (defaults to clientId)
     * Can be a string or array of strings
     */
    audience?: string | string[];
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
     * - 'none': Never fetch UserInfo from the endpoint
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
    /**
     * Whether to allow insecure requests (HTTP instead of HTTPS)
     * Only use this for development or testing purposes
     */
    allowInsecureRequests?: boolean;
    /**
     * @deprecated Use `enableIntrospectionFallthrough` instead.
     * Ignored when `enableIntrospectionFallthrough` is defined.
     */
    disableIntrospectionFallthrough?: boolean;
    /**
     * Allow automatic introspection fallback when JWT signature verification fails.
     * When defined, takes precedence over `disableIntrospectionFallthrough`.
     * Defaults to `true` when neither setting is provided.
     */
    enableIntrospectionFallthrough?: boolean;
}

/**
 * Configuration for public clients (no client secret)
 */
interface PublicClientConfig<TUser> extends BaseDefauthConfig<TUser> {
    /** Client secret is not provided for public clients */
    clientSecret?: undefined;
    /** Authentication method must be 'none' for public clients */
    authenticationMethod?: 'none';
}

/**
 * Configuration for confidential clients (with client secret)
 */
interface ConfidentialClientConfig<TUser> extends BaseDefauthConfig<TUser> {
    /** Client secret for confidential clients */
    clientSecret: string;
    /** Authentication method (defaults to 'client_secret_post') */
    authenticationMethod?: AuthenticationMethod;
}

/**
 * Configuration options for the authenticator
 * Type is conditional based on whether clientSecret is provided
 */
export type DefauthConfig<TUser> =
    | PublicClientConfig<TUser>
    | ConfidentialClientConfig<TUser>;
