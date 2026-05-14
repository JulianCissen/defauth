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
 * JWT validation options. All fields are optional and can be set globally via
 * `jwtValidationOptions` in the config, or overridden per-call in `getUser`.
 *
 * Defaults (applied when not set):
 * - `algorithms`: asymmetric algorithms only (RS*, PS*, ES*, EdDSA)
 * - `clockTolerance`: '1 minute'
 * - `requiredClaims`: ['sub', 'exp']
 * - `audience`: the configured `clientId`
 * - `issuer`: the configured `issuer` (OIDC discovery URL)
 */
export interface JwtValidationOptions {
    /**
     * Accepted JWS algorithms for JWT signature verification.
     * Defaults to asymmetric algorithms only (RS*, PS*, ES*, EdDSA).
     * Symmetric algorithms (HS*) are excluded by default to prevent algorithm confusion attacks.
     */
    algorithms?: string[];
    /** Clock tolerance for token expiration validation (default: '1 minute') */
    clockTolerance?: string;
    /** Required claims that must be present in the JWT (default: ['sub', 'exp']) */
    requiredClaims?: string[];
    /**
     * Expected JWT "aud" claim. Defaults to `clientId`.
     * Can be a string or array of strings.
     */
    audience?: string | string[];
    /**
     * Expected JWT "iss" claim. Defaults to `issuer` from the top-level config.
     * Override when the OIDC discovery URL and the token issuer claim differ
     * (e.g. some Keycloak deployments).
     */
    issuer?: string;
    /** Force token introspection even for valid JWTs */
    forceIntrospection?: boolean;
    /** Custom validator function to apply additional authentication/authorization logic */
    customValidator?: CustomValidator;
}

/**
 * Base configuration options for the authenticator
 */
interface BaseDefauthConfig<TUser> {
    // ── Identity / connection ────────────────────────────────────────────────
    /** OIDC issuer URL used for discovery */
    issuer: string;
    /** Client ID */
    clientId: string;

    // ── JWT behavior ─────────────────────────────────────────────────────────
    /**
     * Global JWT validation options. All fields can be overridden per `getUser` call.
     * Unset fields fall back to their defaults (see `JwtValidationOptions`).
     * Use `audience` here to override the default audience (clientId).
     * Use `issuer` here when the OIDC discovery URL differs from the token's `iss` claim.
     */
    jwtValidationOptions?: JwtValidationOptions;
    /**
     * Allow automatic introspection fallback when JWT signature verification fails.
     * When defined, takes precedence over `disableIntrospectionFallthrough`.
     * Defaults to `true` when neither setting is provided.
     */
    enableIntrospectionFallthrough?: boolean;

    // ── UserInfo ─────────────────────────────────────────────────────────────
    /**
     * Strategy for when to fetch UserInfo during authentication (defaults to 'afterUserRetrieval').
     * - 'afterUserRetrieval': Fetch UserInfo after finding user in storage
     * - 'beforeUserRetrieval': Fetch UserInfo before storage lookup and include in TokenContext
     * - 'none': Never fetch UserInfo from the endpoint
     */
    userInfoStrategy?: UserInfoStrategy;
    /**
     * Function to determine when to refresh UserInfo (defaults to 1 hour check).
     * Called with the current user record and its metadata.
     */
    userInfoRefreshCondition?: UserInfoRefreshCondition<TUser>;
    /**
     * Whether to throw errors when the UserInfo endpoint fails (defaults to false).
     * When false, UserInfo failures are logged and authentication continues with available data.
     */
    throwOnUserInfoFailure?: boolean;

    // ── Infrastructure ───────────────────────────────────────────────────────
    /** Storage adapter for user persistence (defaults to in-memory) */
    storageAdapter?: StorageAdapter<TUser>;
    /** Logger implementation (defaults to console-based logger) */
    logger?: Logger;
    /**
     * Whether to allow insecure requests (HTTP instead of HTTPS).
     * Only use this for development or testing purposes.
     */
    allowInsecureRequests?: boolean;

    // ── Deprecated ───────────────────────────────────────────────────────────
    /**
     * @deprecated Use `enableIntrospectionFallthrough` instead.
     * Ignored when `enableIntrospectionFallthrough` is defined.
     */
    disableIntrospectionFallthrough?: boolean;
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
 * Configuration options for the authenticator.
 * Type is conditional based on whether clientSecret is provided.
 */
export type DefauthConfig<TUser> =
    | PublicClientConfig<TUser>
    | ConfidentialClientConfig<TUser>;
