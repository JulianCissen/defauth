import * as jose from 'jose';
import * as openid from 'openid-client';
import type {
    AuthenticatorConfig,
    JwtValidationOptions,
    Logger,
    StorageAdapter,
    StorageMetadata,
    TokenContext,
    UserClaims,
    UserInfoRefreshCondition,
    UserInfoStrategy,
} from '../types/index.js';
import {
    ConsoleLogger,
    defaultUserInfoRefreshCondition,
    getTokenType,
} from '../utils/index.js';
import {
    DefAuthError,
    InitializationError,
    IntrospectionError,
    JwtVerificationError,
    TokenType,
    TokenValidationError,
    UserClaimsSchema,
    UserInfoError,
} from '../types/index.js';
import { InMemoryStorageAdapter } from '../storage/index.js';
import type { IntrospectionResponse } from 'oauth4webapi';

/**
 * Main authenticator class that handles OIDC authentication and user management
 */
export class Authenticator<TUser> {
    private clientConfig?: openid.Configuration;
    private clientId: string;
    private storageAdapter: StorageAdapter<TUser>;
    private userInfoRefreshCondition: UserInfoRefreshCondition<TUser>;
    private userInfoStrategy: UserInfoStrategy;
    private logger: Logger;
    private throwOnUserInfoFailure: boolean;
    private globalJwtValidationOptions: JwtValidationOptions;
    private initializationConfig?: AuthenticatorConfig<TUser>;

    private static readonly JWT_METADATA_CLAIMS = [
        'client_id',
        'scope',
        'token_type',
        'nbf',
        'jti',
    ] as const;

    private static readonly INTROSPECTION_METADATA_CLAIMS = [
        'active',
        'client_id',
        'scope',
        'token_type',
        'nbf',
        'jti',
    ] as const;

    /**
     * Creates and initializes an Authenticator instance asynchronously
     * @param config - Configuration options for the authenticator
     * @returns Promise resolving to a fully initialized Authenticator instance
     * @throws InitializationError if OIDC client initialization fails
     */
    static async create<TUser>(
        config: AuthenticatorConfig<TUser>,
    ): Promise<Authenticator<TUser>> {
        const authenticator = new Authenticator(config);
        await authenticator.initializeClient(config);
        return authenticator;
    }

    /**
     * Creates an instance of the Authenticator
     * @param config - Configuration options for the authenticator
     * @deprecated Use Authenticator.create() instead. The constructor does not initialize the OIDC client
     * and will require manual initialization. This constructor will be removed in a future version.
     * @internal This constructor is primarily for internal use by the static create method.
     */
    constructor(config: AuthenticatorConfig<TUser>) {
        // WARNING: Constructor is deprecated - use Authenticator.create() instead
        this.clientId = config.clientId;
        this.initializationConfig = config;
        this.storageAdapter =
            config.storageAdapter || new InMemoryStorageAdapter<TUser>();
        this.userInfoRefreshCondition =
            config.userInfoRefreshCondition || defaultUserInfoRefreshCondition;
        this.userInfoStrategy = config.userInfoStrategy || 'afterUserRetrieval';
        this.logger = config.logger || new ConsoleLogger();
        this.throwOnUserInfoFailure = config.throwOnUserInfoFailure || false;
        this.globalJwtValidationOptions = config.jwtValidationOptions || {
            requiredClaims: ['sub', 'exp'],
            clockTolerance: '1 minute',
        };
    }

    /**
     * Main method to get user details from a token
     * @param token - The token (JWT or opaque)
     * @param options - Optional settings for token processing
     * @param options.forceIntrospection - Force token introspection even for valid JWTs
     * @param options.clockTolerance - Clock tolerance for JWT expiration validation
     * @param options.requiredClaims - Required claims that must be present in the JWT
     * @returns Promise resolving to user claims
     * @throws Error if token is invalid or user cannot be retrieved
     */
    async getUser(
        token: string,
        options?: JwtValidationOptions,
    ): Promise<TUser> {
        this.validateToken(token);
        await this.ensureInitialized();

        const tokenType = getTokenType(token);

        if (tokenType === TokenType.OPAQUE) {
            return this.handleOpaqueToken(token);
        }

        return this.handleJwtToken(token, options);
    }

    /**
     * Clear all cached user data (useful for testing)
     */
    async clearCache(): Promise<void> {
        if (this.storageAdapter instanceof InMemoryStorageAdapter) {
            this.storageAdapter.clear();
        }
    }

    /**
     * Initialize the OIDC client
     * @param config - Configuration options
     */
    private async initializeClient(
        config: AuthenticatorConfig<TUser>,
    ): Promise<void> {
        try {
            this.clientConfig = await openid.discovery(
                new URL(config.issuer),
                config.clientId,
                config.clientSecret,
            );
        } catch (error) {
            throw new InitializationError(
                'Failed to discover OIDC issuer or create client',
                error as Error,
            );
        }
    }

    /**
     * Validate token input
     * @param token - The token to validate
     * @throws Error if token is invalid
     */
    private validateToken(token: string): void {
        if (!token) {
            throw new Error('Token is required');
        }
    }

    /**
     * Ensure client is initialized, initialize lazily if needed
     * @throws Error if client initialization fails
     */
    private async ensureInitialized(): Promise<void> {
        if (!this.clientConfig && this.initializationConfig) {
            await this.initializeClient(this.initializationConfig);
        }
        
        if (!this.clientConfig) {
            throw new Error('OIDC client is not initialized. Use Authenticator.create() for proper initialization.');
        }
    }

    /**
     * Handle opaque token by introspecting
     * @param token - The opaque token
     * @returns Promise resolving to user claims
     */
    private async handleOpaqueToken(token: string): Promise<TUser> {
        const introspectionResult = await this.introspectToken(token);
        this.validateIntrospectionResult(introspectionResult);

        let userClaims =
            this.introspectionResponseToUserClaims(introspectionResult);

        const tokenContext: TokenContext = {
            sub: userClaims.sub,
            introspectionResponse: introspectionResult,
            metadata: {
                validatedAt: new Date(),
            },
        };

        // Handle beforeUserRetrieval strategy
        if (this.userInfoStrategy === 'beforeUserRetrieval') {
            try {
                const userInfoClaims = await this.fetchUserInfo(
                    token,
                    userClaims.sub,
                );
                tokenContext.userInfoResult = userInfoClaims;
                // Combine claims with UserInfo taking priority
                userClaims = this.combineClaimsWithPriority(
                    userClaims,
                    userInfoClaims,
                );
            } catch (error) {
                this.handleUserInfoFailure(error as Error, {
                    tokenType: 'opaque',
                    subject: userClaims.sub,
                    strategy: 'beforeUserRetrieval',
                });
            }
        }

        const userRecord = await this.storageAdapter.findUser(tokenContext);
        // Set intropection metadata
        const metadata = userRecord?.metadata ?? {};
        metadata.lastIntrospection = new Date();

        return await this.processUserClaims(token, userClaims, {
            tokenType: 'opaque',
            userRecord: userRecord?.user || null,
            userMetadata: metadata,
            userInfoAlreadyFetched:
                this.userInfoStrategy === 'beforeUserRetrieval' &&
                !!tokenContext.userInfoResult,
        });
    }

    /**
     * Handle JWT token with signature verification and conditional introspection
     * @param token - The JWT token
     * @param options - JWT validation options
     * @returns Promise resolving to user claims
     */
    private async handleJwtToken(
        token: string,
        options?: JwtValidationOptions,
    ): Promise<TUser> {
        try {
            const validationResult = await this.getValidatedJwtPayload(
                token,
                options,
            );
            let userClaims = this.createUserClaimsFromPayload(
                validationResult.payload,
            );

            const tokenContext = this.createTokenContext(validationResult);

            // Handle beforeUserRetrieval strategy
            if (this.userInfoStrategy === 'beforeUserRetrieval') {
                try {
                    const userInfoClaims = await this.fetchUserInfo(
                        token,
                        userClaims.sub,
                    );
                    tokenContext.userInfoResult = userInfoClaims;
                    // Combine claims with UserInfo taking priority
                    userClaims = this.combineClaimsWithPriority(
                        userClaims,
                        userInfoClaims,
                    );
                } catch (error) {
                    this.handleUserInfoFailure(error as Error, {
                        tokenType: 'jwt',
                        subject: userClaims.sub,
                        strategy: 'beforeUserRetrieval',
                        forceIntrospection: options?.forceIntrospection,
                    });
                }
            }

            const userRecord = await this.storageAdapter.findUser(tokenContext);
            // Set intropection metadata if introspection was used
            const metadata = userRecord?.metadata ?? {};
            if (validationResult.type === 'introspection') {
                metadata.lastIntrospection = new Date();
            }

            return await this.processUserClaims(token, userClaims, {
                tokenType: 'jwt',
                userRecord: userRecord?.user || null,
                userMetadata: metadata,
                forceIntrospection: options?.forceIntrospection,
                userInfoAlreadyFetched:
                    this.userInfoStrategy === 'beforeUserRetrieval' &&
                    !!tokenContext.userInfoResult,
            });
        } catch (error) {
            // If it's already a DefAuth error, re-throw it to preserve the specific error type
            if (error instanceof DefAuthError) {
                throw error;
            }
            throw new TokenValidationError(
                'Failed to process JWT token',
                error as Error,
            );
        }
    }

    /**
     * Get validated JWT payload, either through signature verification or introspection
     * @param token - The JWT token
     * @param options - JWT validation options
     * @returns Promise resolving to validation result with payload and optional introspection response
     */
    private async getValidatedJwtPayload(
        token: string,
        options?: JwtValidationOptions,
    ): Promise<
        | { type: 'jwt'; payload: UserClaims }
        | {
              type: 'introspection';
              payload: UserClaims;
              introspectionResponse: IntrospectionResponse;
          }
    > {
        const mergedOptions = this.mergeJwtValidationOptions(options);

        if (!mergedOptions.forceIntrospection) {
            try {
                const { payload: verifiedPayload } =
                    await this.verifyJwtSignature(token, mergedOptions);
                const payload = UserClaimsSchema.parse(verifiedPayload);
                return { type: 'jwt', payload };
            } catch (error) {
                this.logger.log(
                    'warn',
                    'JWT verification failed, falling back to introspection',
                    {
                        error: (error as Error).message,
                    },
                );
                // Fall through to introspection
            }
        }

        const introspectionResult = await this.introspectToken(token);
        this.validateIntrospectionResult(introspectionResult);
        const payload =
            this.introspectionResponseToUserClaims(introspectionResult);

        return {
            type: 'introspection',
            payload,
            introspectionResponse: introspectionResult,
        };
    }

    /**
     * Verify the signature of a JWT token
     * @param token - The JWT token to verify
     * @param options - JWT validation options
     * @returns Promise resolving to the verified JWT payload
     * @throws Error if the token signature is invalid
     */
    private async verifyJwtSignature(
        token: string,
        options?: JwtValidationOptions,
    ): Promise<jose.JWTVerifyResult> {
        if (!this.clientConfig) {
            throw new Error('OIDC client configuration is not initialized');
        }

        try {
            const metadata = this.clientConfig.serverMetadata();
            const jwksUri = metadata['jwks_uri'] as string;

            if (!jwksUri) {
                throw new Error('No JWKS URI found in server metadata');
            }

            const jwks = jose.createRemoteJWKSet(new URL(jwksUri));

            const jwtVerifyOptions: jose.JWTVerifyOptions = {
                clockTolerance: options?.clockTolerance,
                requiredClaims: options?.requiredClaims,
            };

            return await jose.jwtVerify(token, jwks, {
                ...jwtVerifyOptions,
                audience: this.clientId,
            });
        } catch (error) {
            throw new JwtVerificationError(
                'JWT signature verification failed',
                error as Error,
            );
        }
    }

    /**
     * Create user claims object from JWT payload, filtering out token metadata
     * @param payload - The validated JWT payload
     * @returns User claims object
     */
    private createUserClaimsFromPayload(payload: UserClaims): UserClaims {
        return this.extractUserClaims(
            payload,
            Authenticator.JWT_METADATA_CLAIMS,
        );
    }

    /**
     * Determine if user info should be refreshed
     * @param userRecord - Existing user record or null
     * @param userMetadata - Existing user metadata
     * @returns True if refresh is needed
     */
    private shouldRefreshUserInfo(
        userRecord: TUser | null,
        userMetadata: StorageMetadata,
    ): boolean {
        return (
            !userRecord ||
            !userMetadata?.lastUserInfoRefresh ||
            this.userInfoRefreshCondition(userRecord, userMetadata)
        );
    }

    /**
     * Validate introspection result
     * @param result - The introspection response
     * @throws TokenValidationError if token is not active
     */
    private validateIntrospectionResult(result: IntrospectionResponse): void {
        if (!result.active) {
            throw new TokenValidationError('Token is not active');
        }
    }

    /**
     * Handle UserInfo fetch failure based on configuration
     * @param error - The error that occurred
     * @param context - Additional context for logging
     * @throws Error if throwOnUserInfoFailure is true
     */
    private handleUserInfoFailure(
        error: Error,
        context?: Record<string, unknown>,
    ): void {
        const message = 'Failed to fetch UserInfo';

        if (this.throwOnUserInfoFailure) {
            throw new UserInfoError(message, error);
        }

        this.logger.log('warn', `${message}: ${error.message}`, context);
    }

    /**
     * Combine claims with priority to the second parameter
     * @param baseClaims - Base claims
     * @param priorityClaims - Priority claims that override base
     * @returns Combined claims
     */
    private combineClaimsWithPriority(
        baseClaims: UserClaims,
        priorityClaims: UserClaims,
    ): UserClaims {
        const combinedClaims: UserClaims = { sub: baseClaims.sub };

        for (const [key, value] of Object.entries(baseClaims)) {
            if (key !== 'sub' && value !== undefined) {
                combinedClaims[key] = value;
            }
        }

        for (const [key, value] of Object.entries(priorityClaims)) {
            if (key !== 'sub' && value !== undefined) {
                combinedClaims[key] = value;
            }
        }

        return combinedClaims;
    }

    /**
     * Introspect a token using the OIDC provider
     * @param token - The token to introspect
     * @returns Promise resolving to introspection response
     */
    private async introspectToken(
        token: string,
    ): Promise<IntrospectionResponse> {
        if (!this.clientConfig) {
            throw new Error('OIDC client configuration is not initialized');
        }

        try {
            return (await openid.tokenIntrospection(
                this.clientConfig,
                token,
            )) as IntrospectionResponse;
        } catch (error) {
            throw new IntrospectionError(
                'Failed to introspect token',
                error as Error,
            );
        }
    }

    /**
     * Convert introspection response to user claims
     * @param response - The introspection response
     * @returns User claims object
     */
    private introspectionResponseToUserClaims(
        response: IntrospectionResponse,
    ): UserClaims {
        return this.extractUserClaims(
            response,
            Authenticator.INTROSPECTION_METADATA_CLAIMS,
        );
    }

    /**
     * Fetch user information from the OIDC provider's UserInfo endpoint
     * @param token - The access token to use for authentication
     * @param expectedSubject - Expected subject identifier for validation
     * @returns Promise resolving to user claims
     */
    private async fetchUserInfo(
        token: string,
        expectedSubject: string,
    ): Promise<UserClaims> {
        if (!this.clientConfig) {
            throw new Error('OIDC client configuration is not initialized');
        }

        try {
            const metadata = this.clientConfig.serverMetadata();
            const userInfoEndpoint = metadata['userinfo_endpoint'] as string;

            if (!userInfoEndpoint) {
                throw new Error(
                    'No UserInfo endpoint found in server metadata',
                );
            }

            const userInfoResponse = await openid.fetchUserInfo(
                this.clientConfig,
                token,
                expectedSubject,
            );

            return this.extractUserClaims(userInfoResponse);
        } catch (error) {
            throw new UserInfoError(
                'Failed to fetch user info',
                error as Error,
            );
        }
    }

    /**
     * Process user claims and handle user info refresh
     * @param token - The token (JWT or opaque)
     * @param userClaims - Initial user claims
     * @param options - Processing options
     * @param options.tokenType - Type of token being processed
     * @param options.userRecord - Existing user record if available
     * @param options.userMetadata - Existing user metadata if available
     * @param options.forceIntrospection - Whether introspection was forced
     * @param options.userInfoAlreadyFetched - Whether UserInfo was already fetched (beforeUserRetrieval strategy)
     * @returns Promise resolving to processed user claims
     */
    private async processUserClaims(
        token: string,
        userClaims: UserClaims,
        options: {
            tokenType: 'jwt' | 'opaque';
            userRecord: TUser | null;
            userMetadata: StorageMetadata;
            forceIntrospection?: boolean;
            userInfoAlreadyFetched?: boolean;
        },
    ): Promise<TUser> {
        const {
            tokenType,
            userRecord,
            userMetadata,
            forceIntrospection,
            userInfoAlreadyFetched,
        } = options;
        let finalClaims = userClaims;

        // Only fetch UserInfo if strategy is not 'none' and using afterUserRetrieval strategy or if not already fetched
        if (
            this.userInfoStrategy !== 'none' &&
            !userInfoAlreadyFetched &&
            this.shouldRefreshUserInfo(userRecord, userMetadata)
        ) {
            try {
                const userInfoClaims = await this.fetchUserInfo(
                    token,
                    userClaims.sub,
                );
                // Apply claims changes on the user object
                finalClaims = this.combineClaimsWithPriority(
                    finalClaims,
                    userInfoClaims,
                );
                userMetadata.lastUserInfoRefresh = new Date();
            } catch (error) {
                this.handleUserInfoFailure(error as Error, {
                    tokenType,
                    subject: userClaims.sub,
                    forceIntrospection,
                });
            }
        } else if (userInfoAlreadyFetched) {
            // UserInfo was already fetched in beforeUserRetrieval strategy
            userMetadata.lastUserInfoRefresh = new Date();
        }

        const result = await this.storageAdapter.storeUser(
            userRecord,
            finalClaims,
            userMetadata,
        );

        return result;
    }

    /**
     * Extract user claims from any token-related response, filtering out metadata claims
     * @param payload - Token payload or response with claims
     * @param metadataClaims - List of metadata claims to exclude
     * @returns User claims object
     */
    private extractUserClaims(
        payload: Record<string, unknown>,
        metadataClaims: string[] | Readonly<string[]> = [],
    ): UserClaims {
        const sub = (payload['sub'] as string) || '';
        if (!sub) {
            throw new TokenValidationError(
                'Payload missing required "sub" claim',
            );
        }

        const userClaims: UserClaims = { sub };

        for (const [key, value] of Object.entries(payload)) {
            if (
                key !== 'sub' &&
                !metadataClaims.includes(key) &&
                value !== undefined
            ) {
                userClaims[key] = value;
            }
        }

        return userClaims;
    }

    /**
     * Merge JWT validation options with global defaults
     * @param options - Options provided to getUser call
     * @returns Merged options with global defaults
     */
    private mergeJwtValidationOptions(
        options?: JwtValidationOptions,
    ): JwtValidationOptions {
        return {
            ...this.globalJwtValidationOptions,
            ...options,
        };
    }

    /**
     * Create token context from validation result
     * @param validationResult - Result from JWT validation
     * @returns Token context for storage
     */
    private createTokenContext(
        validationResult: Awaited<
            ReturnType<typeof this.getValidatedJwtPayload>
        >,
    ): TokenContext {
        const context: TokenContext = {
            sub: validationResult.payload.sub,
            metadata: { validatedAt: new Date() },
        };

        if (validationResult.type === 'jwt') {
            context.jwtPayload = validationResult.payload;
        } else {
            context.introspectionResponse =
                validationResult.introspectionResponse;
            context.metadata = {
                ...context.metadata,
                forcedIntrospection: true,
            };
        }

        return context;
    }
}
