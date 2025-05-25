import * as jose from 'jose';
import * as openid from 'openid-client';
import type {
    AuthenticatorConfig,
    Logger,
    StorageAdapter,
    UserClaims,
    UserInfoRefreshCondition,
    UserRecord,
} from '../types/index.js';
import {
    ConsoleLogger,
    defaultUserInfoRefreshCondition,
    getTokenType,
} from '../utils/index.js';
import { TokenType, UserClaimsSchema } from '../types/index.js';
import { InMemoryStorageAdapter } from '../storage/index.js';
import type { IntrospectionResponse } from 'oauth4webapi';

/**
 * Main authenticator class that handles OIDC authentication and user management
 */
export class Authenticator {
    private clientConfig?: openid.Configuration;
    private storageAdapter: StorageAdapter;
    private userInfoRefreshCondition: UserInfoRefreshCondition;
    private logger: Logger;
    private throwOnUserInfoFailure: boolean;
    private isInitialized = false;

    /**
     * Creates an instance of the Authenticator
     * @param config - Configuration options for the authenticator
     */
    constructor(config: AuthenticatorConfig) {
        this.storageAdapter =
            config.storageAdapter || new InMemoryStorageAdapter();
        this.userInfoRefreshCondition =
            config.userInfoRefreshCondition || defaultUserInfoRefreshCondition;
        this.logger = config.logger || new ConsoleLogger();
        this.throwOnUserInfoFailure = config.throwOnUserInfoFailure || false;

        this.initializeClient(config).catch((error) => {
            throw new Error(
                `Failed to initialize OIDC client: ${error.message}`,
            );
        });
    }

    /**
     * Main method to get user details from a token
     * @param token - The token (JWT or opaque)
     * @param options - Optional settings for token processing
     * @param options.forceIntrospection - Force token introspection even for valid JWTs
     * @returns Promise resolving to user claims
     * @throws Error if token is invalid or user cannot be retrieved
     */
    async getUser(
        token: string,
        options?: { forceIntrospection?: boolean },
    ): Promise<UserClaims> {
        this.validateToken(token);
        this.ensureInitialized();

        const tokenType = getTokenType(token);

        if (tokenType === TokenType.OPAQUE) {
            return this.handleOpaqueToken(token);
        }

        return this.handleJwtToken(token, options?.forceIntrospection);
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
    private async initializeClient(config: AuthenticatorConfig): Promise<void> {
        try {
            this.clientConfig = await openid.discovery(
                new URL(config.issuer),
                config.clientId,
                config.clientSecret,
            );
            this.isInitialized = true;
        } catch (error) {
            throw new Error(
                `Failed to discover OIDC issuer or create client: ${(error as Error).message}`,
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
     * Ensure client is initialized
     * @throws Error if client is not initialized
     */
    private ensureInitialized(): void {
        if (!this.isInitialized || !this.clientConfig) {
            throw new Error('OIDC client is not initialized yet');
        }
    }

    /**
     * Handle opaque token by introspecting
     * @param token - The opaque token
     * @returns Promise resolving to user claims
     */
    private async handleOpaqueToken(token: string): Promise<UserClaims> {
        const introspectionResult = await this.introspectToken(token);
        this.validateIntrospectionResult(introspectionResult);

        const userClaims =
            this.introspectionResponseToUserClaims(introspectionResult);

        const userRecord = await this.storageAdapter.findUser(userClaims.sub);

        if (this.shouldRefreshUserInfo(userRecord)) {
            try {
                const userInfoClaims = await this.fetchUserInfo(
                    token,
                    userClaims.sub,
                );
                const finalClaims = this.combineClaimsWithPriority(
                    userClaims,
                    userInfoClaims,
                );
                await this.storeUserWithTimestamps(finalClaims, {
                    lastUserInfoRefresh: Date.now(),
                    lastIntrospection: Date.now(),
                });
                return finalClaims;
            } catch (error) {
                this.handleUserInfoFailure(error as Error, {
                    tokenType: 'opaque',
                    subject: userClaims.sub,
                });
                await this.storeUserWithTimestamps(userClaims, {
                    lastIntrospection: Date.now(),
                });
                return userClaims;
            }
        }

        const finalClaims = userRecord
            ? this.combineClaimsWithPriority(userRecord, userClaims)
            : userClaims;

        await this.storeUserWithTimestamps(finalClaims, {
            lastIntrospection: Date.now(),
        });
        return finalClaims;
    }

    /**
     * Handle JWT token with signature verification and conditional introspection
     * @param token - The JWT token
     * @param forceIntrospection - Whether to force token introspection regardless of conditions
     * @returns Promise resolving to user claims
     */
    private async handleJwtToken(
        token: string,
        forceIntrospection?: boolean,
    ): Promise<UserClaims> {
        try {
            const payload = await this.getValidatedJwtPayload(
                token,
                forceIntrospection,
            );
            const userClaims = this.createUserClaimsFromPayload(payload);
            const userRecord = await this.storageAdapter.findUser(payload.sub);

            if (this.shouldRefreshUserInfo(userRecord)) {
                try {
                    const userInfoClaims = await this.fetchUserInfo(
                        token,
                        userClaims.sub,
                    );
                    const finalClaims = this.combineClaimsWithPriority(
                        userClaims,
                        userInfoClaims,
                    );
                    await this.storeUserWithTimestamps(finalClaims, {
                        lastUserInfoRefresh: Date.now(),
                        lastIntrospection: forceIntrospection
                            ? Date.now()
                            : userRecord?.lastIntrospection,
                    });
                    return finalClaims;
                } catch (error) {
                    this.handleUserInfoFailure(error as Error, {
                        tokenType: 'jwt',
                        subject: userClaims.sub,
                        forceIntrospection,
                    });
                    const finalClaims = userRecord
                        ? this.combineClaimsWithPriority(userRecord, userClaims)
                        : userClaims;
                    await this.storeUserWithTimestamps(finalClaims, {
                        lastUserInfoRefresh: userRecord?.lastUserInfoRefresh,
                        lastIntrospection: forceIntrospection
                            ? Date.now()
                            : userRecord?.lastIntrospection,
                    });
                    return finalClaims;
                }
            }

            const finalClaims = userRecord
                ? this.combineClaimsWithPriority(userRecord, userClaims)
                : userClaims;

            await this.storeUserWithTimestamps(finalClaims, {
                lastUserInfoRefresh: userRecord?.lastUserInfoRefresh,
                lastIntrospection: forceIntrospection
                    ? Date.now()
                    : userRecord?.lastIntrospection,
            });
            return finalClaims;
        } catch (error) {
            throw new Error(
                `Failed to process JWT token: ${(error as Error).message}`,
            );
        }
    }

    /**
     * Get validated JWT payload, either through signature verification or introspection
     * @param token - The JWT token
     * @param forceIntrospection - Whether to use introspection instead of signature verification
     * @returns Promise resolving to validated payload
     */
    private async getValidatedJwtPayload(
        token: string,
        forceIntrospection?: boolean,
    ) {
        if (forceIntrospection) {
            const introspectionResult = await this.introspectToken(token);
            this.validateIntrospectionResult(introspectionResult);
            return this.introspectionResponseToUserClaims(introspectionResult);
        }

        const { payload: verifiedPayload } =
            await this.verifyJwtSignature(token);
        return UserClaimsSchema.parse(verifiedPayload);
    }

    /**
     * Verify the signature of a JWT token
     * @param token - The JWT token to verify
     * @returns Promise resolving to the verified JWT payload
     * @throws Error if the token signature is invalid
     */
    private async verifyJwtSignature(
        token: string,
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
            return await jose.jwtVerify(token, jwks);
        } catch (error) {
            throw new Error(
                `JWT signature verification failed: ${(error as Error).message}`,
            );
        }
    }

    /**
     * Create user claims object from JWT payload, filtering out token metadata
     * @param payload - The validated JWT payload
     * @returns User claims object
     */
    private createUserClaimsFromPayload(payload: UserClaims): UserClaims {
        const userClaims: UserClaims = { sub: payload.sub };
        const tokenMetadataClaims = [
            'client_id',
            'scope',
            'token_type',
            'nbf',
            'jti',
        ];

        for (const [key, value] of Object.entries(payload)) {
            if (
                key !== 'sub' &&
                !tokenMetadataClaims.includes(key) &&
                value !== undefined
            ) {
                userClaims[key] = value;
            }
        }

        return userClaims;
    }

    /**
     * Determine if user info should be refreshed
     * @param userRecord - Existing user record or null
     * @returns True if refresh is needed
     */
    private shouldRefreshUserInfo(userRecord: UserRecord | null): boolean {
        return (
            !userRecord ||
            !userRecord.lastUserInfoRefresh ||
            this.userInfoRefreshCondition(userRecord)
        );
    }

    /**
     * Validate introspection result
     * @param result - The introspection response
     * @throws Error if token is not active
     */
    private validateIntrospectionResult(result: IntrospectionResponse): void {
        if (!result.active) {
            throw new Error('Token is not active');
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
        const message = `Failed to fetch UserInfo: ${error.message}`;

        if (this.throwOnUserInfoFailure) {
            throw new Error(message);
        }

        this.logger.log('warn', message, context);
    }

    /**
     * Store user record with timestamp metadata
     * @param userClaims - User claims to store
     * @param timestamps - Timestamp metadata
     * @param timestamps.lastUserInfoRefresh - Last UserInfo refresh timestamp
     * @param timestamps.lastIntrospection - Last token introspection timestamp
     */
    private async storeUserWithTimestamps(
        userClaims: UserClaims,
        timestamps: {
            lastUserInfoRefresh?: number;
            lastIntrospection?: number;
        },
    ): Promise<void> {
        const userRecord: UserRecord = {
            ...userClaims,
            ...timestamps,
        };
        await this.storageAdapter.storeUser(userRecord);
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
            throw new Error(
                `Failed to introspect token: ${(error as Error).message}`,
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
        const sub = response.sub || '';
        if (!sub) {
            throw new Error(
                'Introspection response missing required "sub" claim',
            );
        }

        const userClaims: UserClaims = { sub };
        const tokenMetadataClaims = [
            'active',
            'client_id',
            'scope',
            'token_type',
            'nbf',
            'jti',
        ];

        for (const [key, value] of Object.entries(response)) {
            if (
                key !== 'sub' &&
                !tokenMetadataClaims.includes(key) &&
                value !== undefined
            ) {
                userClaims[key] = value;
            }
        }

        return userClaims;
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

            if (!userInfoResponse.sub) {
                throw new Error(
                    'UserInfo response missing required "sub" claim',
                );
            }

            const userClaims: UserClaims = { sub: userInfoResponse.sub };

            for (const [key, value] of Object.entries(userInfoResponse)) {
                if (key !== 'sub' && value !== undefined) {
                    userClaims[key] = value;
                }
            }

            return userClaims;
        } catch (error) {
            throw new Error(
                `Failed to fetch user info: ${(error as Error).message}`,
            );
        }
    }
}
