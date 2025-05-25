import * as openid from 'openid-client';
import type {
    AuthenticatorConfig,
    StorageAdapter,
    UserClaims,
    UserInfoRefreshCondition,
    UserRecord,
} from '../types/index.js';
import { TokenType, UserClaimsSchema } from '../types/index.js';
import {
    decodeJwtPayload,
    defaultUserInfoRefreshCondition,
    getTokenType,
} from '../utils/index.js';
import { InMemoryStorageAdapter } from '../storage/index.js';
import type { IntrospectionResponse } from 'oauth4webapi';

/**
 * Main authenticator class that handles OIDC authentication and user management
 */
export class Authenticator {
    private clientConfig?: openid.Configuration;
    private storageAdapter: StorageAdapter;
    private userInfoRefreshCondition: UserInfoRefreshCondition;
    private isInitialized: boolean = false;

    /**
     * Creates an instance of the Authenticator
     * @param config - Configuration options for the authenticator
     */
    constructor(config: AuthenticatorConfig) {
        this.storageAdapter =
            config.storageAdapter || new InMemoryStorageAdapter();

        // Handle userInfoRefreshCondition (new name) with fallback to introspectionCondition (old name)
        this.userInfoRefreshCondition =
            config.userInfoRefreshCondition ||
            defaultUserInfoRefreshCondition;

        // Initialize the client asynchronously
        this.initializeClient(config).catch((error) => {
            throw new Error(
                `Failed to initialize OIDC client: ${error.message}`,
            );
        });
    }

    /**
     * Initialize the OIDC client
     * @param config - Configuration options
     */
    private async initializeClient(config: AuthenticatorConfig): Promise<void> {
        try {
            // Call discovery with client ID and optional client secret
            this.clientConfig = await openid.discovery(
                new URL(config.issuer),
                config.clientId,
                config.clientSecret, // This can be undefined for public clients
            );
            this.isInitialized = true;
        } catch (error) {
            throw new Error(
                `Failed to discover OIDC issuer or create client: ${(error as Error).message}`,
            );
        }
    }

    /**
     * Main method to get user details from a token
     * @param token - The token (JWT or opaque)
     * @param options - Optional settings for token processing
     * @param options.forceIntrospection
     * @returns Promise resolving to user claims
     * @throws Error if token is invalid or user cannot be retrieved
     */
    async getUser(
        token: string,
        options?: { forceIntrospection?: boolean },
    ): Promise<UserClaims> {
        if (!token) {
            throw new Error('Token is required');
        }

        // Ensure client is initialized
        if (!this.isInitialized || !this.clientConfig) {
            throw new Error('OIDC client is not initialized yet');
        }

        const tokenType = getTokenType(token);

        if (tokenType === TokenType.OPAQUE) {
            return this.handleOpaqueToken(token);
        } else {
            return this.handleJwtToken(token, options?.forceIntrospection);
        }
    }

    /**
     * Handle opaque token by introspecting
     * @param token - The opaque token
     * @returns Promise resolving to user claims
     */
    private async handleOpaqueToken(token: string): Promise<UserClaims> {
        // Introspect the token (required for opaque tokens)
        const introspectionResult = await this.introspectToken(token);

        if (!introspectionResult.active) {
            throw new Error('Token is not active');
        }

        // Convert the introspection response to user claims
        const userClaims =
            this.introspectionResponseToUserClaims(introspectionResult);

        // Try to fetch additional user information if possible
        try {
            // Fetch fresh user info data
            const userInfoClaims = await this.fetchUserInfo(
                token,
                userClaims.sub,
            );

            // Create combined claims with priority to UserInfo data
            const mergedClaims: UserClaims = { sub: userClaims.sub };

            // First add claims from introspection
            for (const [key, value] of Object.entries(userClaims)) {
                if (key !== 'sub' && value !== undefined) {
                    mergedClaims[key] = value;
                }
            }

            // Then override with UserInfo claims
            for (const [key, value] of Object.entries(userInfoClaims)) {
                if (key !== 'sub' && value !== undefined) {
                    mergedClaims[key] = value;
                }
            }

            // Store the user with UserInfo timestamp
            const userRecord: UserRecord = {
                ...mergedClaims,
                lastUserInfoRefresh: Date.now(),
                lastIntrospection: Date.now(), // Also update introspection timestamp
            };

            await this.storageAdapter.storeUser(userRecord);
            return mergedClaims;
        } catch (error) {
            // If UserInfo fetch fails, use introspection data only
            console.warn(
                `Failed to fetch UserInfo: ${(error as Error).message}`,
            );

            // Store the user with introspection timestamp only
            const userRecord: UserRecord = {
                ...userClaims,
                lastIntrospection: Date.now(),
            };

            await this.storageAdapter.storeUser(userRecord);
            return userClaims;
        }
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
            // Parse and validate the JWT payload
            const decodedPayload = decodeJwtPayload(token);

            // Validate the payload with Zod
            const payload = UserClaimsSchema.parse(decodedPayload);

            // Create a UserClaims object from the validated payload
            // Start with the required sub claim
            const userClaims: UserClaims = { sub: payload.sub };

            // Define token metadata claims that shouldn't be included in user claims
            const tokenMetadataClaims = [
                'client_id', // Client the token was issued for
                'scope', // Scopes associated with the token
                'token_type', // Type of token
                'nbf', // Not before time
                'jti', // JWT ID
            ];

            // Copy all claims except token metadata
            for (const [key, value] of Object.entries(payload)) {
                if (
                    key !== 'sub' && // Already added
                    !tokenMetadataClaims.includes(key) &&
                    value !== undefined
                ) {
                    userClaims[key] = value;
                }
            }

            // Look for existing user in storage
            let userRecord = await this.storageAdapter.findUser(payload.sub);

            // Force token introspection if requested
            if (forceIntrospection) {
                // Introspect to verify token and get additional claims
                const introspectionResult = await this.introspectToken(token);

                if (!introspectionResult.active) {
                    throw new Error('Token is not active');
                }

                const introspectionClaims =
                    this.introspectionResponseToUserClaims(introspectionResult);

                // Merge claims from JWT and introspection with priority to introspection
                for (const [key, value] of Object.entries(
                    introspectionClaims,
                )) {
                    if (key !== 'sub' && value !== undefined) {
                        userClaims[key] = value;
                    }
                }
            }

            // Determine if we need to refresh user info
            const needsUserInfoRefresh =
                !userRecord ||
                !userRecord.lastUserInfoRefresh ||
                this.userInfoRefreshCondition(userRecord);

            if (needsUserInfoRefresh) {
                try {
                    // Fetch fresh user data from UserInfo endpoint
                    const userInfoClaims = await this.fetchUserInfo(
                        token,
                        payload.sub,
                    );

                    // Create combined claims object with priority to UserInfo data
                    const combinedClaims: UserClaims = { sub: userClaims.sub };

                    // First add all JWT/introspection claims
                    for (const [key, value] of Object.entries(userClaims)) {
                        if (key !== 'sub' && value !== undefined) {
                            combinedClaims[key] = value;
                        }
                    }

                    // Then override with UserInfo claims (highest priority)
                    for (const [key, value] of Object.entries(userInfoClaims)) {
                        if (key !== 'sub' && value !== undefined) {
                            combinedClaims[key] = value;
                        }
                    }

                    // Update storage with fresh data and both timestamps
                    userRecord = {
                        ...combinedClaims,
                        lastUserInfoRefresh: Date.now(),
                        lastIntrospection: forceIntrospection
                            ? Date.now()
                            : userRecord?.lastUserInfoRefresh,
                    };

                    await this.storageAdapter.storeUser(userRecord);
                    return combinedClaims;
                } catch (error) {
                    // If UserInfo fetch fails but we have valid JWT/introspection data, continue
                    console.warn(
                        `Failed to fetch UserInfo: ${(error as Error).message}`,
                    );
                }
            }

            // If we get here, either UserInfo fetch wasn't needed or failed
            // Use cached user data if available, merged with current JWT claims
            if (userRecord) {
                // Use cached user data, but prioritize JWT/introspection claims for freshness
                const {
                    lastUserInfoRefresh,
                    lastIntrospection,
                    ...cachedClaims
                } = userRecord;

                // Create combined claims object with priority to current JWT/introspection
                const combinedClaims: UserClaims = { sub: userClaims.sub };

                // First add all cached claims
                for (const [key, value] of Object.entries(cachedClaims)) {
                    if (key !== 'sub' && value !== undefined) {
                        combinedClaims[key] = value;
                    }
                }

                // Then override with any JWT/introspection claims
                for (const [key, value] of Object.entries(userClaims)) {
                    if (key !== 'sub' && value !== undefined) {
                        combinedClaims[key] = value;
                    }
                }

                // Update storage if anything changed
                const newUserRecord = {
                    ...combinedClaims,
                    lastUserInfoRefresh: userRecord.lastUserInfoRefresh,
                    lastIntrospection: forceIntrospection
                        ? Date.now()
                        : userRecord.lastUserInfoRefresh,
                };

                await this.storageAdapter.storeUser(newUserRecord);
                return combinedClaims;
            }

            // No existing user record and UserInfo fetch failed
            // Store the JWT claims and return them
            userRecord = {
                ...userClaims,
                lastIntrospection: forceIntrospection ? Date.now() : undefined,
            };

            await this.storageAdapter.storeUser(userRecord);
            return userClaims;
        } catch (error) {
            throw new Error(
                `Failed to process JWT token: ${(error as Error).message}`,
            );
        }
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
            // Use openid client's built-in token introspection function
            const metadata = this.clientConfig.serverMetadata();

            // Get the introspection endpoint
            const tokenIntrospectionEndpoint = metadata[
                'token_introspection_endpoint'
            ] as string;
            if (!tokenIntrospectionEndpoint) {
                throw new Error(
                    'No token introspection endpoint found in server metadata',
                );
            }

            // Use the openid-client's tokenIntrospection function
            // This handles all the necessary authentication and formatting
            const introspectionResponse = await openid.tokenIntrospection(
                this.clientConfig,
                token,
            );

            return introspectionResponse as IntrospectionResponse;
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
        // Ensure we have a sub claim, which is the only required claim
        const sub = response.sub || '';
        if (!sub) {
            throw new Error(
                'Introspection response missing required "sub" claim',
            );
        }

        // Create a minimal user claims object with only the required 'sub' property
        const userClaims: UserClaims = { sub };

        // Define token metadata claims that shouldn't be considered user claims
        const tokenMetadataClaims = [
            'active', // Introspection-specific field
            'client_id', // Client the token was issued for
            'scope', // Scopes associated with the token
            'token_type', // Type of token
            'nbf', // Not before time
            'jti', // JWT ID
        ];

        // Copy all claims from the response except token metadata
        for (const [key, value] of Object.entries(response)) {
            if (
                key !== 'sub' && // Already added
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
     * @param expectedSubject
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
            // Get the UserInfo endpoint from the server metadata
            const metadata = this.clientConfig.serverMetadata();
            const userInfoEndpoint = metadata['userinfo_endpoint'] as string;

            if (!userInfoEndpoint) {
                throw new Error(
                    'No UserInfo endpoint found in server metadata',
                );
            }

            // Use openid-client's built-in fetchUserInfo function
            const userInfoResponse = await openid.fetchUserInfo(
                this.clientConfig,
                token,
                expectedSubject,
            );

            // Ensure we have a sub claim
            if (!userInfoResponse.sub) {
                throw new Error(
                    'UserInfo response missing required "sub" claim',
                );
            }

            // Create a base UserClaims object with the required sub property
            const userClaims: UserClaims = { sub: userInfoResponse.sub };

            // Copy all other claims from the userInfo response
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

    /**
     * Clear all cached user data (useful for testing or reset)
     */
    async clearCache(): Promise<void> {
        if (this.storageAdapter instanceof InMemoryStorageAdapter) {
            this.storageAdapter.clear();
        }
    }
}
