import * as openid from 'openid-client';
import type {
    CustomValidator,
    Logger,
    StorageAdapter,
    StorageMetadata,
    UserClaims,
    UserInfoRefreshCondition,
    UserInfoStrategy,
} from '../types/index.js';
import { CustomValidationError, UserInfoError } from '../types/index.js';
import {
    combineClaimsWithPriority,
    extractUserClaims,
} from './claims-processor.js';

export interface UserInfoManagerConfig<TUser> {
    clientConfig: openid.Configuration;
    logger: Logger;
    throwOnUserInfoFailure: boolean;
    userInfoStrategy: UserInfoStrategy;
    userInfoRefreshCondition: UserInfoRefreshCondition<TUser>;
    storageAdapter: StorageAdapter<TUser>;
}

/**
 * Manages UserInfo endpoint fetching, refresh decisions, and merging claims into the final user record.
 */
export class UserInfoManager<TUser> {
    private config: UserInfoManagerConfig<TUser>;

    public constructor(config: UserInfoManagerConfig<TUser>) {
        this.config = config;
    }

    /**
     * Fetches claims from the OIDC UserInfo endpoint for the given token and subject.
     * @param token - The access token to use when calling the UserInfo endpoint
     * @param sub - The subject identifier to pass to the UserInfo endpoint
     * @returns Extracted user claims from the UserInfo response
     */
    private async fetchUserInfo(
        token: string,
        sub: string,
    ): Promise<UserClaims> {
        try {
            const metadata = this.config.clientConfig.serverMetadata();
            const userInfoEndpoint = metadata['userinfo_endpoint'] as string;

            if (!userInfoEndpoint) {
                throw new UserInfoError(
                    'No UserInfo endpoint found in server metadata',
                );
            }

            const userInfoResponse = await openid.fetchUserInfo(
                this.config.clientConfig,
                token,
                sub,
            );

            return extractUserClaims(userInfoResponse);
        } catch (error) {
            throw new UserInfoError(
                'Failed to fetch user info',
                error as Error,
            );
        }
    }

    /**
     * Returns true if the UserInfo endpoint should be called for this request,
     * based on whether the user record exists and the configured refresh condition.
     * @param userRecord - The existing user record, or null if not yet stored
     * @param userMetadata - Metadata associated with the stored user record
     * @returns Whether a UserInfo refresh is needed
     */
    public shouldRefresh(
        userRecord: TUser | null,
        userMetadata: StorageMetadata,
    ): boolean {
        return (
            !userRecord ||
            !userMetadata?.lastUserInfoRefresh ||
            this.config.userInfoRefreshCondition(userRecord, userMetadata)
        );
    }

    /**
     * Attempts to fetch UserInfo claims, handling failure according to `throwOnUserInfoFailure`.
     * @param token - The access token to use when calling the UserInfo endpoint
     * @param sub - The subject identifier
     * @param context - Optional context to include in warning logs on failure
     * @returns Extracted user claims, or `null` if the fetch failed and `throwOnUserInfoFailure` is false
     */
    public async tryFetchUserInfo(
        token: string,
        sub: string,
        context?: Record<string, unknown>,
    ): Promise<UserClaims | null> {
        try {
            return await this.fetchUserInfo(token, sub);
        } catch (error) {
            this.handleFailure(error as Error, context);
            return null;
        }
    }

    private handleFailure(
        error: Error,
        context?: Record<string, unknown>,
    ): void {
        const message = 'Failed to fetch UserInfo';

        if (this.config.throwOnUserInfoFailure) {
            throw new UserInfoError(message, error);
        }

        this.config.logger.log('warn', `${message}: ${error.message}`, context);
    }

    /**
     * Fetches UserInfo if needed, runs optional custom validation, and persists the final user record via the storage adapter.
     * @param token - The token used to call the UserInfo endpoint if a refresh is needed
     * @param userClaims - User claims extracted from the token (JWT payload or introspection response)
     * @param options - Processing options including token type, existing user record, and optional validator
     * @returns The stored user object after merging claims and running validation
     *
     * Note: when `userInfoStrategy` is `'beforeUserRetrieval'`, UserInfo is always fetched before
     * this method is called (no storage lookup has occurred yet, so `userInfoRefreshCondition`
     * cannot be evaluated). The `userInfoAlreadyFetched` flag signals this case.
     */
    public async processUserClaims(
        token: string,
        userClaims: UserClaims,
        options: {
            tokenType: 'jwt' | 'opaque';
            userRecord: TUser | null;
            userMetadata: StorageMetadata;
            forceIntrospection?: boolean;
            userInfoAlreadyFetched?: boolean;
            customValidator?: CustomValidator;
        },
    ): Promise<TUser> {
        const finalClaims = await this.enrichWithUserInfo(
            token,
            userClaims,
            options,
        );
        await this.runCustomValidation(finalClaims, options.customValidator);
        return this.config.storageAdapter.storeUser(
            options.userRecord,
            finalClaims,
            options.userMetadata,
        );
    }

    private async enrichWithUserInfo(
        token: string,
        userClaims: UserClaims,
        options: {
            tokenType: 'jwt' | 'opaque';
            userRecord: TUser | null;
            userMetadata: StorageMetadata;
            forceIntrospection?: boolean;
            userInfoAlreadyFetched?: boolean;
        },
    ): Promise<UserClaims> {
        if (options.userInfoAlreadyFetched) {
            options.userMetadata.lastUserInfoRefresh = new Date();
            return userClaims;
        }

        if (this.config.userInfoStrategy === 'none') return userClaims;

        if (!this.shouldRefresh(options.userRecord, options.userMetadata))
            return userClaims;

        const userInfoClaims = await this.tryFetchUserInfo(
            token,
            userClaims.sub,
            {
                tokenType: options.tokenType,
                subject: userClaims.sub,
                forceIntrospection: options.forceIntrospection,
            },
        );
        if (!userInfoClaims) return userClaims;
        options.userMetadata.lastUserInfoRefresh = new Date();
        return combineClaimsWithPriority(userClaims, userInfoClaims);
    }

    private async runCustomValidation(
        claims: UserClaims,
        customValidator?: CustomValidator,
    ): Promise<void> {
        if (!customValidator) return;
        try {
            await customValidator(claims);
        } catch (error) {
            throw new CustomValidationError(
                'Custom validation failed',
                error as Error,
            );
        }
    }
}
