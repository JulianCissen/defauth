import type { IntrospectionResponse } from 'oauth4webapi';
import * as openid from 'openid-client';
import type {
    JwtValidationOptions,
    StorageAdapter,
    StorageMetadata,
    TokenContext,
    UserClaims,
    UserInfoStrategy,
} from '../types/index.js';
import {
    DefauthError,
    IntrospectionError,
    TokenValidationError,
} from '../types/index.js';
import { combineClaimsWithPriority } from './claims-processor.js';
import type { UserInfoManager } from './user-info-manager.js';

export interface ValidationResult {
    claims: UserClaims;
    context: TokenContext;
    usedIntrospection: boolean;
}

export interface BaseHandlerConfig<TUser> {
    clientConfig: openid.Configuration;
    userInfoManager: UserInfoManager<TUser>;
    storageAdapter: StorageAdapter<TUser>;
    userInfoStrategy: UserInfoStrategy;
}

export abstract class TokenHandler<TUser> {
    protected readonly clientConfig: openid.Configuration;
    private readonly userInfoManager: UserInfoManager<TUser>;
    private readonly storageAdapter: StorageAdapter<TUser>;
    private readonly userInfoStrategy: UserInfoStrategy;

    public constructor(config: BaseHandlerConfig<TUser>) {
        this.clientConfig = config.clientConfig;
        this.userInfoManager = config.userInfoManager;
        this.storageAdapter = config.storageAdapter;
        this.userInfoStrategy = config.userInfoStrategy;
    }

    public async handle(
        token: string,
        options?: JwtValidationOptions,
    ): Promise<TUser> {
        try {
            const { claims, context, usedIntrospection } = await this.validate(
                token,
                options,
            );
            const enrichedClaims = await this.fetchUserInfoBeforeRetrieval(
                token,
                claims,
                context,
                options,
            );
            const { user, metadata } = await this.loadUserRecord(
                context,
                usedIntrospection,
            );
            return this.userInfoManager.processUserClaims(
                token,
                enrichedClaims,
                {
                    tokenType: this.tokenType,
                    userRecord: user,
                    userMetadata: metadata,
                    userInfoAlreadyFetched: !!context.userInfoResult,
                    customValidator: options?.customValidator,
                },
            );
        } catch (error) {
            if (error instanceof DefauthError) throw error;
            throw new TokenValidationError(
                `Failed to process ${this.tokenType} token`,
                error as Error,
            );
        }
    }

    protected abstract readonly tokenType: 'jwt' | 'opaque';
    protected abstract validate(
        token: string,
        options?: JwtValidationOptions,
    ): Promise<ValidationResult>;

    protected async introspectToken(
        token: string,
    ): Promise<IntrospectionResponse> {
        try {
            return await openid.tokenIntrospection(this.clientConfig, token);
        } catch (error) {
            throw new IntrospectionError(
                'Failed to introspect token',
                error as Error,
            );
        }
    }

    private async fetchUserInfoBeforeRetrieval(
        token: string,
        userClaims: UserClaims,
        tokenContext: TokenContext,
        options?: JwtValidationOptions,
    ): Promise<UserClaims> {
        if (this.userInfoStrategy !== 'beforeUserRetrieval') return userClaims;
        const userInfoClaims = await this.userInfoManager.tryFetchUserInfo(
            token,
            userClaims.sub,
            {
                tokenType: this.tokenType,
                subject: userClaims.sub,
                strategy: 'beforeUserRetrieval',
                forceIntrospection: options?.forceIntrospection,
            },
        );
        if (!userInfoClaims) return userClaims;
        tokenContext.userInfoResult = userInfoClaims;
        return combineClaimsWithPriority(userClaims, userInfoClaims);
    }

    private async loadUserRecord(
        context: TokenContext,
        usedIntrospection: boolean,
    ): Promise<{ user: TUser | null; metadata: StorageMetadata }> {
        const record = await this.storageAdapter.findUser(context);
        const metadata = record?.metadata ?? {};
        if (usedIntrospection) metadata.lastIntrospection = new Date();
        return { user: record?.user ?? null, metadata };
    }
}
