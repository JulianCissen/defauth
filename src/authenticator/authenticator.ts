import * as openid from 'openid-client';
import { InitializationError, TokenValidationError } from '../errors.js';
import { InMemoryStorageAdapter } from '../storage/index.js';
import type {
    AuthenticationMethod,
    DefauthConfig,
    JwtValidationOptions,
    StorageAdapter,
} from '../types/index.js';
import { TokenType } from '../types/index.js';
import {
    ConsoleLogger,
    defaultUserInfoRefreshCondition,
    getTokenType,
} from '../utils/index.js';
import { JwtHandler } from './jwt-handler.js';
import { OpaqueHandler } from './opaque-handler.js';
import { UserInfoManager } from './user-info-manager.js';

/**
 * Resolves the effective introspection fallthrough setting.
 * `enableIntrospectionFallthrough` takes precedence over the deprecated `disableIntrospectionFallthrough`.
 * When neither is set, fallthrough is enabled by default.
 * @param enable - Value of `enableIntrospectionFallthrough` from config
 * @param disable - Value of `disableIntrospectionFallthrough` from config
 * @returns Whether introspection fallthrough is enabled
 */
function resolveIntrospectionFallthrough(
    enable: boolean | undefined,
    disable: boolean | undefined,
): boolean {
    if (enable !== undefined) return enable;
    if (disable !== undefined) return !disable;
    return true;
}

/**
 * Main authenticator class for validating OIDC tokens and retrieving user information.
 */
export class Defauth<TUser> {
    private clientConfig?: openid.Configuration;
    private jwtHandler?: JwtHandler<TUser>;
    private opaqueHandler?: OpaqueHandler<TUser>;
    private storageAdapter: StorageAdapter<TUser>;
    private authenticationMethod: AuthenticationMethod;
    private clientId: string;
    private clientSecret?: string;
    private allowInsecureRequests: boolean;
    private initializationConfig?: DefauthConfig<TUser>;

    /**
     * Creates and initializes a new `Defauth` instance by running OIDC discovery against the issuer.
     * @param config - Configuration for the OIDC client
     * @returns A fully initialized `Defauth` instance
     */
    public static async create<TUser>(
        config: DefauthConfig<TUser>,
    ): Promise<Defauth<TUser>> {
        const authenticator = new Defauth(config);
        await authenticator.initializeClient(config);
        return authenticator;
    }

    private constructor(config: DefauthConfig<TUser>) {
        this.clientId = config.clientId;
        this.clientSecret = config.clientSecret;
        this.authenticationMethod =
            config.authenticationMethod ||
            (config.clientSecret ? 'client_secret_post' : 'none');
        this.allowInsecureRequests = config.allowInsecureRequests || false;
        this.initializationConfig = config;
        this.storageAdapter =
            config.storageAdapter || new InMemoryStorageAdapter<TUser>();
    }

    /**
     * Validates the given token and returns the resolved user.
     * Supports both JWT and opaque tokens, routing each to the appropriate handler.
     * @param token - The token to validate (JWT or opaque)
     * @param options - Optional per-call validation options
     * @returns The resolved user object
     */
    public async getUser(
        token: string,
        options?: JwtValidationOptions,
    ): Promise<TUser> {
        this.validateToken(token);
        await this.ensureInitialized();

        const tokenType = getTokenType(token);

        if (tokenType === TokenType.OPAQUE) {
            return this.opaqueHandler!.handle(token, options);
        }

        return this.jwtHandler!.handle(token, options);
    }

    /**
     * Clears the in-memory user cache if the configured storage adapter supports it.
     */
    public async clearCache(): Promise<void> {
        if (this.storageAdapter instanceof InMemoryStorageAdapter) {
            this.storageAdapter.clear();
        }
    }

    private async initializeClient(
        config: DefauthConfig<TUser>,
    ): Promise<void> {
        try {
            const executeOptions = this.allowInsecureRequests
                ? [openid.allowInsecureRequests]
                : [];

            const authMethod = this.getAuthenticationMethod();

            this.clientConfig = await openid.discovery(
                new URL(config.issuer),
                this.clientId,
                this.clientSecret,
                authMethod,
                { execute: executeOptions },
            );
        } catch (error) {
            throw new InitializationError(
                'Failed to discover OIDC issuer or create client',
                error as Error,
            );
        }

        this.buildHandlers(config);
    }

    private buildHandlers(config: DefauthConfig<TUser>): void {
        const logger = config.logger || new ConsoleLogger();
        const userInfoStrategy =
            config.userInfoStrategy || 'afterUserRetrieval';

        const userInfoManager = new UserInfoManager({
            clientConfig: this.clientConfig!,
            logger,
            throwOnUserInfoFailure: config.throwOnUserInfoFailure || false,
            userInfoStrategy,
            userInfoRefreshCondition:
                config.userInfoRefreshCondition ||
                defaultUserInfoRefreshCondition,
            storageAdapter: this.storageAdapter,
        });

        const enableIntrospectionFallthrough = resolveIntrospectionFallthrough(
            config.enableIntrospectionFallthrough,
            config.disableIntrospectionFallthrough,
        );

        this.jwtHandler = new JwtHandler({
            clientConfig: this.clientConfig!,
            audience: config.audience || this.clientId,
            globalJwtValidationOptions: config.jwtValidationOptions || {
                requiredClaims: ['sub', 'exp'],
                clockTolerance: '1 minute',
            },
            enableIntrospectionFallthrough,
            logger,
            userInfoManager,
            storageAdapter: this.storageAdapter,
            userInfoStrategy,
        });

        this.opaqueHandler = new OpaqueHandler({
            clientConfig: this.clientConfig!,
            userInfoManager,
            storageAdapter: this.storageAdapter,
            userInfoStrategy,
        });
    }

    private async ensureInitialized(): Promise<void> {
        if (!this.clientConfig && this.initializationConfig) {
            await this.initializeClient(this.initializationConfig);
        }

        if (!this.clientConfig) {
            throw new InitializationError(
                'OIDC client is not initialized. Use Defauth.create() for proper initialization.',
            );
        }
    }

    private validateToken(token: string): void {
        if (!token) {
            throw new TokenValidationError('Token is required');
        }
    }

    private getAuthenticationMethod() {
        switch (this.authenticationMethod) {
            case 'client_secret_post': {
                return openid.ClientSecretPost(this.clientSecret);
            }
            case 'client_secret_basic': {
                return openid.ClientSecretBasic(this.clientSecret);
            }
            case 'client_secret_jwt': {
                return openid.ClientSecretJwt(this.clientSecret);
            }
            case 'none': {
                return openid.None();
            }
            default: {
                throw new InitializationError(
                    `Unsupported authentication method: ${String(this.authenticationMethod)}`,
                );
            }
        }
    }
}
