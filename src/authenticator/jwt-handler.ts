import * as jose from 'jose';
import type { IntrospectionResponse } from 'oauth4webapi';
import { JwtVerificationError } from '../errors.js';
import type {
    JwtValidationOptions,
    Logger,
    TokenContext,
    UserClaims,
} from '../types/index.js';
import { UserClaimsSchema } from '../types/index.js';
import {
    extractFromIntrospection,
    extractFromJwt,
    validateIntrospectionResult,
} from './claims-processor.js';
import { TokenHandler } from './token-handler.js';
import type { BaseHandlerConfig, ValidationResult } from './token-handler.js';

export interface JwtHandlerConfig<TUser> extends BaseHandlerConfig<TUser> {
    audience: string | string[];
    globalJwtValidationOptions: JwtValidationOptions;
    enableIntrospectionFallthrough: boolean;
    logger: Logger;
}

type JwtValidationResult =
    | { type: 'jwt'; payload: UserClaims }
    | {
          type: 'introspection';
          payload: UserClaims;
          introspectionResponse: IntrospectionResponse;
      };

export class JwtHandler<TUser> extends TokenHandler<TUser> {
    protected readonly tokenType = 'jwt' as const;
    private config: JwtHandlerConfig<TUser>;
    private jwks: ReturnType<typeof jose.createRemoteJWKSet> | undefined =
        undefined;

    public constructor(config: JwtHandlerConfig<TUser>) {
        super(config);
        this.config = config;
    }

    protected async validate(
        token: string,
        options?: JwtValidationOptions,
    ): Promise<ValidationResult> {
        const validationResult = await this.getValidatedPayload(token, options);
        const claims = extractFromJwt(validationResult.payload);
        const context = this.createTokenContext(validationResult);
        return {
            claims,
            context,
            usedIntrospection: validationResult.type === 'introspection',
        };
    }

    private async getValidatedPayload(
        token: string,
        options?: JwtValidationOptions,
    ): Promise<JwtValidationResult> {
        const mergedOptions = this.mergeOptions(options);

        if (!mergedOptions.forceIntrospection) {
            try {
                const { payload: verifiedPayload } = await this.verifySignature(
                    token,
                    mergedOptions,
                );
                const payload = UserClaimsSchema.parse(verifiedPayload);
                return { type: 'jwt', payload };
            } catch (error) {
                if (!this.config.enableIntrospectionFallthrough) throw error;
                this.config.logger.log(
                    'warn',
                    'JWT verification failed, falling back to introspection',
                    { error: (error as Error).message },
                );
            }
        }

        const introspectionResult = await this.introspectToken(token);
        validateIntrospectionResult(introspectionResult);
        const payload = extractFromIntrospection(introspectionResult);

        return {
            type: 'introspection',
            payload,
            introspectionResponse: introspectionResult,
        };
    }

    private async verifySignature(
        token: string,
        options?: JwtValidationOptions,
    ): Promise<jose.JWTVerifyResult> {
        try {
            const jwks = this.getJwks();
            return await jose.jwtVerify(token, jwks, {
                clockTolerance: options?.clockTolerance,
                requiredClaims: options?.requiredClaims,
                audience: this.config.audience,
            });
        } catch (error) {
            throw new JwtVerificationError(
                'JWT signature verification failed',
                error as Error,
            );
        }
    }

    private getJwks(): ReturnType<typeof jose.createRemoteJWKSet> {
        if (!this.jwks) {
            const metadata = this.clientConfig.serverMetadata();
            const jwksUri = metadata['jwks_uri'];
            if (!jwksUri) {
                throw new JwtVerificationError(
                    'No JWKS URI found in server metadata',
                );
            }
            this.jwks = jose.createRemoteJWKSet(new URL(jwksUri));
        }
        return this.jwks;
    }

    private mergeOptions(options?: JwtValidationOptions): JwtValidationOptions {
        return {
            ...this.config.globalJwtValidationOptions,
            ...options,
        };
    }

    private createTokenContext(
        validationResult: JwtValidationResult,
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
