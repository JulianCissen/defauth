import type { IntrospectionResponse } from 'oauth4webapi';
import type { TokenContext, UserClaims } from '../types/index.js';
import {
    extractFromIntrospection,
    validateIntrospectionResult,
} from './claims-processor.js';
import { TokenHandler } from './token-handler.js';
import type { BaseHandlerConfig, ValidationResult } from './token-handler.js';

export type OpaqueHandlerConfig<TUser> = BaseHandlerConfig<TUser>;

export class OpaqueHandler<TUser> extends TokenHandler<TUser> {
    protected readonly tokenType = 'opaque' as const;

    public constructor(config: OpaqueHandlerConfig<TUser>) {
        super(config);
    }

    protected async validate(token: string): Promise<ValidationResult> {
        const introspectionResult = await this.introspectToken(token);
        validateIntrospectionResult(introspectionResult);
        const claims = extractFromIntrospection(introspectionResult);
        const context = this.buildTokenContext(claims, introspectionResult);
        return { claims, context, usedIntrospection: true };
    }

    private buildTokenContext(
        userClaims: UserClaims,
        introspectionResult: IntrospectionResponse,
    ): TokenContext {
        return {
            sub: userClaims.sub,
            introspectionResponse: introspectionResult,
            metadata: { validatedAt: new Date() },
        };
    }
}
