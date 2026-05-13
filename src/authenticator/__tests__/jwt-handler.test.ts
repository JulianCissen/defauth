import * as jose from 'jose';
import * as openid from 'openid-client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { JwtVerificationError } from '../../errors.js';
import type { UserClaims } from '../../types/index.js';
import { defaultUserInfoRefreshCondition } from '../../utils/index.js';
import { JwtHandler } from '../jwt-handler.js';
import { UserInfoManager } from '../user-info-manager.js';
import {
    MOCK_CLIENT_ID,
    MOCK_INTROSPECTION_ACTIVE,
    MOCK_JWT_PAYLOAD,
    MOCK_JWT_TOKEN,
    MOCK_USER_CLAIMS,
    MOCK_USERINFO_RESPONSE,
    MockLogger,
    MockStorageAdapter,
    createMockJwtVerifyResult,
    createMockOpenidClient,
} from './test-utils.js';

const joseMock = vi.mocked(jose);
const openidMock = vi.mocked(openid);

function buildHandler(
    overrides: Partial<
        ConstructorParameters<typeof JwtHandler<UserClaims>>[0]
    > = {},
) {
    const storageAdapter =
        overrides.storageAdapter ?? new MockStorageAdapter<UserClaims>();
    const logger = overrides.logger ?? new MockLogger();
    const clientConfig = createMockOpenidClient() as never;

    const userInfoManager =
        overrides.userInfoManager ??
        new UserInfoManager({
            clientConfig,
            logger,
            throwOnUserInfoFailure: false,
            userInfoStrategy: 'afterUserRetrieval',
            userInfoRefreshCondition: defaultUserInfoRefreshCondition,
            storageAdapter,
        });

    return new JwtHandler<UserClaims>({
        clientConfig,
        audience: MOCK_CLIENT_ID,
        globalJwtValidationOptions: {
            requiredClaims: ['sub', 'exp'],
            clockTolerance: '1 minute',
        },
        enableIntrospectionFallthrough: true,
        logger,
        userInfoManager,
        storageAdapter,
        userInfoStrategy: 'afterUserRetrieval',
        ...overrides,
    });
}

describe('JwtHandler', () => {
    let mockStorageAdapter: MockStorageAdapter<UserClaims>;
    let mockLogger: MockLogger;

    beforeEach(() => {
        vi.clearAllMocks();
        mockStorageAdapter = new MockStorageAdapter<UserClaims>();
        mockLogger = new MockLogger();

        joseMock.createRemoteJWKSet.mockReturnValue(vi.fn() as never);
        joseMock.jwtVerify.mockResolvedValue(
            createMockJwtVerifyResult() as never,
        );
        joseMock.decodeProtectedHeader.mockReturnValue({
            alg: 'RS256',
            typ: 'JWT',
        } as never);
        joseMock.decodeJwt.mockReturnValue({
            sub: 'user123',
            name: 'Test User',
            email: 'test@example.com',
            iat: 1_630_000_000,
            exp: 9_999_999_999,
            aud: 'test-client-id',
            iss: 'https://mock-oidc-provider.com',
        } as never);
        openidMock.tokenIntrospection.mockResolvedValue(
            MOCK_INTROSPECTION_ACTIVE as never,
        );
        openidMock.fetchUserInfo.mockResolvedValue(
            MOCK_USERINFO_RESPONSE as never,
        );
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe('JWT signature verification', () => {
        it('should verify JWT and return user', async () => {
            const handler = buildHandler({
                storageAdapter: mockStorageAdapter,
                logger: mockLogger,
            });

            const result = await handler.handle(MOCK_JWT_TOKEN);

            expect(joseMock.jwtVerify).toHaveBeenCalledWith(
                MOCK_JWT_TOKEN,
                expect.any(Function),
                expect.objectContaining({
                    clockTolerance: '1 minute',
                    requiredClaims: ['sub', 'exp'],
                    audience: MOCK_CLIENT_ID,
                }),
            );
            expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
        });

        it('should pass audience to jwtVerify', async () => {
            const handler = buildHandler({
                audience: 'https://api.example.com',
                storageAdapter: mockStorageAdapter,
            });

            await handler.handle(MOCK_JWT_TOKEN);

            expect(joseMock.jwtVerify).toHaveBeenCalledWith(
                MOCK_JWT_TOKEN,
                expect.any(Function),
                expect.objectContaining({
                    audience: 'https://api.example.com',
                }),
            );
        });

        it('should respect per-call options over global defaults', async () => {
            const handler = buildHandler({
                storageAdapter: mockStorageAdapter,
            });

            await handler.handle(MOCK_JWT_TOKEN, {
                clockTolerance: '30 seconds',
                requiredClaims: ['sub', 'iss'],
            });

            expect(joseMock.jwtVerify).toHaveBeenCalledWith(
                MOCK_JWT_TOKEN,
                expect.any(Function),
                expect.objectContaining({
                    clockTolerance: '30 seconds',
                    requiredClaims: ['sub', 'iss'],
                }),
            );
        });

        it('should filter JWT metadata claims from result', async () => {
            const payloadWithMetadata = {
                ...MOCK_JWT_PAYLOAD,
                custom_claim: 'keep-me',
            };
            joseMock.jwtVerify.mockResolvedValueOnce(
                createMockJwtVerifyResult(payloadWithMetadata) as never,
            );

            const cachedUser = { sub: MOCK_USER_CLAIMS.sub, name: 'Cached' };
            mockStorageAdapter.setUser(cachedUser);

            const handler = buildHandler({
                storageAdapter: mockStorageAdapter,
            });
            const result = await handler.handle(MOCK_JWT_TOKEN);

            expect(result['custom_claim']).toBe('keep-me');
            expect(result['client_id']).toBeUndefined();
            expect(result['scope']).toBeUndefined();
            expect(result['jti']).toBeUndefined();
        });
    });

    describe('introspection fallback', () => {
        it('should fall back to introspection when JWT verification fails', async () => {
            joseMock.jwtVerify.mockRejectedValue(
                new Error('Invalid signature'),
            );
            const handler = buildHandler({
                storageAdapter: mockStorageAdapter,
                logger: mockLogger,
            });

            const result = await handler.handle(MOCK_JWT_TOKEN);

            expect(openidMock.tokenIntrospection).toHaveBeenCalledWith(
                expect.any(Object),
                MOCK_JWT_TOKEN,
            );
            expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
        });

        it('should log a warning before falling back to introspection', async () => {
            joseMock.jwtVerify.mockRejectedValue(new Error('Expired'));
            const handler = buildHandler({ logger: mockLogger });

            await handler.handle(MOCK_JWT_TOKEN);

            const warnings = mockLogger.getLogsForLevel('warn');
            expect(warnings).toHaveLength(1);
            expect(warnings[0]?.message).toContain(
                'JWT verification failed, falling back to introspection',
            );
        });

        it('should set TokenContext.introspectionResponse on fallback', async () => {
            joseMock.jwtVerify.mockRejectedValue(new Error('Sig failed'));
            const handler = buildHandler({
                storageAdapter: mockStorageAdapter,
            });

            await handler.handle(MOCK_JWT_TOKEN);

            const ctx = mockStorageAdapter.findUserCalls[0];
            expect(ctx?.introspectionResponse).toBeDefined();
            expect(ctx?.metadata?.forcedIntrospection).toBe(true);
        });

        it('should set TokenContext.jwtPayload on successful JWT verification', async () => {
            const handler = buildHandler({
                storageAdapter: mockStorageAdapter,
            });

            await handler.handle(MOCK_JWT_TOKEN);

            const ctx = mockStorageAdapter.findUserCalls[0];
            expect(ctx?.jwtPayload).toBeDefined();
            expect(ctx?.introspectionResponse).toBeUndefined();
        });

        it('should fall back to introspection when JWKS URI is missing', async () => {
            const clientWithoutJwks = {
                serverMetadata: vi.fn().mockReturnValue({
                    userinfo_endpoint: 'https://mock/userinfo',
                }),
            };
            const handler = buildHandler({
                clientConfig: clientWithoutJwks as never,
                storageAdapter: mockStorageAdapter,
            });

            const result = await handler.handle(MOCK_JWT_TOKEN);

            expect(openidMock.tokenIntrospection).toHaveBeenCalled();
            expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
        });
    });

    describe('forceIntrospection', () => {
        it('should skip JWT verification and go straight to introspection', async () => {
            const handler = buildHandler({
                storageAdapter: mockStorageAdapter,
            });

            const result = await handler.handle(MOCK_JWT_TOKEN, {
                forceIntrospection: true,
            });

            expect(joseMock.jwtVerify).not.toHaveBeenCalled();
            expect(openidMock.tokenIntrospection).toHaveBeenCalledWith(
                expect.any(Object),
                MOCK_JWT_TOKEN,
            );
            expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
        });

        it('should set lastIntrospection metadata when introspection is used', async () => {
            const handler = buildHandler({
                storageAdapter: mockStorageAdapter,
            });

            await handler.handle(MOCK_JWT_TOKEN, { forceIntrospection: true });

            const stored = mockStorageAdapter.storeUserCalls[0];
            expect(stored?.metadata.lastIntrospection).toBeInstanceOf(Date);
        });
    });

    describe('enableIntrospectionFallthrough', () => {
        it('should throw JwtVerificationError instead of falling back when disabled', async () => {
            joseMock.jwtVerify.mockRejectedValue(
                new JwtVerificationError('Invalid signature'),
            );
            const handler = buildHandler({
                enableIntrospectionFallthrough: false,
                storageAdapter: mockStorageAdapter,
            });

            await expect(handler.handle(MOCK_JWT_TOKEN)).rejects.toThrow(
                JwtVerificationError,
            );
            expect(openidMock.tokenIntrospection).not.toHaveBeenCalled();
        });

        it('should still allow forceIntrospection when fallthrough is disabled', async () => {
            const handler = buildHandler({
                enableIntrospectionFallthrough: false,
                storageAdapter: mockStorageAdapter,
            });

            const result = await handler.handle(MOCK_JWT_TOKEN, {
                forceIntrospection: true,
            });

            expect(openidMock.tokenIntrospection).toHaveBeenCalled();
            expect(joseMock.jwtVerify).not.toHaveBeenCalled();
            expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
        });
    });

    describe('beforeUserRetrieval strategy', () => {
        it('should fetch UserInfo before the storage lookup', async () => {
            const handler = buildHandler({
                storageAdapter: mockStorageAdapter,
                userInfoStrategy: 'beforeUserRetrieval',
                userInfoManager: new UserInfoManager({
                    clientConfig: createMockOpenidClient() as never,
                    logger: mockLogger,
                    throwOnUserInfoFailure: false,
                    userInfoStrategy: 'beforeUserRetrieval',
                    userInfoRefreshCondition: defaultUserInfoRefreshCondition,
                    storageAdapter: mockStorageAdapter,
                }),
            });

            await handler.handle(MOCK_JWT_TOKEN);

            expect(openidMock.fetchUserInfo).toHaveBeenCalledWith(
                expect.any(Object),
                MOCK_JWT_TOKEN,
                MOCK_USER_CLAIMS.sub,
            );

            const ctx = mockStorageAdapter.findUserCalls[0];
            expect(ctx?.userInfoResult).toEqual(MOCK_USERINFO_RESPONSE);
        });

        it('should not retry UserInfo fetch when the first attempt fails in beforeUserRetrieval', async () => {
            openidMock.fetchUserInfo.mockRejectedValueOnce(
                new Error('UserInfo failed'),
            );

            const handler = buildHandler({
                storageAdapter: mockStorageAdapter,
                logger: mockLogger,
                userInfoStrategy: 'beforeUserRetrieval',
                userInfoManager: new UserInfoManager({
                    clientConfig: createMockOpenidClient() as never,
                    logger: mockLogger,
                    throwOnUserInfoFailure: false,
                    userInfoStrategy: 'beforeUserRetrieval',
                    userInfoRefreshCondition: defaultUserInfoRefreshCondition,
                    storageAdapter: mockStorageAdapter,
                }),
            });

            await handler.handle(MOCK_JWT_TOKEN);

            expect(openidMock.fetchUserInfo).toHaveBeenCalledTimes(1);
        });

        it('should combine JWT and UserInfo claims with UserInfo taking priority', async () => {
            const jwtPayload = {
                ...MOCK_JWT_PAYLOAD,
                email: 'jwt@example.com',
                name: 'JWT Name',
            };
            joseMock.jwtVerify.mockResolvedValueOnce(
                createMockJwtVerifyResult(jwtPayload) as never,
            );

            const userInfoClaims = {
                sub: MOCK_USER_CLAIMS.sub,
                email: 'userinfo@example.com',
                name: 'UserInfo Name',
                phone: '+1234567890',
            };
            openidMock.fetchUserInfo.mockResolvedValueOnce(userInfoClaims);

            const handler = buildHandler({
                storageAdapter: mockStorageAdapter,
                userInfoStrategy: 'beforeUserRetrieval',
                userInfoManager: new UserInfoManager({
                    clientConfig: createMockOpenidClient() as never,
                    logger: mockLogger,
                    throwOnUserInfoFailure: false,
                    userInfoStrategy: 'beforeUserRetrieval',
                    userInfoRefreshCondition: defaultUserInfoRefreshCondition,
                    storageAdapter: mockStorageAdapter,
                }),
            });

            const result = await handler.handle(MOCK_JWT_TOKEN);

            expect(result['email']).toBe('userinfo@example.com');
            expect(result['name']).toBe('UserInfo Name');
            expect(result['phone']).toBe('+1234567890');
        });
    });
});
