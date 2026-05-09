import * as openid from 'openid-client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { UserClaims } from '../../types/index.js';
import { defaultUserInfoRefreshCondition } from '../../utils/index.js';
import { OpaqueHandler } from '../opaque-handler.js';
import { UserInfoManager } from '../user-info-manager.js';
import {
    MOCK_INTROSPECTION_ACTIVE,
    MOCK_INTROSPECTION_INACTIVE,
    MOCK_OPAQUE_TOKEN,
    MOCK_USER_CLAIMS,
    MOCK_USERINFO_RESPONSE,
    MockLogger,
    MockStorageAdapter,
    createMockOpenidClient,
} from './test-utils.js';

const openidMock = vi.mocked(openid);

function buildHandler(
    overrides: Partial<
        ConstructorParameters<typeof OpaqueHandler<UserClaims>>[0]
    > & {
        logger?: MockLogger;
    } = {},
) {
    const storageAdapter =
        overrides.storageAdapter ?? new MockStorageAdapter<UserClaims>();
    const logger = overrides.logger ?? new MockLogger();
    const clientConfig =
        overrides.clientConfig ?? (createMockOpenidClient() as never);

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

    return new OpaqueHandler<UserClaims>({
        clientConfig,
        userInfoManager,
        storageAdapter,
        userInfoStrategy: 'afterUserRetrieval',
        ...overrides,
    });
}

describe('OpaqueHandler', () => {
    let mockStorageAdapter: MockStorageAdapter<UserClaims>;
    let mockLogger: MockLogger;

    beforeEach(() => {
        vi.clearAllMocks();
        mockStorageAdapter = new MockStorageAdapter<UserClaims>();
        mockLogger = new MockLogger();

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

    describe('successful opaque token handling', () => {
        it('should introspect and return user', async () => {
            const handler = buildHandler({
                storageAdapter: mockStorageAdapter,
            });

            const result = await handler.handle(MOCK_OPAQUE_TOKEN);

            expect(openidMock.tokenIntrospection).toHaveBeenCalledWith(
                expect.any(Object),
                MOCK_OPAQUE_TOKEN,
            );
            expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
        });

        it('should set lastIntrospection metadata', async () => {
            const startTime = new Date();
            const handler = buildHandler({
                storageAdapter: mockStorageAdapter,
            });

            await handler.handle(MOCK_OPAQUE_TOKEN);

            const stored = mockStorageAdapter.storeUserCalls[0];
            expect(stored?.metadata.lastIntrospection).toBeInstanceOf(Date);
            expect(
                stored?.metadata.lastIntrospection!.getTime(),
            ).toBeGreaterThanOrEqual(startTime.getTime());
        });

        it('should set lastIntrospection even when existing metadata is present', async () => {
            const existingUser = {
                sub: MOCK_USER_CLAIMS.sub,
                name: 'Existing',
            };
            mockStorageAdapter.setUser(existingUser, {
                lastIntrospection: new Date(Date.now() - 10 * 60_000),
                lastUserInfoRefresh: new Date(Date.now() - 2 * 60 * 60_000),
            });

            const startTime = new Date();
            const handler = buildHandler({
                storageAdapter: mockStorageAdapter,
            });

            await handler.handle(MOCK_OPAQUE_TOKEN);

            const stored = mockStorageAdapter.storeUserCalls[0];
            expect(
                stored?.metadata.lastIntrospection!.getTime(),
            ).toBeGreaterThanOrEqual(startTime.getTime());
        });

        it('should build a correct TokenContext with introspectionResponse', async () => {
            const handler = buildHandler({
                storageAdapter: mockStorageAdapter,
            });

            await handler.handle(MOCK_OPAQUE_TOKEN);

            const ctx = mockStorageAdapter.findUserCalls[0];
            expect(ctx?.introspectionResponse).toBeDefined();
            expect(ctx?.sub).toBe(MOCK_USER_CLAIMS.sub);
            expect(ctx?.metadata?.validatedAt).toBeInstanceOf(Date);
        });

        it('should filter introspection metadata claims', async () => {
            const handler = buildHandler({
                storageAdapter: mockStorageAdapter,
            });

            await handler.handle(MOCK_OPAQUE_TOKEN);

            const stored = mockStorageAdapter.storeUserCalls[0];
            expect(stored?.claims['active']).toBeUndefined();
            expect(stored?.claims['client_id']).toBeUndefined();
            expect(stored?.claims['scope']).toBeUndefined();
        });
    });

    describe('inactive token', () => {
        it('should throw TokenValidationError for inactive token', async () => {
            openidMock.tokenIntrospection.mockResolvedValue(
                MOCK_INTROSPECTION_INACTIVE as never,
            );
            const handler = buildHandler();

            await expect(handler.handle(MOCK_OPAQUE_TOKEN)).rejects.toThrow(
                'Token is not active',
            );
        });
    });

    describe('introspection failure', () => {
        it('should throw IntrospectionError when introspection fails', async () => {
            openidMock.tokenIntrospection.mockRejectedValue(
                new Error('Network error'),
            );
            const handler = buildHandler();

            await expect(handler.handle(MOCK_OPAQUE_TOKEN)).rejects.toThrow(
                'Failed to introspect token',
            );
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

            const result = await handler.handle(MOCK_OPAQUE_TOKEN);

            expect(openidMock.fetchUserInfo).toHaveBeenCalledWith(
                expect.any(Object),
                MOCK_OPAQUE_TOKEN,
                MOCK_USER_CLAIMS.sub,
            );
            expect(result['name']).toBe(MOCK_USERINFO_RESPONSE.name);

            const ctx = mockStorageAdapter.findUserCalls[0];
            expect(ctx?.userInfoResult).toEqual(MOCK_USERINFO_RESPONSE);
            expect(ctx?.introspectionResponse).toBeDefined();
        });

        it('should continue gracefully when UserInfo fails in beforeUserRetrieval', async () => {
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

            const result = await handler.handle(MOCK_OPAQUE_TOKEN);

            expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);

            const ctx = mockStorageAdapter.findUserCalls[0];
            expect(ctx?.userInfoResult).toBeUndefined();
        });
    });
});
