import * as openid from 'openid-client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CustomValidationError, UserInfoError } from '../../errors.js';
import type { StorageMetadata, UserClaims } from '../../types/index.js';
import { defaultUserInfoRefreshCondition } from '../../utils/index.js';
import { UserInfoManager } from '../user-info-manager.js';
import {
    MOCK_INTROSPECTION_ACTIVE,
    MOCK_JWT_TOKEN,
    MOCK_OPAQUE_TOKEN,
    MOCK_USER_CLAIMS,
    MOCK_USERINFO_RESPONSE,
    MockLogger,
    MockStorageAdapter,
    createMockOpenidClient,
} from './test-utils.js';

const openidMock = vi.mocked(openid);

function buildManager(
    overrides: Partial<
        ConstructorParameters<typeof UserInfoManager<UserClaims>>[0]
    > = {},
) {
    const storageAdapter =
        overrides.storageAdapter ?? new MockStorageAdapter<UserClaims>();
    const logger = overrides.logger ?? new MockLogger();
    const clientConfig = createMockOpenidClient() as never;

    return new UserInfoManager<UserClaims>({
        clientConfig,
        logger,
        throwOnUserInfoFailure: false,
        userInfoStrategy: 'afterUserRetrieval',
        userInfoRefreshCondition: defaultUserInfoRefreshCondition,
        storageAdapter,
        ...overrides,
    });
}

describe('UserInfoManager', () => {
    let mockStorageAdapter: MockStorageAdapter<UserClaims>;
    let mockLogger: MockLogger;

    beforeEach(() => {
        vi.clearAllMocks();
        mockStorageAdapter = new MockStorageAdapter<UserClaims>();
        mockLogger = new MockLogger();

        openidMock.fetchUserInfo.mockResolvedValue(
            MOCK_USERINFO_RESPONSE as never,
        );
        openidMock.tokenIntrospection.mockResolvedValue(
            MOCK_INTROSPECTION_ACTIVE as never,
        );
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe('shouldRefresh', () => {
        it('should return true when userRecord is null', () => {
            const manager = buildManager();

            expect(manager.shouldRefresh(null, {})).toBe(true);
        });

        it('should return true when lastUserInfoRefresh is not set', () => {
            const manager = buildManager();

            expect(
                manager.shouldRefresh(MOCK_USER_CLAIMS as UserClaims, {}),
            ).toBe(true);
        });

        it('should return true when refresh condition returns true', () => {
            const manager = buildManager({
                userInfoRefreshCondition: () => true,
            });
            const metadata: StorageMetadata = {
                lastUserInfoRefresh: new Date(),
            };

            expect(
                manager.shouldRefresh(MOCK_USER_CLAIMS as UserClaims, metadata),
            ).toBe(true);
        });

        it('should return false when refresh condition returns false', () => {
            const manager = buildManager({
                userInfoRefreshCondition: () => false,
            });
            const metadata: StorageMetadata = {
                lastUserInfoRefresh: new Date(Date.now() - 30 * 60_000),
            };

            expect(
                manager.shouldRefresh(MOCK_USER_CLAIMS as UserClaims, metadata),
            ).toBe(false);
        });

        it('should use defaultUserInfoRefreshCondition for stale data', () => {
            const manager = buildManager();
            const metadata: StorageMetadata = {
                lastUserInfoRefresh: new Date(Date.now() - 2 * 60 * 60_000),
            };

            expect(
                manager.shouldRefresh(MOCK_USER_CLAIMS as UserClaims, metadata),
            ).toBe(true);
        });

        it('should return false for fresh data with default condition', () => {
            const manager = buildManager();
            const metadata: StorageMetadata = {
                lastUserInfoRefresh: new Date(Date.now() - 30 * 60_000),
            };

            expect(
                manager.shouldRefresh(MOCK_USER_CLAIMS as UserClaims, metadata),
            ).toBe(false);
        });
    });

    describe('tryFetchUserInfo', () => {
        it('should return UserClaims on success', async () => {
            const manager = buildManager({
                storageAdapter: mockStorageAdapter,
            });

            const result = await manager.tryFetchUserInfo(
                MOCK_JWT_TOKEN,
                MOCK_USER_CLAIMS.sub,
            );

            expect(result).not.toBeNull();
            expect(result?.sub).toBe(MOCK_USER_CLAIMS.sub);
            expect(result?.['name']).toBe(MOCK_USERINFO_RESPONSE.name);
            expect(openidMock.fetchUserInfo).toHaveBeenCalledWith(
                expect.any(Object),
                MOCK_JWT_TOKEN,
                MOCK_USER_CLAIMS.sub,
            );
        });

        it('should throw UserInfoError when the UserInfo endpoint is missing', async () => {
            const clientWithoutUserInfo = {
                serverMetadata: vi.fn().mockReturnValue({}),
            };
            const manager = buildManager({
                clientConfig: clientWithoutUserInfo as never,
                throwOnUserInfoFailure: true,
            });

            await expect(
                manager.tryFetchUserInfo(MOCK_JWT_TOKEN, MOCK_USER_CLAIMS.sub),
            ).rejects.toThrow(UserInfoError);
        });

        it('should throw UserInfoError when the network request fails', async () => {
            openidMock.fetchUserInfo.mockRejectedValueOnce(
                new Error('Network error'),
            );
            const manager = buildManager({ throwOnUserInfoFailure: true });

            await expect(
                manager.tryFetchUserInfo(MOCK_JWT_TOKEN, MOCK_USER_CLAIMS.sub),
            ).rejects.toThrow(UserInfoError);
        });

        it('should return null and log a warning when throwOnUserInfoFailure is false', async () => {
            openidMock.fetchUserInfo.mockRejectedValueOnce(
                new Error('fetch failed'),
            );
            const manager = buildManager({
                logger: mockLogger,
                throwOnUserInfoFailure: false,
            });

            const result = await manager.tryFetchUserInfo(
                MOCK_JWT_TOKEN,
                MOCK_USER_CLAIMS.sub,
            );

            expect(result).toBeNull();
            const warnings = mockLogger.getLogsForLevel('warn');
            expect(warnings).toHaveLength(1);
            expect(warnings[0]?.message).toContain('Failed to fetch UserInfo');
        });

        it('should throw UserInfoError when throwOnUserInfoFailure is true', async () => {
            openidMock.fetchUserInfo.mockRejectedValueOnce(
                new Error('fetch failed'),
            );
            const manager = buildManager({ throwOnUserInfoFailure: true });

            await expect(
                manager.tryFetchUserInfo(MOCK_JWT_TOKEN, MOCK_USER_CLAIMS.sub),
            ).rejects.toThrow(UserInfoError);
        });
    });

    describe('processUserClaims', () => {
        describe('afterUserRetrieval strategy', () => {
            it('should fetch UserInfo and store updated user', async () => {
                const manager = buildManager({
                    storageAdapter: mockStorageAdapter,
                });

                const result = await manager.processUserClaims(
                    MOCK_JWT_TOKEN,
                    MOCK_USER_CLAIMS,
                    {
                        tokenType: 'jwt',
                        userRecord: null,
                        userMetadata: {},
                    },
                );

                expect(openidMock.fetchUserInfo).toHaveBeenCalled();
                expect(result['name']).toBe(MOCK_USERINFO_RESPONSE.name);
                expect(mockStorageAdapter.storeUserCalls).toHaveLength(1);
            });

            it('should skip UserInfo fetch when user is cached and fresh', async () => {
                const recentUser = {
                    sub: MOCK_USER_CLAIMS.sub,
                    name: 'Cached',
                };
                mockStorageAdapter.setUser(recentUser, {
                    lastUserInfoRefresh: new Date(Date.now() - 30 * 60_000),
                });

                const manager = buildManager({
                    storageAdapter: mockStorageAdapter,
                    userInfoRefreshCondition: () => false,
                });

                await manager.processUserClaims(
                    MOCK_JWT_TOKEN,
                    MOCK_USER_CLAIMS,
                    {
                        tokenType: 'jwt',
                        userRecord: recentUser,
                        userMetadata: {
                            lastUserInfoRefresh: new Date(
                                Date.now() - 30 * 60_000,
                            ),
                        },
                    },
                );

                expect(openidMock.fetchUserInfo).not.toHaveBeenCalled();
            });

            it('should handle UserInfo fetch failure gracefully', async () => {
                openidMock.fetchUserInfo.mockRejectedValue(
                    new Error('UserInfo failed'),
                );
                const manager = buildManager({
                    storageAdapter: mockStorageAdapter,
                    logger: mockLogger,
                });

                const result = await manager.processUserClaims(
                    MOCK_JWT_TOKEN,
                    MOCK_USER_CLAIMS,
                    { tokenType: 'jwt', userRecord: null, userMetadata: {} },
                );

                expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
                expect(mockLogger.getLogsForLevel('warn')).toHaveLength(1);
            });

            it('should throw when throwOnUserInfoFailure is true', async () => {
                openidMock.fetchUserInfo.mockRejectedValue(
                    new Error('UserInfo failed'),
                );
                const manager = buildManager({
                    storageAdapter: mockStorageAdapter,
                    throwOnUserInfoFailure: true,
                });

                await expect(
                    manager.processUserClaims(
                        MOCK_JWT_TOKEN,
                        MOCK_USER_CLAIMS,
                        {
                            tokenType: 'jwt',
                            userRecord: null,
                            userMetadata: {},
                        },
                    ),
                ).rejects.toThrow('Failed to fetch user info');
            });

            it('should set lastUserInfoRefresh after successful fetch', async () => {
                const startTime = new Date();
                const manager = buildManager({
                    storageAdapter: mockStorageAdapter,
                });

                await manager.processUserClaims(
                    MOCK_JWT_TOKEN,
                    MOCK_USER_CLAIMS,
                    {
                        tokenType: 'jwt',
                        userRecord: null,
                        userMetadata: {},
                    },
                );

                const stored = mockStorageAdapter.storeUserCalls[0];
                expect(stored?.metadata.lastUserInfoRefresh).toBeInstanceOf(
                    Date,
                );
                expect(
                    stored?.metadata.lastUserInfoRefresh!.getTime(),
                ).toBeGreaterThanOrEqual(startTime.getTime());
            });
        });

        describe('none strategy', () => {
            it('should not fetch UserInfo when strategy is none', async () => {
                const manager = buildManager({
                    storageAdapter: mockStorageAdapter,
                    userInfoStrategy: 'none',
                });

                await manager.processUserClaims(
                    MOCK_JWT_TOKEN,
                    MOCK_USER_CLAIMS,
                    {
                        tokenType: 'jwt',
                        userRecord: null,
                        userMetadata: {},
                    },
                );

                expect(openidMock.fetchUserInfo).not.toHaveBeenCalled();
            });
        });

        describe('userInfoAlreadyFetched', () => {
            it('should skip afterUserRetrieval fetch when already fetched', async () => {
                const manager = buildManager({
                    storageAdapter: mockStorageAdapter,
                });

                await manager.processUserClaims(
                    MOCK_JWT_TOKEN,
                    MOCK_USER_CLAIMS,
                    {
                        tokenType: 'jwt',
                        userRecord: null,
                        userMetadata: {},
                        userInfoAlreadyFetched: true,
                    },
                );

                expect(openidMock.fetchUserInfo).not.toHaveBeenCalled();
            });

            it('should still set lastUserInfoRefresh when already fetched', async () => {
                const manager = buildManager({
                    storageAdapter: mockStorageAdapter,
                });
                const startTime = new Date();

                await manager.processUserClaims(
                    MOCK_JWT_TOKEN,
                    MOCK_USER_CLAIMS,
                    {
                        tokenType: 'jwt',
                        userRecord: null,
                        userMetadata: {},
                        userInfoAlreadyFetched: true,
                    },
                );

                const stored = mockStorageAdapter.storeUserCalls[0];
                expect(
                    stored?.metadata.lastUserInfoRefresh!.getTime(),
                ).toBeGreaterThanOrEqual(startTime.getTime());
            });
        });

        describe('custom validation', () => {
            it('should run customValidator on the final claims', async () => {
                const validator = vi.fn().mockResolvedValue(null);
                const manager = buildManager({
                    storageAdapter: mockStorageAdapter,
                });

                await manager.processUserClaims(
                    MOCK_JWT_TOKEN,
                    MOCK_USER_CLAIMS,
                    {
                        tokenType: 'jwt',
                        userRecord: null,
                        userMetadata: {},
                        customValidator: validator,
                    },
                );

                expect(validator).toHaveBeenCalledTimes(1);
            });

            it('should throw CustomValidationError when validator throws', async () => {
                const manager = buildManager({
                    storageAdapter: mockStorageAdapter,
                });

                await expect(
                    manager.processUserClaims(
                        MOCK_JWT_TOKEN,
                        MOCK_USER_CLAIMS,
                        {
                            tokenType: 'jwt',
                            userRecord: null,
                            userMetadata: {},
                            customValidator: async () => {
                                throw new Error('Validation failed');
                            },
                        },
                    ),
                ).rejects.toThrow(CustomValidationError);
            });

            it('should not store user when customValidator throws', async () => {
                const manager = buildManager({
                    storageAdapter: mockStorageAdapter,
                });

                await expect(
                    manager.processUserClaims(
                        MOCK_JWT_TOKEN,
                        MOCK_USER_CLAIMS,
                        {
                            tokenType: 'jwt',
                            userRecord: null,
                            userMetadata: {},
                            customValidator: async () => {
                                throw new Error('Validation failed');
                            },
                        },
                    ),
                ).rejects.toThrow(CustomValidationError);

                expect(mockStorageAdapter.storeUserCalls).toHaveLength(0);
            });

            it('should validate with opaque tokens', async () => {
                const manager = buildManager({
                    storageAdapter: mockStorageAdapter,
                });

                await expect(
                    manager.processUserClaims(
                        MOCK_OPAQUE_TOKEN,
                        MOCK_USER_CLAIMS,
                        {
                            tokenType: 'opaque',
                            userRecord: null,
                            userMetadata: {},
                            customValidator: async () => {
                                throw new Error('Validation failed');
                            },
                        },
                    ),
                ).rejects.toThrow(CustomValidationError);
            });

            it('should validate claim values', async () => {
                const manager = buildManager({
                    storageAdapter: mockStorageAdapter,
                });
                const claims: UserClaims = {
                    ...MOCK_USER_CLAIMS,
                    organizationId: 'org-123',
                };
                openidMock.fetchUserInfo.mockResolvedValueOnce(claims as never);

                const result = await manager.processUserClaims(
                    MOCK_JWT_TOKEN,
                    claims,
                    {
                        tokenType: 'jwt',
                        userRecord: null,
                        userMetadata: {},
                        customValidator: async (c) => {
                            if (c['organizationId'] !== 'org-123') {
                                throw new Error('Organization mismatch');
                            }
                        },
                    },
                );

                expect(result['organizationId']).toBe('org-123');
            });
        });
    });
});
