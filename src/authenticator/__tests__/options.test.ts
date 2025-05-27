import {
    afterEach,
    beforeEach,
    describe,
    expect,
    it,
    jest,
} from '@jest/globals';
import type { UserRecord } from '../../types/index.js';

// Mock external dependencies using ESM mocking
jest.unstable_mockModule('jose', () => ({
    jwtVerify: jest.fn(),
    createRemoteJWKSet: jest.fn(),
}));

jest.unstable_mockModule('openid-client', () => ({
    discovery: jest.fn(),
    tokenIntrospection: jest.fn(),
    fetchUserInfo: jest.fn(),
}));

// Import modules after mocking
const { Authenticator } = await import('../authenticator.js');

// Type alias for the authenticated Authenticator with UserRecord
type UserRecordAuthenticator = InstanceType<typeof Authenticator<UserRecord>>;
const {
    MOCK_INTROSPECTION_ACTIVE,
    MOCK_JWT_TOKEN,
    MOCK_USERINFO_RESPONSE,
    MOCK_USER_CLAIMS,
    MockLogger,
    MockStorageAdapter,
    createMockConfig,
    createMockJwtVerifyResult,
    createMockOpenidClient,
    waitForAsync,
} = await import('./test-utils.js');

// Get mocked modules
const joseMock = jest.mocked(await import('jose'));
const openidMock = jest.mocked(await import('openid-client'));

describe('Authenticator - Configuration Options and Validation', () => {
    let mockStorageAdapter: InstanceType<typeof MockStorageAdapter>;
    let mockLogger: InstanceType<typeof MockLogger>;

    beforeEach(() => {
        jest.clearAllMocks();
        mockStorageAdapter = new MockStorageAdapter();
        mockLogger = new MockLogger();

        // Setup default mocks
        openidMock.discovery.mockResolvedValue(
            createMockOpenidClient() as never,
        );
        joseMock.createRemoteJWKSet.mockReturnValue(jest.fn() as never);
        joseMock.jwtVerify.mockResolvedValue(
            createMockJwtVerifyResult() as never,
        );
        openidMock.tokenIntrospection.mockResolvedValue(
            MOCK_INTROSPECTION_ACTIVE as never,
        );
        openidMock.fetchUserInfo.mockResolvedValue(
            MOCK_USERINFO_RESPONSE as never,
        );
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    describe('JWT Validation Options', () => {
        let authenticator: UserRecordAuthenticator;

        beforeEach(async () => {
            // Create authenticator with custom global JWT validation options
            const configWithJwtOptions = createMockConfig({
                storageAdapter: mockStorageAdapter,
                logger: mockLogger,
                jwtValidationOptions: {
                    requiredClaims: ['sub', 'exp', 'aud'],
                    clockTolerance: '2 minutes',
                },
            });
            authenticator = new Authenticator(configWithJwtOptions);
            await waitForAsync();
        });

        it('should use global JWT validation options by default', async () => {
            await authenticator.getUser(MOCK_JWT_TOKEN);

            expect(joseMock.jwtVerify).toHaveBeenCalledWith(
                MOCK_JWT_TOKEN,
                expect.any(Function),
                expect.objectContaining({
                    clockTolerance: '2 minutes',
                    requiredClaims: ['sub', 'exp', 'aud'],
                }),
            );
        });

        it('should allow per-call options to override global options', async () => {
            await authenticator.getUser(MOCK_JWT_TOKEN, {
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

        it('should merge global and per-call options correctly', async () => {
            await authenticator.getUser(MOCK_JWT_TOKEN, {
                requiredClaims: ['sub', 'custom_claim'],
                // clockTolerance should inherit from global
            });

            expect(joseMock.jwtVerify).toHaveBeenCalledWith(
                MOCK_JWT_TOKEN,
                expect.any(Function),
                expect.objectContaining({
                    clockTolerance: '2 minutes', // From global
                    requiredClaims: ['sub', 'custom_claim'], // From per-call
                }),
            );
        });

        it('should force introspection when requested in per-call options', async () => {
            const result = await authenticator.getUser(MOCK_JWT_TOKEN, {
                forceIntrospection: true,
            });

            expect(openidMock.tokenIntrospection).toHaveBeenCalledWith(
                expect.any(Object),
                MOCK_JWT_TOKEN,
            );
            expect(joseMock.jwtVerify).not.toHaveBeenCalled();
            expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
        });

        it('should automatically fallback to introspection on JWT verification failure', async () => {
            const jwtError = new Error('JWT verification failed');
            joseMock.jwtVerify.mockRejectedValueOnce(jwtError);

            const result = await authenticator.getUser(MOCK_JWT_TOKEN);

            // Should first try JWT verification, then fallback to introspection
            expect(joseMock.jwtVerify).toHaveBeenCalledTimes(1);
            expect(openidMock.tokenIntrospection).toHaveBeenCalledWith(
                expect.any(Object),
                MOCK_JWT_TOKEN,
            );
            expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);

            // Should log the fallback
            const warningLogs = mockLogger.getLogsForLevel('warn');
            expect(warningLogs).toHaveLength(1);
            expect(warningLogs[0]?.message).toContain(
                'JWT verification failed, falling back to introspection',
            );
        });

        it('should handle JWT expired error gracefully with fallback', async () => {
            const expiredError = new Error('Token has expired');
            joseMock.jwtVerify.mockRejectedValueOnce(expiredError);

            const result = await authenticator.getUser(MOCK_JWT_TOKEN);

            expect(openidMock.tokenIntrospection).toHaveBeenCalledWith(
                expect.any(Object),
                MOCK_JWT_TOKEN,
            );
            expect(result.sub).toBe(MOCK_USER_CLAIMS.sub);
        });

        it('should create correct TokenContext for JWT validation result', async () => {
            await authenticator.getUser(MOCK_JWT_TOKEN);

            expect(mockStorageAdapter.findUserCalls).toHaveLength(1);
            const tokenContext = mockStorageAdapter.findUserCalls[0];
            expect(tokenContext).toBeDefined();
            if (tokenContext) {
                expect(tokenContext.jwtPayload).toBeDefined();
                expect(tokenContext.sub).toBe(MOCK_USER_CLAIMS.sub);
                expect(tokenContext.metadata?.validatedAt).toBeGreaterThan(0);
                expect(tokenContext.jwtPayload).toBeDefined();
            }
        });

        it('should create correct TokenContext for introspection fallback result', async () => {
            joseMock.jwtVerify.mockRejectedValueOnce(new Error('JWT failed'));

            await authenticator.getUser(MOCK_JWT_TOKEN);

            expect(mockStorageAdapter.findUserCalls).toHaveLength(1);
            const tokenContext = mockStorageAdapter.findUserCalls[0];
            expect(tokenContext).toBeDefined();
            if (tokenContext) {
                expect(tokenContext.introspectionResponse).toBeDefined();
                expect(tokenContext.sub).toBe(MOCK_USER_CLAIMS.sub);
                expect(tokenContext.metadata?.validatedAt).toBeGreaterThan(0);
                expect(tokenContext.introspectionResponse).toBeDefined();
                expect(tokenContext.metadata?.forcedIntrospection).toBe(true);
            }
        });

        it('should use static metadata claims constants for filtering', async () => {
            // Mock a JWT payload with metadata claims that should be filtered out
            const payloadWithMetadata = {
                sub: 'user123',
                name: 'Test User',
                client_id: 'test-client',
                scope: 'openid profile',
                token_type: 'Bearer',
                nbf: 1234567890,
                jti: 'jwt-id-123',
                custom_claim: 'should-be-kept',
            };

            joseMock.jwtVerify.mockResolvedValueOnce({
                payload: payloadWithMetadata,
                protectedHeader: { alg: 'RS256', typ: 'JWT' },
            } as any);

            // Set cached user to prevent UserInfo refresh that would change the name
            const cachedUser = {
                sub: 'user123',
                name: 'Test User',
                lastUserInfoRefresh: Date.now(), // Fresh to prevent refresh
                lastIntrospection: Date.now(),
            };
            mockStorageAdapter.setUser(cachedUser);

            const result = await authenticator.getUser(MOCK_JWT_TOKEN);

            // Should keep user claims but filter out JWT metadata claims
            expect(result.sub).toBe('user123');
            expect(result['name']).toBe('Test User');
            expect(result['custom_claim']).toBe('should-be-kept');
            expect(result['client_id']).toBeUndefined();
            expect(result['scope']).toBeUndefined();
            expect(result['token_type']).toBeUndefined();
            expect(result['nbf']).toBeUndefined();
            expect(result['jti']).toBeUndefined();
        });
    });

    describe('Default JWT Validation Options', () => {
        let defaultAuthenticator: UserRecordAuthenticator;

        beforeEach(async () => {
            // Create authenticator without custom JWT validation options
            const defaultConfig = createMockConfig({
                storageAdapter: mockStorageAdapter,
                logger: mockLogger,
            });
            defaultAuthenticator = new Authenticator(defaultConfig);
            await waitForAsync();
        });

        it('should use default JWT validation options when none are provided', async () => {
            await defaultAuthenticator.getUser(MOCK_JWT_TOKEN);

            expect(joseMock.jwtVerify).toHaveBeenCalledWith(
                MOCK_JWT_TOKEN,
                expect.any(Function),
                expect.objectContaining({
                    clockTolerance: '1 minute',
                    requiredClaims: ['sub', 'exp'],
                }),
            );
        });

        it('should allow per-call options to override defaults', async () => {
            await defaultAuthenticator.getUser(MOCK_JWT_TOKEN, {
                clockTolerance: '5 minutes',
                requiredClaims: ['sub', 'aud', 'iss'],
            });

            expect(joseMock.jwtVerify).toHaveBeenCalledWith(
                MOCK_JWT_TOKEN,
                expect.any(Function),
                expect.objectContaining({
                    clockTolerance: '5 minutes',
                    requiredClaims: ['sub', 'aud', 'iss'],
                }),
            );
        });
    });
});
