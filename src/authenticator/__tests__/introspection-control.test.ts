import type { DefauthConfig, UserClaims } from '../../types/index.js';
import { beforeEach, describe, expect, it, jest } from '@jest/globals';

const {
    MOCK_INTROSPECTION_ACTIVE,
    MOCK_JWT_TOKEN,
    MockLogger,
    MockStorageAdapter,
    createMockConfig,
    createMockOpenidClient,
    setupModuleMocks,
} = await import('./test-utils.js');

const { joseMock, openidMock } = await setupModuleMocks();
const { Defauth } = await import('../defauth.js');
const { JwtVerificationError } = await import('../../types/index.js');

describe('Defauth - Introspection Fallthrough Control', () => {
    let mockStorageAdapter: InstanceType<typeof MockStorageAdapter<UserClaims>>;
    let mockConfig: DefauthConfig<UserClaims>;

    beforeEach(() => {
        jest.clearAllMocks();
        mockStorageAdapter = new MockStorageAdapter<UserClaims>();
        mockConfig = createMockConfig<UserClaims>({
            storageAdapter: mockStorageAdapter,
            logger: new MockLogger(),
        });

        openidMock.discovery.mockResolvedValue(
            createMockOpenidClient() as never,
        );
        joseMock.createRemoteJWKSet.mockReturnValue(jest.fn() as never);
        joseMock.decodeProtectedHeader.mockReturnValue({
            alg: 'RS256',
            typ: 'JWT',
        } as never);
        joseMock.decodeJwt.mockReturnValue({
            sub: 'user123',
        } as never);
        openidMock.tokenIntrospection.mockResolvedValue(
            MOCK_INTROSPECTION_ACTIVE as never,
        );
    });

    it('should fallback to introspection by default when JWT verification fails', async () => {
        const authenticator = await Defauth.create(mockConfig);
        joseMock.jwtVerify.mockRejectedValue(new Error('Invalid signature'));

        const result = await authenticator.getUser(MOCK_JWT_TOKEN);

        expect(openidMock.tokenIntrospection).toHaveBeenCalled();
        expect(result.sub).toBe('user123');
    });

    it('should throw error when disableIntrospectionFallthrough is true', async () => {
        const authenticator = await Defauth.create({
            ...mockConfig,
            disableIntrospectionFallthrough: true,
        });
        joseMock.jwtVerify.mockRejectedValue(
            new JwtVerificationError('Invalid signature'),
        );

        await expect(authenticator.getUser(MOCK_JWT_TOKEN)).rejects.toThrow(
            JwtVerificationError,
        );
        expect(openidMock.tokenIntrospection).not.toHaveBeenCalled();
    });

    it('should allow forced introspection even when fallthrough is disabled', async () => {
        const authenticator = await Defauth.create({
            ...mockConfig,
            disableIntrospectionFallthrough: true,
        });

        const result = await authenticator.getUser(MOCK_JWT_TOKEN, {
            forceIntrospection: true,
        });

        expect(openidMock.tokenIntrospection).toHaveBeenCalled();
        expect(joseMock.jwtVerify).not.toHaveBeenCalled();
        expect(result.sub).toBe('user123');
    });
});
