import type { DefauthConfig, UserClaims } from '../../types/index.js';
import { beforeEach, describe, expect, it, jest } from '@jest/globals';

const {
    MOCK_INTROSPECTION_ACTIVE,
    MOCK_JWT_TOKEN,
    MOCK_OPAQUE_TOKEN,
    MockStorageAdapter,
    createMockConfig,
    createMockJwtVerifyResult,
    createMockOpenidClient,
    setupModuleMocks,
} = await import('./test-utils.js');

const { joseMock, openidMock } = await setupModuleMocks();
const { Defauth } = await import('../defauth.js');
const { CustomValidationError } = await import('../../types/index.js');

describe('Defauth - Custom Validation', () => {
    let mockStorageAdapter: InstanceType<typeof MockStorageAdapter<UserClaims>>;
    let mockConfig: DefauthConfig<UserClaims>;

    beforeEach(() => {
        jest.clearAllMocks();
        mockStorageAdapter = new MockStorageAdapter<UserClaims>();
        mockConfig = createMockConfig<UserClaims>({
            storageAdapter: mockStorageAdapter,
        });

        openidMock.discovery.mockResolvedValue(
            createMockOpenidClient() as never,
        );
        joseMock.createRemoteJWKSet.mockReturnValue(jest.fn() as never);
        joseMock.jwtVerify.mockResolvedValue({
            ...createMockJwtVerifyResult(),
            payload: {
                ...createMockJwtVerifyResult().payload,
                organizationId: 'org-123',
            },
        } as never);
        joseMock.decodeProtectedHeader.mockReturnValue({
            alg: 'RS256',
            typ: 'JWT',
        } as never);
        joseMock.decodeJwt.mockReturnValue({
            sub: 'user123',
            organizationId: 'org-123',
        } as never);
        openidMock.tokenIntrospection.mockResolvedValue({
            ...MOCK_INTROSPECTION_ACTIVE,
            organizationId: 'org-123',
        } as never);
    });

    it('should throw CustomValidationError when validation fails', async () => {
        const authenticator = await Defauth.create(mockConfig);

        await expect(
            authenticator.getUser(MOCK_JWT_TOKEN, {
                customValidator: async () => {
                    throw new Error('Validation failed');
                },
            }),
        ).rejects.toThrow(CustomValidationError);
    });

    it('should validate custom claim values (e.g., organizationId)', async () => {
        const authenticator = await Defauth.create(mockConfig);
        const requestOrgId = 'org-123';

        const result = await authenticator.getUser(MOCK_JWT_TOKEN, {
            customValidator: async (claims) => {
                if (claims['organizationId'] !== requestOrgId) {
                    throw new Error('Organization mismatch');
                }
            },
        });

        expect(result['organizationId']).toBe(requestOrgId);
    });

    it('should work with opaque tokens', async () => {
        const authenticator = await Defauth.create(mockConfig);

        await expect(
            authenticator.getUser(MOCK_OPAQUE_TOKEN, {
                customValidator: async () => {
                    throw new Error('Validation failed');
                },
            }),
        ).rejects.toThrow(CustomValidationError);
    });

    it('should not store user if validation fails', async () => {
        const authenticator = await Defauth.create(mockConfig);

        await expect(
            authenticator.getUser(MOCK_JWT_TOKEN, {
                customValidator: async () => {
                    throw new Error('Validation failed');
                },
            }),
        ).rejects.toThrow(CustomValidationError);

        expect(mockStorageAdapter.storeUserCalls).toHaveLength(0);
    });
});
