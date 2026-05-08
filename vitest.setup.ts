import { vi } from 'vitest';

vi.mock('jose', () => ({
    jwtVerify: vi.fn(),
    createRemoteJWKSet: vi.fn(),
    decodeProtectedHeader: vi.fn(),
    decodeJwt: vi.fn(),
}));

vi.mock('openid-client', () => ({
    discovery: vi.fn(),
    tokenIntrospection: vi.fn(),
    fetchUserInfo: vi.fn(),
    allowInsecureRequests: vi.fn(),
    ClientSecretPost: vi.fn(() => vi.fn()),
    ClientSecretBasic: vi.fn(() => vi.fn()),
    ClientSecretJwt: vi.fn(() => vi.fn()),
    None: vi.fn(() => vi.fn()),
}));
