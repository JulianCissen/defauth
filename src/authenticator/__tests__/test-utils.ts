import type {
    DefauthConfig,
    IntrospectionResponse,
    Logger,
    StorageAdapter,
    StorageMetadata,
    TokenContext,
    UserClaims,
} from '../../types/index.js';
import { jest } from '@jest/globals';

/**
 * Mock OIDC endpoints and responses for testing
 */
export const MOCK_ISSUER = 'https://mock-oidc-provider.com';
export const MOCK_CLIENT_ID = 'test-client-id';
export const MOCK_CLIENT_SECRET = 'test-client-secret';

/**
 * Mock JWT token (properly formatted but not real)
 */
export const MOCK_JWT_TOKEN =
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwibmFtZSI6IlRlc3QgVXNlciIsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSIsImlhdCI6MTYzMDAwMDAwMCwiZXhwIjo5OTk5OTk5OTk5LCJhdWQiOiJ0ZXN0LWNsaWVudC1pZCIsImlzcyI6Imh0dHBzOi8vbW9jay1vaWRjLXByb3ZpZGVyLmNvbSJ9.signature';

/**
 * Mock opaque token
 */
export const MOCK_OPAQUE_TOKEN = 'opaque-token-12345';

/**
 * Mock user claims
 */
export const MOCK_USER_CLAIMS: UserClaims = {
    sub: 'user123',
    name: 'Test User',
    email: 'test@example.com',
    preferred_username: 'testuser',
};

/**
 * Mock user metadata with timestamps
 */
export const MOCK_USER_METADATA: StorageMetadata = {
    lastUserInfoRefresh: new Date(Date.now() - 30 * 60 * 1000), // 30 minutes ago
    lastIntrospection: new Date(Date.now() - 5 * 60 * 1000), // 5 minutes ago
};

/**
 * Mock introspection response for active token
 */
export const MOCK_INTROSPECTION_ACTIVE: IntrospectionResponse = {
    active: true,
    sub: 'user123',
    name: 'Test User',
    email: 'test@example.com',
    preferred_username: 'testuser',
    client_id: MOCK_CLIENT_ID,
    scope: 'openid profile email',
    exp: 9999999999,
    iat: 1630000000,
};

/**
 * Mock introspection response for inactive token
 */
export const MOCK_INTROSPECTION_INACTIVE: IntrospectionResponse = {
    active: false,
};

/**
 * Mock JWT payload
 */
export const MOCK_JWT_PAYLOAD = {
    sub: 'user123',
    name: 'Test User',
    email: 'test@example.com',
    preferred_username: 'testuser',
    aud: MOCK_CLIENT_ID,
    iss: MOCK_ISSUER,
    exp: 9999999999,
    iat: 1630000000,
    client_id: MOCK_CLIENT_ID,
    scope: 'openid profile email',
    jti: 'token-id-123',
};

/**
 * Mock UserInfo response
 */
export const MOCK_USERINFO_RESPONSE = {
    sub: 'user123',
    name: 'Updated Test User',
    email: 'updated@example.com',
    preferred_username: 'updateduser',
    picture: 'https://example.com/avatar.jpg',
    locale: 'en-US',
};

/**
 * Mock storage adapter that tracks method calls
 */
export class MockStorageAdapter<
    TUser = UserClaims,
> implements StorageAdapter<TUser> {
    private storage = new Map<
        string,
        { user: TUser; metadata: StorageMetadata }
    >();
    public findUserCalls: TokenContext[] = [];
    public storeUserCalls: Array<{
        user: TUser | null;
        claims: UserClaims;
        metadata: StorageMetadata;
    }> = [];

    async findUser(
        context: TokenContext,
    ): Promise<{ user: TUser; metadata: StorageMetadata } | null> {
        this.findUserCalls.push(context);
        return this.storage.get(context.sub) || null;
    }

    async storeUser(
        user: TUser | null,
        newClaims: UserClaims,
        metadata: StorageMetadata,
    ): Promise<TUser> {
        // Create user record from claims if user is null, otherwise merge with existing
        const updatedUser = user
            ? ({ ...user, ...newClaims } as TUser)
            : (newClaims as TUser);

        const result = { user: updatedUser, metadata };
        this.storeUserCalls.push({ user, claims: newClaims, metadata });
        this.storage.set(newClaims.sub, result);
        return Promise.resolve(result.user);
    }

    async getAllUsers(): Promise<
        Array<{ user: TUser; metadata: StorageMetadata }>
    > {
        return Array.from(this.storage.values());
    }

    // Test utilities
    setUser(user: TUser, metadata: StorageMetadata = MOCK_USER_METADATA): void {
        const userClaims = user as any;
        this.storage.set(userClaims.sub, { user, metadata });
    }

    clear(): void {
        this.storage.clear();
        this.findUserCalls = [];
        this.storeUserCalls = [];
    }

    getStoredUser(
        sub: string,
    ): { user: TUser; metadata: StorageMetadata } | undefined {
        return this.storage.get(sub);
    }
}

/**
 * Mock logger that captures log entries
 */
export class MockLogger implements Logger {
    public logs: Array<{
        level: string;
        message: string;
        context?: Record<string, unknown>;
    }> = [];

    log(
        level: string,
        message: string,
        context?: Record<string, unknown>,
    ): void {
        this.logs.push({ level, message, context });
    }

    clear(): void {
        this.logs = [];
    }

    getLogsForLevel(
        level: string,
    ): Array<{ message: string; context?: Record<string, unknown> }> {
        return this.logs.filter((log) => log.level === level);
    }
}

/**
 * Mock OIDC configuration for testing
 * @param overrides - Partial configuration to override defaults
 * @returns Mock authenticator configuration
 */
export const createMockConfig = <TUser = UserClaims>(
    overrides: Partial<DefauthConfig<TUser>> = {},
): DefauthConfig<TUser> => ({
    issuer: MOCK_ISSUER,
    clientId: MOCK_CLIENT_ID,
    clientSecret: MOCK_CLIENT_SECRET,
    ...overrides,
});

/**
 * Mock openid-client methods
 * @returns Mock openid client with mocked methods
 */
export const createMockOpenidClient = () => ({
    serverMetadata: jest.fn().mockReturnValue({
        jwks_uri: 'https://mock-oidc-provider.com/.well-known/jwks',
        userinfo_endpoint: 'https://mock-oidc-provider.com/userinfo',
        token_introspection_endpoint:
            'https://mock-oidc-provider.com/introspect',
    }),
});

/**
 * Create mock JWT verify result
 * @param payload - JWT payload to use in the mock result
 * @returns Mock JWT verification result
 */
export const createMockJwtVerifyResult = (payload = MOCK_JWT_PAYLOAD) => ({
    payload,
    protectedHeader: {
        alg: 'RS256',
        typ: 'JWT',
    },
});

/**
 * Sets up module mocks for jose and openid-client using Jest's unstable_mockModule.
 * This function should be called before importing the modules you want to test.
 * @returns Promise resolving to an object containing the mocked modules
 */
export const setupModuleMocks = async () => {
    // Mock jose module
    jest.unstable_mockModule('jose', () => ({
        jwtVerify: jest.fn(),
        createRemoteJWKSet: jest.fn(),
        decodeProtectedHeader: jest.fn(),
        decodeJwt: jest.fn(),
    }));

    // Mock openid-client module
    jest.unstable_mockModule('openid-client', async () => ({
        discovery: jest.fn(),
        tokenIntrospection: jest.fn(),
        fetchUserInfo: jest.fn(),

        // Mock the authentication method constructors for testing
        // Each returns a function that acts as the auth method
        ClientSecretPost: jest.fn().mockReturnValue(jest.fn()),
        ClientSecretBasic: jest.fn().mockReturnValue(jest.fn()),
        ClientSecretJwt: jest.fn().mockReturnValue(jest.fn()),
        None: jest.fn().mockReturnValue(jest.fn()),
    }));

    // Import and return the mocked modules
    const joseMock = jest.mocked(await import('jose'));
    const openidMock = jest.mocked(await import('openid-client'));

    return {
        joseMock,
        openidMock,
    };
};
