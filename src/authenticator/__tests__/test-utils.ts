import { jest } from '@jest/globals';
import type {
    AuthenticatorConfig,
    Logger,
    StorageAdapter,
    UserClaims,
    UserRecord,
} from '../../types/index.js';
import type { IntrospectionResponse } from 'oauth4webapi';

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
 * Mock user record with timestamps
 */
export const MOCK_USER_RECORD: UserRecord = {
    ...MOCK_USER_CLAIMS,
    lastUserInfoRefresh: Date.now() - 30 * 60 * 1000, // 30 minutes ago
    lastIntrospection: Date.now() - 5 * 60 * 1000, // 5 minutes ago
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
export class MockStorageAdapter implements StorageAdapter {
    private storage = new Map<string, UserRecord>();
    public findUserCalls: string[] = [];
    public storeUserCalls: UserRecord[] = [];

    async findUser(sub: string): Promise<UserRecord | null> {
        this.findUserCalls.push(sub);
        return this.storage.get(sub) || null;
    }

    async storeUser(user: UserRecord): Promise<void> {
        this.storeUserCalls.push({ ...user });
        this.storage.set(user.sub, user);
    }

    // Test utilities
    setUser(user: UserRecord): void {
        this.storage.set(user.sub, user);
    }

    clear(): void {
        this.storage.clear();
        this.findUserCalls = [];
        this.storeUserCalls = [];
    }

    getStoredUser(sub: string): UserRecord | undefined {
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
export const createMockConfig = (
    overrides: Partial<AuthenticatorConfig> = {},
): AuthenticatorConfig => ({
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
 * Utility to create fresh timestamps for testing
 * @returns Object with various timestamps for testing
 */
export const createTimestamps = () => ({
    now: Date.now(),
    oneHourAgo: Date.now() - 60 * 60 * 1000,
    fiveMinutesAgo: Date.now() - 5 * 60 * 1000,
    tomorrow: Date.now() + 24 * 60 * 60 * 1000,
});

/**
 * Utility to wait for async operations
 * @returns Promise that resolves on next tick
 */
export const waitForAsync = (): Promise<void> =>
    new Promise((resolve) => setImmediate(resolve));

/**
 * Create a test user refresh condition that always requires refresh
 * @returns Function that always returns true
 */
export const alwaysRefreshCondition = () => true;

/**
 * Create a test user refresh condition that never requires refresh
 * @returns Function that always returns false
 */
export const neverRefreshCondition = () => false;
