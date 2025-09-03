import type {
    StorageMetadata,
    TokenContext,
    UserClaims,
} from '../../types/index.js';
import { describe, expect, it } from '@jest/globals';
import { ConsoleLogger } from '../../utils/logger.js';
import { InMemoryStorageAdapter } from '../../storage/index.js';
import { defaultUserInfoRefreshCondition } from '../../utils/refresh-conditions.js';

const createJwtTokenContext = (sub: string): TokenContext => ({
    sub,
    jwtPayload: { sub },
    metadata: { validatedAt: new Date() },
});

describe('Defauth - Component Integration and Utilities', () => {
    describe('Storage Integration', () => {
        it('should store and retrieve user data correctly', async () => {
            const storageAdapter = new InMemoryStorageAdapter();
            const user: UserClaims = {
                sub: 'user123',
                name: 'Test User',
                email: 'test@example.com',
            };
            const metadata: StorageMetadata = {
                lastUserInfoRefresh: new Date(),
            };

            const result = await storageAdapter.storeUser(user, user, metadata);
            expect(result).toEqual(user);

            const retrievedResult = await storageAdapter.findUser(
                createJwtTokenContext('user123'),
            );

            expect(retrievedResult?.user).toEqual(user);
            expect(retrievedResult?.metadata).toEqual(metadata);
        });

        it('should return null for non-existent users', async () => {
            const storageAdapter = new InMemoryStorageAdapter();
            const userResult = await storageAdapter.findUser(
                createJwtTokenContext('nonexistent'),
            );
            expect(userResult).toBeNull();
        });
    });

    describe('Logger Integration', () => {
        it('should create logger instance', () => {
            const logger = new ConsoleLogger();
            expect(logger).toBeDefined();
            expect(typeof logger.log).toBe('function');
        });
    });

    describe('Refresh Logic Integration', () => {
        it('should require refresh for users never refreshed', () => {
            const user: UserClaims = {
                sub: 'user123',
                name: 'Test User',
            };
            const metadata: StorageMetadata = {};

            expect(defaultUserInfoRefreshCondition(user, metadata)).toBe(true);
        });

        it('should require refresh for stale user data', () => {
            const twoHoursAgo = Date.now() - 2 * 60 * 60 * 1000;
            const user: UserClaims = {
                sub: 'user123',
                name: 'Test User',
            };
            const metadata: StorageMetadata = {
                lastUserInfoRefresh: new Date(twoHoursAgo),
            };

            expect(defaultUserInfoRefreshCondition(user, metadata)).toBe(true);
        });
    });
});
