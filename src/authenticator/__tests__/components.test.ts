import type { TokenContext, UserRecord } from '../../types/index.js';
import { describe, expect, it } from '@jest/globals';
import { ConsoleLogger } from '../../utils/logger.js';
import { InMemoryStorageAdapter } from '../../storage/index.js';
import { defaultUserInfoRefreshCondition } from '../../utils/refresh-conditions.js';

const createJwtTokenContext = (sub: string): TokenContext => ({
    sub,
    type: 'jwt',
    jwtPayload: { sub },
    metadata: { validatedAt: Date.now() },
});

describe('Authenticator Components', () => {
    describe('Storage Integration', () => {
        it('should store and retrieve user data correctly', async () => {
            const storageAdapter = new InMemoryStorageAdapter();
            const user: UserRecord = {
                sub: 'user123',
                name: 'Test User',
                email: 'test@example.com',
                lastUserInfoRefresh: Date.now(),
            };

            await storageAdapter.storeUser(user);
            const retrievedUser = await storageAdapter.findUser(
                createJwtTokenContext('user123'),
            );

            expect(retrievedUser).toEqual(user);
        });

        it('should return null for non-existent users', async () => {
            const storageAdapter = new InMemoryStorageAdapter();
            const user = await storageAdapter.findUser(
                createJwtTokenContext('nonexistent'),
            );
            expect(user).toBeNull();
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
            const user: UserRecord = {
                sub: 'user123',
                name: 'Test User',
            };

            expect(defaultUserInfoRefreshCondition(user)).toBe(true);
        });

        it('should require refresh for stale user data', () => {
            const twoHoursAgo = Date.now() - 2 * 60 * 60 * 1000;
            const user: UserRecord = {
                sub: 'user123',
                name: 'Test User',
                lastUserInfoRefresh: twoHoursAgo,
            };

            expect(defaultUserInfoRefreshCondition(user)).toBe(true);
        });
    });
});
