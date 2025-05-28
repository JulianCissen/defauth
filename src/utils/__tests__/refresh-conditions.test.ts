import type { StorageMetadata, UserClaims } from '../../types/index.js';
import {
    afterEach,
    beforeEach,
    describe,
    expect,
    it,
    jest,
} from '@jest/globals';
import { defaultUserInfoRefreshCondition } from '../refresh-conditions.js';

describe('refresh-conditions', () => {
    let dateNowSpy: jest.SpiedFunction<() => number>;
    let currentTime: number;

    beforeEach(() => {
        currentTime = 1630000000000; // Fixed timestamp for consistent testing
        dateNowSpy = jest.spyOn(Date, 'now');
        dateNowSpy.mockReturnValue(currentTime);
    });

    afterEach(() => {
        dateNowSpy.mockRestore();
    });

    describe('defaultUserInfoRefreshCondition', () => {
        it('should return true when user has never been refreshed', () => {
            const user: UserClaims = {
                sub: 'user123',
                name: 'Test User',
            };
            const metadata: StorageMetadata = {
                // lastUserInfoRefresh is undefined
            };

            expect(defaultUserInfoRefreshCondition(user, metadata)).toBe(true);
        });

        it('should return true when user has undefined lastUserInfoRefresh', () => {
            const user: UserClaims = {
                sub: 'user123',
                name: 'Test User',
            };
            const metadata: StorageMetadata = {
                lastUserInfoRefresh: undefined,
            };

            expect(defaultUserInfoRefreshCondition(user, metadata)).toBe(true);
        });

        it('should return true when last refresh was over 1 hour ago', () => {
            const twoHoursAgo = new Date(currentTime - 2 * 60 * 60 * 1000);
            const user: UserClaims = {
                sub: 'user123',
                name: 'Test User',
            };
            const metadata: StorageMetadata = {
                lastUserInfoRefresh: twoHoursAgo,
            };

            expect(defaultUserInfoRefreshCondition(user, metadata)).toBe(true);
        });

        it('should return true when last refresh was exactly 1 hour ago', () => {
            const oneHourAgo = new Date(currentTime - 60 * 60 * 1000);
            const user: UserClaims = {
                sub: 'user123',
                name: 'Test User',
            };
            const metadata: StorageMetadata = {
                lastUserInfoRefresh: oneHourAgo,
            };

            expect(defaultUserInfoRefreshCondition(user, metadata)).toBe(true);
        });

        it('should return false when last refresh was within the last hour', () => {
            const thirtyMinutesAgo = new Date(currentTime - 30 * 60 * 1000);
            const user: UserClaims = {
                sub: 'user123',
                name: 'Test User',
            };
            const metadata: StorageMetadata = {
                lastUserInfoRefresh: thirtyMinutesAgo,
            };

            expect(defaultUserInfoRefreshCondition(user, metadata)).toBe(false);
        });

        it('should return false when last refresh was very recent', () => {
            const fiveMinutesAgo = new Date(currentTime - 5 * 60 * 1000);
            const user: UserClaims = {
                sub: 'user123',
                name: 'Test User',
            };
            const metadata: StorageMetadata = {
                lastUserInfoRefresh: fiveMinutesAgo,
            };

            expect(defaultUserInfoRefreshCondition(user, metadata)).toBe(false);
        });

        it('should return false when last refresh was just now', () => {
            const user: UserClaims = {
                sub: 'user123',
                name: 'Test User',
            };
            const metadata: StorageMetadata = {
                lastUserInfoRefresh: new Date(currentTime),
            };

            expect(defaultUserInfoRefreshCondition(user, metadata)).toBe(false);
        });
        it('should handle edge case timestamps correctly', () => {
            // Exactly one millisecond over an hour
            const oneHourAndOneMs = new Date(
                currentTime - (60 * 60 * 1000 + 1),
            );
            const user: UserClaims = {
                sub: 'user123',
                name: 'Test User',
            };
            const metadata1: StorageMetadata = {
                lastUserInfoRefresh: oneHourAndOneMs,
            };

            expect(defaultUserInfoRefreshCondition(user, metadata1)).toBe(true);

            // Exactly one millisecond under an hour
            const oneHourMinusOneMs = new Date(
                currentTime - (60 * 60 * 1000 - 1),
            );
            const metadata2: StorageMetadata = {
                lastUserInfoRefresh: oneHourMinusOneMs,
            };

            expect(defaultUserInfoRefreshCondition(user, metadata2)).toBe(
                false,
            );
        });

        it('should work with different current times', () => {
            // Change current time
            const newCurrentTime = currentTime + 24 * 60 * 60 * 1000; // 24 hours later
            dateNowSpy.mockReturnValue(newCurrentTime);

            const originalRefreshTime = new Date(currentTime - 30 * 60 * 1000); // Originally 30 mins ago
            const user: UserClaims = {
                sub: 'user123',
                name: 'Test User',
            };
            const metadata: StorageMetadata = {
                lastUserInfoRefresh: originalRefreshTime, // Now 24.5 hours ago
            };

            expect(defaultUserInfoRefreshCondition(user, metadata)).toBe(true);
        });

        it('should ignore other user properties', () => {
            const user: UserClaims = {
                sub: 'user123',
                name: 'Test User',
                email: 'test@example.com',
                given_name: 'Test',
                family_name: 'User',
                picture: 'https://example.com/avatar.jpg',
                customClaim: 'custom value',
            };
            const metadata: StorageMetadata = {
                lastUserInfoRefresh: new Date(currentTime - 30 * 60 * 1000), // 30 mins ago
                lastIntrospection: new Date(currentTime - 10 * 60 * 1000), // 10 mins ago
            };

            expect(defaultUserInfoRefreshCondition(user, metadata)).toBe(false);
        });

        it('should handle zero timestamp', () => {
            const user: UserClaims = {
                sub: 'user123',
                name: 'Test User',
            };
            const metadata: StorageMetadata = {
                lastUserInfoRefresh: new Date(0),
            };

            expect(defaultUserInfoRefreshCondition(user, metadata)).toBe(true);
        });

        it('should handle negative timestamp', () => {
            const user: UserClaims = {
                sub: 'user123',
                name: 'Test User',
            };
            const metadata: StorageMetadata = {
                lastUserInfoRefresh: new Date(-1000),
            };

            expect(defaultUserInfoRefreshCondition(user, metadata)).toBe(true);
        });

        it('should handle future timestamp (clock skew)', () => {
            const futureTimestamp = new Date(currentTime + 60 * 60 * 1000); // 1 hour in the future
            const user: UserClaims = {
                sub: 'user123',
                name: 'Test User',
            };
            const metadata: StorageMetadata = {
                lastUserInfoRefresh: futureTimestamp,
            };

            expect(defaultUserInfoRefreshCondition(user, metadata)).toBe(false);
        });
    });
});
