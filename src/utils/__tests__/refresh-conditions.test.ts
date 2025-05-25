import {
    afterEach,
    beforeEach,
    describe,
    expect,
    it,
    jest,
} from '@jest/globals';
import type { UserRecord } from '../../types/index.js';
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
            const userWithoutRefresh: UserRecord = {
                sub: 'user123',
                name: 'Test User',
                // lastUserInfoRefresh is undefined
            };

            expect(defaultUserInfoRefreshCondition(userWithoutRefresh)).toBe(
                true,
            );
        });

        it('should return true when user has undefined lastUserInfoRefresh', () => {
            const userWithUndefinedRefresh: UserRecord = {
                sub: 'user123',
                name: 'Test User',
                lastUserInfoRefresh: undefined,
            };

            expect(
                defaultUserInfoRefreshCondition(userWithUndefinedRefresh),
            ).toBe(true);
        });

        it('should return true when last refresh was over 1 hour ago', () => {
            const twoHoursAgo = currentTime - 2 * 60 * 60 * 1000;
            const userOldRefresh: UserRecord = {
                sub: 'user123',
                name: 'Test User',
                lastUserInfoRefresh: twoHoursAgo,
            };

            expect(defaultUserInfoRefreshCondition(userOldRefresh)).toBe(true);
        });

        it('should return true when last refresh was exactly 1 hour ago', () => {
            const oneHourAgo = currentTime - 60 * 60 * 1000;
            const userExactlyOneHour: UserRecord = {
                sub: 'user123',
                name: 'Test User',
                lastUserInfoRefresh: oneHourAgo,
            };

            expect(defaultUserInfoRefreshCondition(userExactlyOneHour)).toBe(
                true,
            );
        });

        it('should return false when last refresh was within the last hour', () => {
            const thirtyMinutesAgo = currentTime - 30 * 60 * 1000;
            const userRecentRefresh: UserRecord = {
                sub: 'user123',
                name: 'Test User',
                lastUserInfoRefresh: thirtyMinutesAgo,
            };

            expect(defaultUserInfoRefreshCondition(userRecentRefresh)).toBe(
                false,
            );
        });

        it('should return false when last refresh was very recent', () => {
            const fiveMinutesAgo = currentTime - 5 * 60 * 1000;
            const userVeryRecentRefresh: UserRecord = {
                sub: 'user123',
                name: 'Test User',
                lastUserInfoRefresh: fiveMinutesAgo,
            };

            expect(defaultUserInfoRefreshCondition(userVeryRecentRefresh)).toBe(
                false,
            );
        });

        it('should return false when last refresh was just now', () => {
            const userJustRefreshed: UserRecord = {
                sub: 'user123',
                name: 'Test User',
                lastUserInfoRefresh: currentTime,
            };

            expect(defaultUserInfoRefreshCondition(userJustRefreshed)).toBe(
                false,
            );
        });

        it('should handle edge case timestamps correctly', () => {
            // Exactly one millisecond over an hour
            const oneHourAndOneMs = currentTime - (60 * 60 * 1000 + 1);
            const userJustOverOneHour: UserRecord = {
                sub: 'user123',
                name: 'Test User',
                lastUserInfoRefresh: oneHourAndOneMs,
            };

            expect(defaultUserInfoRefreshCondition(userJustOverOneHour)).toBe(
                true,
            );

            // Exactly one millisecond under an hour
            const oneHourMinusOneMs = currentTime - (60 * 60 * 1000 - 1);
            const userJustUnderOneHour: UserRecord = {
                sub: 'user123',
                name: 'Test User',
                lastUserInfoRefresh: oneHourMinusOneMs,
            };

            expect(defaultUserInfoRefreshCondition(userJustUnderOneHour)).toBe(
                false,
            );
        });

        it('should work with different current times', () => {
            // Change current time
            const newCurrentTime = currentTime + 24 * 60 * 60 * 1000; // 24 hours later
            dateNowSpy.mockReturnValue(newCurrentTime);

            const originalRefreshTime = currentTime - 30 * 60 * 1000; // Originally 30 mins ago
            const userNowOldRefresh: UserRecord = {
                sub: 'user123',
                name: 'Test User',
                lastUserInfoRefresh: originalRefreshTime, // Now 24.5 hours ago
            };

            expect(defaultUserInfoRefreshCondition(userNowOldRefresh)).toBe(
                true,
            );
        });

        it('should ignore other user properties', () => {
            const userWithManyProperties: UserRecord = {
                sub: 'user123',
                name: 'Test User',
                email: 'test@example.com',
                given_name: 'Test',
                family_name: 'User',
                picture: 'https://example.com/avatar.jpg',
                lastUserInfoRefresh: currentTime - 30 * 60 * 1000, // 30 mins ago
                lastIntrospection: currentTime - 10 * 60 * 1000, // 10 mins ago
                customClaim: 'custom value',
            };

            expect(
                defaultUserInfoRefreshCondition(userWithManyProperties),
            ).toBe(false);
        });

        it('should handle zero timestamp', () => {
            const userWithZeroTimestamp: UserRecord = {
                sub: 'user123',
                name: 'Test User',
                lastUserInfoRefresh: 0,
            };

            expect(defaultUserInfoRefreshCondition(userWithZeroTimestamp)).toBe(
                true,
            );
        });

        it('should handle negative timestamp', () => {
            const userWithNegativeTimestamp: UserRecord = {
                sub: 'user123',
                name: 'Test User',
                lastUserInfoRefresh: -1000,
            };

            expect(
                defaultUserInfoRefreshCondition(userWithNegativeTimestamp),
            ).toBe(true);
        });

        it('should handle future timestamp (clock skew)', () => {
            const futureTimestamp = currentTime + 60 * 60 * 1000; // 1 hour in the future
            const userWithFutureTimestamp: UserRecord = {
                sub: 'user123',
                name: 'Test User',
                lastUserInfoRefresh: futureTimestamp,
            };

            // Future timestamp should not trigger refresh (treat as recent)
            expect(
                defaultUserInfoRefreshCondition(userWithFutureTimestamp),
            ).toBe(false);
        });
    });
});
