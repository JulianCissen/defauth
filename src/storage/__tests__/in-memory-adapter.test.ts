import { beforeEach, describe, expect, it } from '@jest/globals';
import { InMemoryStorageAdapter } from '../in-memory-adapter.js';
import type { UserRecord } from '../../types/index.js';

describe('InMemoryStorageAdapter', () => {
    let adapter: InMemoryStorageAdapter;
    let mockUser: UserRecord;

    beforeEach(() => {
        adapter = new InMemoryStorageAdapter();
        mockUser = {
            sub: 'user123',
            name: 'Test User',
            email: 'test@example.com',
            lastUserInfoRefresh: Date.now(),
            lastIntrospection: Date.now(),
        };
    });

    describe('storeUser', () => {
        it('should store a user successfully', async () => {
            await adapter.storeUser(mockUser);

            const retrievedUser = await adapter.findUser('user123');
            expect(retrievedUser).toEqual(mockUser);
        });

        it('should update existing user', async () => {
            // Store initial user
            await adapter.storeUser(mockUser);

            // Update user with new data
            const updatedUser: UserRecord = {
                ...mockUser,
                name: 'Updated Name',
                email: 'updated@example.com',
            };

            await adapter.storeUser(updatedUser);

            const retrievedUser = await adapter.findUser('user123');
            expect(retrievedUser).toEqual(updatedUser);
            expect(retrievedUser?.['name']).toBe('Updated Name');
            expect(retrievedUser?.['email']).toBe('updated@example.com');
        });

        it('should handle users with only required fields', async () => {
            const minimalUser: UserRecord = {
                sub: 'minimal-user',
            };

            await adapter.storeUser(minimalUser);

            const retrievedUser = await adapter.findUser('minimal-user');
            expect(retrievedUser).toEqual(minimalUser);
        });
    });

    describe('findUser', () => {
        it('should return user when found', async () => {
            await adapter.storeUser(mockUser);

            const result = await adapter.findUser('user123');
            expect(result).toEqual(mockUser);
        });

        it('should return null when user not found', async () => {
            const result = await adapter.findUser('nonexistent-user');
            expect(result).toBeNull();
        });

        it('should return null for empty subject', async () => {
            const result = await adapter.findUser('');
            expect(result).toBeNull();
        });

        it('should be case-sensitive for subject matching', async () => {
            await adapter.storeUser(mockUser);

            const result = await adapter.findUser('USER123'); // Different case
            expect(result).toBeNull();
        });
    });

    describe('clear', () => {
        it('should clear all stored users', async () => {
            // Store multiple users
            await adapter.storeUser(mockUser);
            await adapter.storeUser({
                sub: 'user456',
                name: 'Another User',
            });

            // Verify users are stored
            expect(await adapter.findUser('user123')).toBeTruthy();
            expect(await adapter.findUser('user456')).toBeTruthy();

            // Clear all users
            adapter.clear();

            // Verify users are removed
            expect(await adapter.findUser('user123')).toBeNull();
            expect(await adapter.findUser('user456')).toBeNull();
        });

        it('should not affect subsequent store operations', async () => {
            // Store, clear, then store again
            await adapter.storeUser(mockUser);
            adapter.clear();
            await adapter.storeUser(mockUser);

            const result = await adapter.findUser('user123');
            expect(result).toEqual(mockUser);
        });
    });

    describe('multiple users', () => {
        it('should handle multiple users independently', async () => {
            const user1: UserRecord = {
                sub: 'user1',
                name: 'First User',
                email: 'first@example.com',
            };

            const user2: UserRecord = {
                sub: 'user2',
                name: 'Second User',
                email: 'second@example.com',
            };

            // Store both users
            await adapter.storeUser(user1);
            await adapter.storeUser(user2);

            // Retrieve both users
            const retrievedUser1 = await adapter.findUser('user1');
            const retrievedUser2 = await adapter.findUser('user2');

            expect(retrievedUser1).toEqual(user1);
            expect(retrievedUser2).toEqual(user2);

            // Update one user shouldn't affect the other
            const updatedUser1 = { ...user1, name: 'Updated First User' };
            await adapter.storeUser(updatedUser1);

            expect(await adapter.findUser('user1')).toEqual(updatedUser1);
            expect(await adapter.findUser('user2')).toEqual(user2); // Unchanged
        });
    });

    describe('data integrity', () => {
        it('should preserve all user properties', async () => {
            const complexUser: UserRecord = {
                sub: 'complex-user',
                name: 'Complex User',
                email: 'complex@example.com',
                given_name: 'Complex',
                family_name: 'User',
                picture: 'https://example.com/avatar.jpg',
                locale: 'en-US',
                zoneinfo: 'America/New_York',
                updated_at: 1640995200,
                custom_claim: 'custom_value',
                nested_object: {
                    key1: 'value1',
                    key2: { nestedKey: 'nestedValue' },
                },
                array_claim: ['item1', 'item2', 'item3'],
                lastUserInfoRefresh: 1640995200000,
                lastIntrospection: 1640995200000,
            };

            await adapter.storeUser(complexUser);
            const retrieved = await adapter.findUser('complex-user');

            expect(retrieved).toEqual(complexUser);
        });

        it('should handle undefined optional properties', async () => {
            const userWithUndefined: UserRecord = {
                sub: 'user-with-undefined',
                name: undefined,
                email: 'test@example.com',
                lastUserInfoRefresh: undefined,
                lastIntrospection: Date.now(),
            };

            await adapter.storeUser(userWithUndefined);
            const retrieved = await adapter.findUser('user-with-undefined');

            expect(retrieved).toEqual(userWithUndefined);
        });
    });
});
