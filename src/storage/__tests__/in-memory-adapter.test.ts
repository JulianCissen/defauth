import type { TokenContext, UserRecord } from '../../types/index.js';
import { beforeEach, describe, expect, it } from '@jest/globals';
import { InMemoryStorageAdapter } from '../in-memory-adapter.js';

const createJwtTokenContext = (sub: string): TokenContext => ({
    sub,
    type: 'jwt',
    jwtPayload: { sub },
    metadata: { validatedAt: Date.now() },
});

describe('InMemoryStorageAdapter', () => {
    let adapter: InMemoryStorageAdapter<UserRecord>;
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
            await adapter.storeUser(mockUser, mockUser, {});

            const retrievedUser = await adapter.findUser(
                createJwtTokenContext('user123'),
            );
            expect(retrievedUser).toEqual(mockUser);
        });

        it('should update existing user', async () => {
            // Store initial user
            await adapter.storeUser(mockUser, mockUser, {});

            // Update user with new data
            const updatedUser: UserRecord = {
                ...mockUser,
                name: 'Updated Name',
                email: 'updated@example.com',
            };

            await adapter.storeUser(updatedUser, updatedUser, {});

            const retrievedUser = await adapter.findUser(
                createJwtTokenContext('user123'),
            );
            expect(retrievedUser).toEqual(updatedUser);
            expect(retrievedUser?.['name']).toBe('Updated Name');
            expect(retrievedUser?.['email']).toBe('updated@example.com');
        });

        it('should handle users with only required fields', async () => {
            const minimalUser: UserRecord = {
                sub: 'minimal-user',
            };

            await adapter.storeUser(minimalUser, minimalUser, {});

            const retrievedUser = await adapter.findUser(
                createJwtTokenContext('minimal-user'),
            );
            expect(retrievedUser).toEqual(minimalUser);
        });
    });

    describe('findUser', () => {
        it('should return user when found', async () => {
            await adapter.storeUser(mockUser, mockUser, {});

            const result = await adapter.findUser(
                createJwtTokenContext('user123'),
            );
            expect(result).toEqual(mockUser);
        });

        it('should return null when user not found', async () => {
            const result = await adapter.findUser(
                createJwtTokenContext('nonexistent-user'),
            );
            expect(result).toBeNull();
        });

        it('should return null for empty subject', async () => {
            const result = await adapter.findUser(createJwtTokenContext(''));
            expect(result).toBeNull();
        });

        it('should be case-sensitive for subject matching', async () => {
            await adapter.storeUser(mockUser, mockUser, {});

            const result = await adapter.findUser(
                createJwtTokenContext('USER123'),
            ); // Different case
            expect(result).toBeNull();
        });
    });

    describe('clear', () => {
        it('should clear all stored users', async () => {
            // Store multiple users
            await adapter.storeUser(mockUser, mockUser, {});
            const anotherUser = {
                sub: 'user456',
                name: 'Another User',
            };
            await adapter.storeUser(anotherUser, anotherUser, {});

            // Verify users are stored
            expect(
                await adapter.findUser(createJwtTokenContext('user123')),
            ).toBeTruthy();
            expect(
                await adapter.findUser(createJwtTokenContext('user456')),
            ).toBeTruthy();

            // Clear all users
            adapter.clear();

            // Verify users are removed
            expect(
                await adapter.findUser(createJwtTokenContext('user123')),
            ).toBeNull();
            expect(
                await adapter.findUser(createJwtTokenContext('user456')),
            ).toBeNull();
        });

        it('should not affect subsequent store operations', async () => {
            // Store, clear, then store again
            await adapter.storeUser(mockUser, mockUser, {});
            adapter.clear();
            await adapter.storeUser(mockUser, mockUser, {});

            const result = await adapter.findUser(
                createJwtTokenContext('user123'),
            );
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
            await adapter.storeUser(user1, user1, {});
            await adapter.storeUser(user2, user2, {});

            // Retrieve both users
            const retrievedUser1 = await adapter.findUser(
                createJwtTokenContext('user1'),
            );
            const retrievedUser2 = await adapter.findUser(
                createJwtTokenContext('user2'),
            );

            expect(retrievedUser1).toEqual(user1);
            expect(retrievedUser2).toEqual(user2);

            // Update one user shouldn't affect the other
            const updatedUser1 = { ...user1, name: 'Updated First User' };
            await adapter.storeUser(updatedUser1, updatedUser1, {});

            expect(
                await adapter.findUser(createJwtTokenContext('user1')),
            ).toEqual(updatedUser1);
            expect(
                await adapter.findUser(createJwtTokenContext('user2')),
            ).toEqual(user2); // Unchanged
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

            await adapter.storeUser(complexUser, complexUser, {});
            const retrieved = await adapter.findUser(
                createJwtTokenContext('complex-user'),
            );

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

            await adapter.storeUser(userWithUndefined, userWithUndefined, {});
            const retrieved = await adapter.findUser(
                createJwtTokenContext('user-with-undefined'),
            );

            expect(retrieved).toEqual(userWithUndefined);
        });
    });

    describe('getAllUsers', () => {
        it('should return empty array when no users stored', () => {
            const users = adapter.getAllUsers();
            expect(users).toEqual([]);
            expect(Array.isArray(users)).toBe(true);
        });

        it('should return all stored users', async () => {
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

            await adapter.storeUser(user1, user1, {});
            await adapter.storeUser(user2, user2, {});

            const users = adapter.getAllUsers();
            expect(users).toHaveLength(2);
            expect(users).toContainEqual(user1);
            expect(users).toContainEqual(user2);
        });

        it('should return updated user data', async () => {
            await adapter.storeUser(mockUser, mockUser, {});

            const updatedUser = { ...mockUser, name: 'Updated Name' };
            await adapter.storeUser(updatedUser, updatedUser, {});

            const users = adapter.getAllUsers();
            expect(users).toHaveLength(1);
            expect(users[0]).toEqual(updatedUser);
            expect(users[0]?.['name']).toBe('Updated Name');
        });

        it('should return empty array after clear', async () => {
            await adapter.storeUser(mockUser, mockUser, {});
            expect(adapter.getAllUsers()).toHaveLength(1);

            adapter.clear();
            expect(adapter.getAllUsers()).toEqual([]);
        });
    });

    describe('metadata separation', () => {
        it('should handle metadata parameter separately from user claims', async () => {
            const userClaims = {
                sub: 'test-metadata-user',
                name: 'Test User',
                email: 'test@example.com',
            };

            const metadata = {
                lastUserInfoRefresh: Date.now(),
                lastIntrospection: Date.now() - 5000,
            };

            // Store user with separated metadata
            await adapter.storeUser(null, userClaims, metadata);

            const retrievedUser = await adapter.findUser(
                createJwtTokenContext('test-metadata-user'),
            );

            expect(retrievedUser).toBeDefined();
            expect(retrievedUser?.sub).toBe('test-metadata-user');
            expect(retrievedUser?.['name']).toBe('Test User');
            expect(retrievedUser?.['email']).toBe('test@example.com');
            expect(retrievedUser?.lastUserInfoRefresh).toBe(
                metadata.lastUserInfoRefresh,
            );
            expect(retrievedUser?.lastIntrospection).toBe(
                metadata.lastIntrospection,
            );
        });

        it('should merge metadata with existing user data', async () => {
            const existingUser: UserRecord = {
                sub: 'existing-user',
                name: 'Existing User',
                email: 'existing@example.com',
                role: 'user',
                lastUserInfoRefresh: Date.now() - 10000,
            };

            await adapter.storeUser(existingUser, existingUser, {});

            const newClaims = {
                sub: 'existing-user',
                name: 'Updated User',
                email: 'updated@example.com',
                department: 'Engineering',
            };

            const newMetadata = {
                lastUserInfoRefresh: Date.now(),
                lastIntrospection: Date.now() - 1000,
            };

            // Update user with new claims and metadata
            await adapter.storeUser(existingUser, newClaims, newMetadata);

            const updatedUser = await adapter.findUser(
                createJwtTokenContext('existing-user'),
            );

            expect(updatedUser).toBeDefined();
            expect(updatedUser?.['name']).toBe('Updated User');
            expect(updatedUser?.['email']).toBe('updated@example.com');
            expect(updatedUser?.['department']).toBe('Engineering');
            expect(updatedUser?.['role']).toBe('user'); // Should preserve existing data
            expect(updatedUser?.lastUserInfoRefresh).toBe(
                newMetadata.lastUserInfoRefresh,
            );
            expect(updatedUser?.lastIntrospection).toBe(
                newMetadata.lastIntrospection,
            );
        });
    });
});
