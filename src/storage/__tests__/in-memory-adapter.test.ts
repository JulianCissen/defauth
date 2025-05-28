import type {
    StorageMetadata,
    TokenContext,
    UserClaims,
} from '../../types/index.js';
import { beforeEach, describe, expect, it } from '@jest/globals';
import { InMemoryStorageAdapter } from '../in-memory-adapter.js';

const createJwtTokenContext = (sub: string): TokenContext => ({
    sub,
    jwtPayload: { sub },
    metadata: { validatedAt: new Date() },
});

describe('InMemoryStorageAdapter', () => {
    let adapter: InMemoryStorageAdapter<UserClaims>;
    let mockUser: UserClaims;
    let mockMetadata: StorageMetadata;

    beforeEach(() => {
        adapter = new InMemoryStorageAdapter();
        mockUser = {
            sub: 'user123',
            name: 'Test User',
            email: 'test@example.com',
        };
        mockMetadata = {
            lastUserInfoRefresh: new Date(),
            lastIntrospection: new Date(),
        };
    });

    describe('storeUser', () => {
        it('should store a user successfully', async () => {
            const result = await adapter.storeUser(
                mockUser,
                mockUser,
                mockMetadata,
            );

            expect(result).toEqual(mockUser);

            const retrievedResult = await adapter.findUser(
                createJwtTokenContext('user123'),
            );
            expect(retrievedResult?.user).toEqual(mockUser);
            expect(retrievedResult?.metadata).toEqual(mockMetadata);
        });

        it('should update existing user', async () => {
            // Store initial user
            await adapter.storeUser(mockUser, mockUser, mockMetadata);

            // Update user with new data
            const updatedUser: UserClaims = {
                ...mockUser,
                name: 'Updated Name',
                email: 'updated@example.com',
            };

            const updatedMetadata: StorageMetadata = {
                lastUserInfoRefresh: new Date(),
                lastIntrospection: new Date(),
            };

            const result = await adapter.storeUser(
                updatedUser,
                updatedUser,
                updatedMetadata,
            );

            expect(result).toEqual(updatedUser);

            const retrievedResult = await adapter.findUser(
                createJwtTokenContext('user123'),
            );
            expect(retrievedResult?.user).toEqual(updatedUser);
            expect(retrievedResult?.user['name']).toBe('Updated Name');
            expect(retrievedResult?.user['email']).toBe('updated@example.com');
        });

        it('should handle users with only required fields', async () => {
            const minimalUser: UserClaims = {
                sub: 'minimal-user',
            };

            const minimalMetadata: StorageMetadata = {};

            const result = await adapter.storeUser(
                minimalUser,
                minimalUser,
                minimalMetadata,
            );

            expect(result).toEqual(minimalUser);

            const retrievedResult = await adapter.findUser(
                createJwtTokenContext('minimal-user'),
            );
            expect(retrievedResult?.user).toEqual(minimalUser);
        });
    });

    describe('findUser', () => {
        it('should return user and metadata when found', async () => {
            await adapter.storeUser(mockUser, mockUser, mockMetadata);

            const result = await adapter.findUser(
                createJwtTokenContext('user123'),
            );
            expect(result?.user).toEqual(mockUser);
            expect(result?.metadata).toEqual(mockMetadata);
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
            await adapter.storeUser(mockUser, mockUser, mockMetadata);

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
            expect(result?.user).toEqual(mockUser);
        });
    });

    describe('multiple users', () => {
        it('should handle multiple users independently', async () => {
            const user1: UserClaims = {
                sub: 'user1',
                name: 'First User',
                email: 'first@example.com',
            };

            const user2: UserClaims = {
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

            expect(retrievedUser1?.user).toEqual(user1);
            expect(retrievedUser2?.user).toEqual(user2);

            // Update one user shouldn't affect the other
            const updatedUser1 = { ...user1, name: 'Updated First User' };
            await adapter.storeUser(updatedUser1, updatedUser1, {});

            expect(
                (await adapter.findUser(createJwtTokenContext('user1')))?.user,
            ).toEqual(updatedUser1);
            expect(
                (await adapter.findUser(createJwtTokenContext('user2')))?.user,
            ).toEqual(user2); // Unchanged
        });
    });

    describe('data integrity', () => {
        it('should preserve all user properties', async () => {
            const complexUser: UserClaims = {
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
            };

            const complexMetadata: StorageMetadata = {
                lastUserInfoRefresh: new Date(1640995200000),
                lastIntrospection: new Date(1640995200000),
            };

            await adapter.storeUser(complexUser, complexUser, complexMetadata);
            const retrieved = await adapter.findUser(
                createJwtTokenContext('complex-user'),
            );

            expect(retrieved?.user).toEqual(complexUser);
            expect(retrieved?.metadata).toEqual(complexMetadata);
        });

        it('should handle undefined optional properties', async () => {
            const userWithUndefined: UserClaims = {
                sub: 'user-with-undefined',
                name: undefined,
                email: 'test@example.com',
            };

            const metadataWithUndefined: StorageMetadata = {
                lastUserInfoRefresh: undefined,
                lastIntrospection: new Date(Date.now()),
            };

            await adapter.storeUser(
                userWithUndefined,
                userWithUndefined,
                metadataWithUndefined,
            );
            const retrieved = await adapter.findUser(
                createJwtTokenContext('user-with-undefined'),
            );

            expect(retrieved?.user).toEqual(userWithUndefined);
            expect(retrieved?.metadata).toEqual(metadataWithUndefined);
        });
    });

    describe('getAllUsers', () => {
        it('should return empty array when no users stored', () => {
            const users = adapter.getAllUsers();
            expect(users).toEqual([]);
            expect(Array.isArray(users)).toBe(true);
        });

        it('should return all stored users', async () => {
            const user1: UserClaims = {
                sub: 'user1',
                name: 'First User',
                email: 'first@example.com',
            };

            const user2: UserClaims = {
                sub: 'user2',
                name: 'Second User',
                email: 'second@example.com',
            };

            await adapter.storeUser(user1, user1, {});
            await adapter.storeUser(user2, user2, {});

            const users = adapter.getAllUsers();
            expect(users).toHaveLength(2);
            expect(users.map((u) => u.user)).toContainEqual(user1);
            expect(users.map((u) => u.user)).toContainEqual(user2);
        });

        it('should return updated user data', async () => {
            await adapter.storeUser(mockUser, mockUser, {});

            const updatedUser = { ...mockUser, name: 'Updated Name' };
            await adapter.storeUser(updatedUser, updatedUser, {});

            const users = adapter.getAllUsers();
            expect(users).toHaveLength(1);
            expect(users[0]?.user).toEqual(updatedUser);
            expect(users[0]?.user['name']).toBe('Updated Name');
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
                lastUserInfoRefresh: new Date(),
                lastIntrospection: new Date(Date.now() - 5000),
            };

            // Store user with separated metadata
            await adapter.storeUser(null, userClaims, metadata);

            const retrievedResult = await adapter.findUser(
                createJwtTokenContext('test-metadata-user'),
            );

            expect(retrievedResult).toBeDefined();
            expect(retrievedResult?.user.sub).toBe('test-metadata-user');
            expect(retrievedResult?.user['name']).toBe('Test User');
            expect(retrievedResult?.user['email']).toBe('test@example.com');
            expect(retrievedResult?.metadata.lastUserInfoRefresh).toBe(
                metadata.lastUserInfoRefresh,
            );
            expect(retrievedResult?.metadata.lastIntrospection).toBe(
                metadata.lastIntrospection,
            );
        });

        it('should merge metadata with existing user data', async () => {
            const existingUser: UserClaims = {
                sub: 'existing-user',
                name: 'Existing User',
                email: 'existing@example.com',
                role: 'user',
            };

            const existingMetadata: StorageMetadata = {
                lastUserInfoRefresh: new Date(Date.now() - 10000),
            };

            await adapter.storeUser(
                existingUser,
                existingUser,
                existingMetadata,
            );

            const newClaims = {
                sub: 'existing-user',
                name: 'Updated User',
                email: 'updated@example.com',
                department: 'Engineering',
            };

            const newMetadata = {
                lastUserInfoRefresh: new Date(),
                lastIntrospection: new Date(Date.now() - 1000),
            };

            // Update user with new claims and metadata
            await adapter.storeUser(existingUser, newClaims, newMetadata);

            const updatedResult = await adapter.findUser(
                createJwtTokenContext('existing-user'),
            );

            expect(updatedResult).toBeDefined();
            expect(updatedResult?.user['name']).toBe('Updated User');
            expect(updatedResult?.user['email']).toBe('updated@example.com');
            expect(updatedResult?.user['department']).toBe('Engineering');
            expect(updatedResult?.user['role']).toBe('user'); // Should preserve existing data
            expect(updatedResult?.metadata.lastUserInfoRefresh).toBe(
                newMetadata.lastUserInfoRefresh,
            );
            expect(updatedResult?.metadata.lastIntrospection).toBe(
                newMetadata.lastIntrospection,
            );
        });
    });
});
