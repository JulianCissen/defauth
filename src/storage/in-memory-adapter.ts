import type { StorageAdapter, UserRecord } from '../types/index.js';

/**
 * In-memory storage adapter implementation
 * This is the default storage adapter that keeps user data in memory
 */
export class InMemoryStorageAdapter implements StorageAdapter {
    private users: Map<string, UserRecord> = new Map();

    /**
     * Find a user by their subject identifier
     * @param sub - The subject identifier
     * @returns Promise resolving to user record or null if not found
     */
    async findUser(sub: string): Promise<UserRecord | null> {
        return this.users.get(sub) || null;
    }

    /**
     * Store or update user data
     * @param user - The user record to store
     * @returns Promise resolving when storage is complete
     */
    async storeUser(user: UserRecord): Promise<void> {
        this.users.set(user.sub, user);
    }

    /**
     * Clear all stored users (useful for testing)
     */
    clear(): void {
        this.users.clear();
    }

    /**
     * Get all stored users (useful for debugging)
     * @returns Array of all user records
     */
    getAllUsers(): UserRecord[] {
        return Array.from(this.users.values());
    }
}
