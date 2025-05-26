import type {
    StorageAdapter,
    StorageMetadata,
    TokenContext,
    UserClaims,
} from '../types/index.js';

/**
 * In-memory storage adapter implementation
 * This is the default storage adapter that keeps user data in memory
 */
export class InMemoryStorageAdapter<TUser extends StorageMetadata>
    implements StorageAdapter<TUser>
{
    private users: Map<string, TUser> = new Map();

    /**
     * Find a user by their token context
     * @param context - The token validation context with full token information
     * @returns Promise resolving to user record or null if not found
     */
    async findUser(context: TokenContext): Promise<TUser | null> {
        return this.users.get(context.sub) || null;
    }

    /**
     * Store or update user data
     * @param user - The user record to store (null for new users)
     * @param newClaims - The new claims to merge with the user record
     * @param metadata - Storage metadata (timestamps, etc.)
     * @returns Promise resolving when storage is complete
     */
    async storeUser(
        user: TUser | null,
        newClaims: UserClaims,
        metadata: StorageMetadata,
    ): Promise<TUser> {
        // Create user record from claims if user is null, otherwise merge with existing
        const result =
            user || ({ ...newClaims, ...metadata } as unknown as TUser);
        Object.assign(result, newClaims, metadata);

        this.users.set(newClaims.sub, result);

        return Promise.resolve(result);
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
    getAllUsers(): TUser[] {
        return Array.from(this.users.values());
    }
}
