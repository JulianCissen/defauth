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
export class InMemoryStorageAdapter<
    TUser = UserClaims,
> implements StorageAdapter<TUser> {
    private users: Map<string, { user: TUser; metadata: StorageMetadata }> =
        new Map();

    /**
     * Find a user by their token context
     * @param context - The token validation context with full token information
     * @returns Promise resolving to user record and metadata, or null if not found
     */
    async findUser(context: TokenContext): Promise<{
        user: TUser;
        metadata: StorageMetadata;
    } | null> {
        return this.users.get(context.sub) || null;
    }

    /**
     * Store or update user data
     * @param user - The user record to store (null for new users)
     * @param newClaims - The new claims to merge with the user record
     * @param metadata - Storage metadata (timestamps, etc.)
     * @returns Promise resolving to the stored user and metadata
     */
    async storeUser(
        user: TUser | null,
        newClaims: UserClaims,
        metadata: StorageMetadata,
    ): Promise<TUser> {
        // Create user record from claims if user is null, otherwise merge with existing
        const result = user
            ? ({ ...user, ...newClaims } as TUser)
            : (newClaims as unknown as TUser);

        const entry = { user: result, metadata };
        this.users.set(newClaims.sub, entry);

        return entry.user;
    }

    /**
     * Clear all stored users (useful for testing)
     */
    clear(): void {
        this.users.clear();
    }

    /**
     * Get all stored users (useful for debugging)
     * @returns Array of all user records with metadata
     */
    getAllUsers(): Array<{ user: TUser; metadata: StorageMetadata }> {
        return Array.from(this.users.values());
    }
}
