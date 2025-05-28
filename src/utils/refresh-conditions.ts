import type { StorageMetadata } from '../types/index.js';

/**
 * Default condition that checks if last user info refresh was over 1 hour ago
 * @param _user - The user record (unused in default implementation)
 * @param metadata - The metadata to check
 * @returns true if refresh is needed
 */
export const defaultUserInfoRefreshCondition = <TUser>(
    _user: TUser,
    metadata: StorageMetadata,
): boolean => {
    if (metadata.lastUserInfoRefresh) {
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000); // 1 hour ago
        return metadata.lastUserInfoRefresh <= oneHourAgo;
    }

    return true; // Never refreshed before
};
