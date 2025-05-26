import type {
    StorageMetadata,
    UserInfoRefreshCondition,
} from '../types/index.js';

/**
 * Default condition that checks if last user info refresh was over 1 hour ago
 * @param user - The user record to check
 * @returns true if refresh is needed
 */
export const defaultUserInfoRefreshCondition: UserInfoRefreshCondition<
    StorageMetadata
> = (user: StorageMetadata): boolean => {
    if (user.lastUserInfoRefresh) {
        const oneHourAgo = Date.now() - 60 * 60 * 1000; // 1 hour in milliseconds
        return user.lastUserInfoRefresh <= oneHourAgo;
    }

    return true; // Never refreshed before
};
