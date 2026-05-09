import { z } from 'zod';

/**
 * Zod schema for user claims validation
 * Only requires the 'sub' claim, all other claims are optional
 */
export const UserClaimsSchema = z
    .object({
        // Only the subject identifier is required
        sub: z.string(),
    })
    .catchall(z.unknown()); // Allow any other claims

/**
 * User claims interface representing the standardized user information
 * Only requires the 'sub' claim, all other claims are handled dynamically
 */
export interface UserClaims {
    /** Subject identifier - unique user ID (required) */
    sub: string;
    /**
     * Additional claims from tokens or introspection
     * This allows for any standard OIDC claims (email, name, etc.)
     * as well as custom claims from identity providers
     */
    [key: string]: unknown;
}

/**
 * Zod schema for user record validation
 */
export const UserRecordSchema = UserClaimsSchema.extend({
    lastUserInfoRefresh: z.instanceof(Date).optional(),
    lastIntrospection: z.instanceof(Date).optional(),
});
