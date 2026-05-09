import { z } from 'zod';

/**
 * Type for OAuth2 introspection response
 * Re-exported from oauth4webapi for convenience
 */
export type { IntrospectionResponse } from 'oauth4webapi';

/**
 * Zod schema for introspection response validation
 * Only requires the 'active' field, all other fields are optional
 */
export const IntrospectionResponseSchema = z
    .object({
        // The only required field from introspection is the 'active' status
        active: z.boolean(),
        // Subject identifier is optional in the response but required for our use
        sub: z.string().optional(),
    })
    .catchall(z.unknown()); // Allow any other fields from the introspection response

/**
 * Token type enumeration
 */
export enum TokenType {
    JWT = 'jwt',
    OPAQUE = 'opaque',
}
