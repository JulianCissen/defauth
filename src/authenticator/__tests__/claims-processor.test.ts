import type { IntrospectionResponse } from 'oauth4webapi';
import { describe, expect, it } from 'vitest';
import type { UserClaims } from '../../types/index.js';
import {
    INTROSPECTION_METADATA_CLAIMS,
    JWT_METADATA_CLAIMS,
    combineClaimsWithPriority,
    extractFromIntrospection,
    extractFromJwt,
    extractUserClaims,
    validateIntrospectionResult,
} from '../claims-processor.js';

describe('extractUserClaims', () => {
    it('should extract sub and other claims', () => {
        const payload = {
            sub: 'user1',
            name: 'Alice',
            email: 'alice@example.com',
        };
        const result = extractUserClaims(payload);

        expect(result.sub).toBe('user1');
        expect(result['name']).toBe('Alice');
        expect(result['email']).toBe('alice@example.com');
    });

    it('should throw when sub is missing', () => {
        expect(() => extractUserClaims({ name: 'Alice' })).toThrow(
            'Payload missing required "sub" claim',
        );
    });

    it('should filter out listed metadata claims', () => {
        const payload = {
            sub: 'user1',
            name: 'Alice',
            client_id: 'cid',
            scope: 'openid',
        };
        const result = extractUserClaims(payload, ['client_id', 'scope']);

        expect(result['name']).toBe('Alice');
        expect(result['client_id']).toBeUndefined();
        expect(result['scope']).toBeUndefined();
    });

    it('should exclude undefined values', () => {
        const payload = { sub: 'user1', empty: undefined, name: 'Alice' };
        const result = extractUserClaims(payload);

        expect(result['empty']).toBeUndefined();
        expect(result['name']).toBe('Alice');
    });
});

describe('extractFromJwt', () => {
    it('should filter all JWT_METADATA_CLAIMS', () => {
        const payload: UserClaims = {
            sub: 'user1',
            name: 'Alice',
            client_id: 'cid',
            scope: 'openid',
            token_type: 'Bearer',
            nbf: 1_000_000,
            jti: 'abc',
        };
        const result = extractFromJwt(payload);

        expect(result.sub).toBe('user1');
        expect(result['name']).toBe('Alice');
        for (const claim of JWT_METADATA_CLAIMS) {
            expect(result[claim]).toBeUndefined();
        }
    });

    it('should keep custom claims not in the metadata list', () => {
        const payload: UserClaims = {
            sub: 'user1',
            org_id: 'org-123',
            roles: ['admin'],
        };
        const result = extractFromJwt(payload);

        expect(result['org_id']).toBe('org-123');
        expect(result['roles']).toEqual(['admin']);
    });
});

describe('extractFromIntrospection', () => {
    it('should filter all INTROSPECTION_METADATA_CLAIMS', () => {
        const response: IntrospectionResponse = {
            active: true,
            sub: 'user1',
            name: 'Alice',
            client_id: 'cid',
            scope: 'openid',
        };
        const result = extractFromIntrospection(response);

        expect(result.sub).toBe('user1');
        expect(result['name']).toBe('Alice');
        for (const claim of INTROSPECTION_METADATA_CLAIMS) {
            expect(result[claim as string]).toBeUndefined();
        }
    });
});

describe('combineClaimsWithPriority', () => {
    it('should keep sub from base', () => {
        const base: UserClaims = { sub: 'user1', name: 'Base' };
        const priority: UserClaims = { sub: 'user1', email: 'p@example.com' };

        const result = combineClaimsWithPriority(base, priority);

        expect(result.sub).toBe('user1');
    });

    it('should let priority claims override base claims', () => {
        const base: UserClaims = {
            sub: 'user1',
            name: 'Base Name',
            email: 'base@example.com',
        };
        const priority: UserClaims = { sub: 'user1', name: 'Priority Name' };

        const result = combineClaimsWithPriority(base, priority);

        expect(result['name']).toBe('Priority Name');
        expect(result['email']).toBe('base@example.com');
    });

    it('should include claims present only in base', () => {
        const base: UserClaims = { sub: 'user1', role: 'admin' };
        const priority: UserClaims = { sub: 'user1', email: 'p@example.com' };

        const result = combineClaimsWithPriority(base, priority);

        expect(result['role']).toBe('admin');
        expect(result['email']).toBe('p@example.com');
    });

    it('should include claims present only in priority', () => {
        const base: UserClaims = { sub: 'user1' };
        const priority: UserClaims = { sub: 'user1', phone: '+1234567890' };

        const result = combineClaimsWithPriority(base, priority);

        expect(result['phone']).toBe('+1234567890');
    });
});

describe('validateIntrospectionResult', () => {
    it('should not throw for active token', () => {
        expect(() =>
            validateIntrospectionResult({ active: true }),
        ).not.toThrow();
    });

    it('should throw TokenValidationError for inactive token', () => {
        expect(() => validateIntrospectionResult({ active: false })).toThrow(
            'Token is not active',
        );
    });
});
