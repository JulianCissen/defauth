import { 
    Defauth, 
    InMemoryStorageAdapter, 
    ConsoleLogger,
    // Error classes for structured error handling
    InitializationError,
    TokenValidationError,
    JwtVerificationError,
    UserInfoError,
    IntrospectionError,
} from '../src/index.js';
import type { Logger, LogLevel } from '../src/index.js';

// Example usage of the Defauth library

/**
 * Custom logger implementation example
 */
class CustomLogger implements Logger {
    log(level: LogLevel, message: string, context?: Record<string, unknown>): void {
        const timestamp = new Date().toISOString();
        const contextStr = context ? ` [Context: ${JSON.stringify(context)}]` : '';
        console.log(`[${timestamp}] [${level.toUpperCase()}] ${message}${contextStr}`);
    }
}

/**
 * Example demonstrating DefAuth's hybrid approach with UserInfo and token introspection
 */
async function example() {
    // Example 1: Initialize using the static create method (recommended approach)
    // This ensures the authenticator is fully initialized before use
    const authWithCustomLogger = await Defauth.create({
        issuer: 'https://your-oidc-provider.com',
        clientId: 'your-client-id',
        clientSecret: 'your-client-secret',
        
        // Custom logger implementation
        logger: new CustomLogger(),
        
        // Throw errors when UserInfo endpoint fails instead of logging warnings
        throwOnUserInfoFailure: true,
        
        storageAdapter: new InMemoryStorageAdapter(),
    });

    // Example 2: Initialize with default console logger using the static create method
    const authWithConsoleLogger = await Defauth.create({
        issuer: 'https://your-oidc-provider.com',
        clientId: 'your-client-id',
        clientSecret: 'your-client-secret',
        
        // Explicitly use the default console logger
        logger: new ConsoleLogger(),
        
        // Log warnings but don't throw (default behavior)
        throwOnUserInfoFailure: false,
    });

    // Example 3: Advanced configuration with custom refresh conditions
    const authWithCustomRefresh = await Defauth.create({
        issuer: 'https://your-oidc-provider.com',
        clientId: 'your-client-id',
        clientSecret: 'your-client-secret', // Provided for confidential clients

        // Optional: Use custom storage adapter
        storageAdapter: new InMemoryStorageAdapter(),

        // Optional: Custom refresh condition for UserInfo
        userInfoRefreshCondition: (user, metadata) => {
            // Refresh UserInfo every 30 minutes instead of default 1 hour
            if (!metadata.lastUserInfoRefresh) return true;

            const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);
            return metadata.lastUserInfoRefresh <= thirtyMinutesAgo;
        },
    });
    
    // Example 4: Public client configuration
    const publicClientAuth = await Defauth.create({
        issuer: 'https://your-oidc-provider.com',
        clientId: 'your-public-client-id',
        // No clientSecret needed for public clients (SPAs, mobile apps, etc.)
        
        // Using default storage adapter and refresh conditions
    });

    // Example JWT token (this would come from your request headers)
    const jwtToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...';

    // Example opaque token
    const opaqueToken = 'abc123def456ghi789';

    try {
        // Standard JWT token validation (signature verification + UserInfo)
        const userFromJwt = await authWithCustomRefresh.getUser(jwtToken);
        console.log('User from JWT (standard validation):', {
            sub: (userFromJwt as any).sub,
            email: (userFromJwt as any).email,
            name: (userFromJwt as any).name,
        });

        // JWT token with forced introspection (for high-security scenarios)
        const userFromJwtWithIntrospection = await authWithCustomRefresh.getUser(jwtToken, { 
            forceIntrospection: true 
        });
        console.log('User from JWT with forced introspection:', {
            sub: (userFromJwtWithIntrospection as any).sub,
            email: (userFromJwtWithIntrospection as any).email,
            name: (userFromJwtWithIntrospection as any).name,
        });

        // Get user from opaque token (always introspected + UserInfo when available)
        const userFromOpaque = await publicClientAuth.getUser(opaqueToken);
        console.log('User from opaque token:', {
            sub: (userFromOpaque as any).sub,
            email: (userFromOpaque as any).email,
            name: (userFromOpaque as any).name,
        });
    } catch (error) {
        // Example of structured error handling with custom error classes
        // Import these from '../src/index.js': InitializationError, TokenValidationError, 
        // JwtVerificationError, UserInfoError, IntrospectionError
        
        if (error.constructor.name === 'InitializationError') {
            console.error('OIDC client initialization failed:', error.message);
            console.error('Original cause:', error.cause?.message);
        } else if (error.constructor.name === 'JwtVerificationError') {
            console.error('JWT signature verification failed:', error.message);
            // This might indicate token tampering or expired keys
        } else if (error.constructor.name === 'UserInfoError') {
            console.error('UserInfo endpoint failed:', error.message);
            // User profile data might be incomplete
        } else if (error.constructor.name === 'IntrospectionError') {
            console.error('Token introspection failed:', error.message);
            // Authorization server might be down
        } else if (error.constructor.name === 'TokenValidationError') {
            console.error('Token validation failed:', error.message);
            // General token validation error
        } else {
            // Legacy error message checking for backward compatibility
            if (error.message?.includes('Token is not active')) {
                console.error('Token expired or invalid');
            } else {
                console.error('Unexpected authentication error:', error.message);
            }
        }
    }
}

// Uncomment to run the example
// example().catch(console.error);
