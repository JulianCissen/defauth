/**
 * Base error class for all Defauth errors
 */
export class DefauthError extends Error {
    public constructor(message: string, cause?: unknown) {
        super(message, { cause });
        this.name = 'DefauthError';
    }
}

/**
 * Error thrown when OIDC client initialization fails
 */
export class InitializationError extends DefauthError {
    public constructor(message: string, cause?: unknown) {
        super(message, cause);
        this.name = 'InitializationError';
    }
}

/**
 * Error thrown when token validation fails
 */
export class TokenValidationError extends DefauthError {
    public constructor(message: string, cause?: unknown) {
        super(message, cause);
        this.name = 'TokenValidationError';
    }
}

/**
 * Error thrown when user info fetching fails
 */
export class UserInfoError extends DefauthError {
    public constructor(message: string, cause?: unknown) {
        super(message, cause);
        this.name = 'UserInfoError';
    }
}

/**
 * Error thrown when token introspection fails
 */
export class IntrospectionError extends DefauthError {
    public constructor(message: string, cause?: unknown) {
        super(message, cause);
        this.name = 'IntrospectionError';
    }
}

/**
 * Error thrown when JWT signature verification fails
 */
export class JwtVerificationError extends TokenValidationError {
    public constructor(message: string, cause?: unknown) {
        super(message, cause);
        this.name = 'JwtVerificationError';
    }
}

/**
 * Error thrown when custom validation fails
 */
export class CustomValidationError extends TokenValidationError {
    public constructor(message: string, cause?: unknown) {
        super(message, cause);
        this.name = 'CustomValidationError';
    }
}

/**
 * Error thrown when the storage adapter fails
 */
export class StorageError extends DefauthError {
    public constructor(message: string, cause?: unknown) {
        super(message, cause);
        this.name = 'StorageError';
    }
}
