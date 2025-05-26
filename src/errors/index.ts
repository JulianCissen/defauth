/**
 * Base error class for all DefAuth errors
 */
export class DefAuthError extends Error {
    /**
     * @param message - Error message
     * @param cause - The original error that caused this error
     */
    constructor(message: string, cause?: Error) {
        super(cause ? `${message}: ${cause.message}` : message);
        this.name = 'DefAuthError';
        this.cause = cause;
    }
}

/**
 * Error thrown when OIDC client initialization fails
 */
export class InitializationError extends DefAuthError {
    /**
     * @param message - Error message
     * @param cause - The original error that caused this error
     */
    constructor(message: string, cause?: Error) {
        super(message, cause);
        this.name = 'InitializationError';
    }
}

/**
 * Error thrown when token validation fails
 */
export class TokenValidationError extends DefAuthError {
    /**
     * @param message - Error message
     * @param cause - The original error that caused this error
     */
    constructor(message: string, cause?: Error) {
        super(message, cause);
        this.name = 'TokenValidationError';
    }
}

/**
 * Error thrown when user info fetching fails
 */
export class UserInfoError extends DefAuthError {
    /**
     * @param message - Error message
     * @param cause - The original error that caused this error
     */
    constructor(message: string, cause?: Error) {
        super(message, cause);
        this.name = 'UserInfoError';
    }
}

/**
 * Error thrown when token introspection fails
 */
export class IntrospectionError extends DefAuthError {
    /**
     * @param message - Error message
     * @param cause - The original error that caused this error
     */
    constructor(message: string, cause?: Error) {
        super(message, cause);
        this.name = 'IntrospectionError';
    }
}

/**
 * Error thrown when JWT signature verification fails
 */
export class JwtVerificationError extends TokenValidationError {
    /**
     * @param message - Error message
     * @param cause - The original error that caused this error
     */
    constructor(message: string, cause?: Error) {
        super(message, cause);
        this.name = 'JwtVerificationError';
    }
}
