/**
 * Base error class for all Defauth errors
 */
export class DefauthError extends Error {
    /**
     * Creates a new DefauthError.
     * @param message - Error message
     * @param cause - The original error that caused this error
     */
    public constructor(message: string, cause?: Error) {
        super(cause ? `${message}: ${cause.message}` : message);
        this.name = 'DefauthError';
        this.cause = cause;
    }
}

/**
 * Error thrown when OIDC client initialization fails
 */
export class InitializationError extends DefauthError {
    /**
     * Creates a new InitializationError.
     * @param message - Error message
     * @param cause - The original error that caused this error
     */
    public constructor(message: string, cause?: Error) {
        super(message, cause);
        this.name = 'InitializationError';
    }
}

/**
 * Error thrown when token validation fails
 */
export class TokenValidationError extends DefauthError {
    /**
     * Creates a new TokenValidationError.
     * @param message - Error message
     * @param cause - The original error that caused this error
     */
    public constructor(message: string, cause?: Error) {
        super(message, cause);
        this.name = 'TokenValidationError';
    }
}

/**
 * Error thrown when user info fetching fails
 */
export class UserInfoError extends DefauthError {
    /**
     * Creates a new UserInfoError.
     * @param message - Error message
     * @param cause - The original error that caused this error
     */
    public constructor(message: string, cause?: Error) {
        super(message, cause);
        this.name = 'UserInfoError';
    }
}

/**
 * Error thrown when token introspection fails
 */
export class IntrospectionError extends DefauthError {
    /**
     * Creates a new IntrospectionError.
     * @param message - Error message
     * @param cause - The original error that caused this error
     */
    public constructor(message: string, cause?: Error) {
        super(message, cause);
        this.name = 'IntrospectionError';
    }
}

/**
 * Error thrown when JWT signature verification fails
 */
export class JwtVerificationError extends TokenValidationError {
    /**
     * Creates a new JwtVerificationError.
     * @param message - Error message
     * @param cause - The original error that caused this error
     */
    public constructor(message: string, cause?: Error) {
        super(message, cause);
        this.name = 'JwtVerificationError';
    }
}

/**
 * Error thrown when custom validation fails
 */
export class CustomValidationError extends TokenValidationError {
    /**
     * Creates a new CustomValidationError.
     * @param message - Error message
     * @param cause - The original error that caused this error
     */
    public constructor(message: string, cause?: Error) {
        super(message, cause);
        this.name = 'CustomValidationError';
    }
}
