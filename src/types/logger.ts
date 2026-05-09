/**
 * Log levels for the logger interface
 */
export type LogLevel = 'error' | 'warn' | 'info' | 'debug';

/**
 * Logger interface for custom logging implementations
 */
export interface Logger {
    /**
     * Log a message with the specified level
     * @param level - The log level
     * @param message - The log message
     * @param context - Optional context object with additional information
     */
    log(
        level: LogLevel,
        message: string,
        context?: Record<string, unknown>,
    ): void;
}
