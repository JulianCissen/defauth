import type { LogLevel, Logger } from '../types/index.js';

/**
 * Default console-based logger implementation
 */
export class ConsoleLogger implements Logger {
    /**
     * Log a message with the specified level using console methods
     * @param level - The log level
     * @param message - The log message
     * @param context - Optional context object with additional information
     */
    log(
        level: LogLevel,
        message: string,
        context?: Record<string, unknown>,
    ): void {
        const logMessage = context
            ? `${message} ${JSON.stringify(context)}`
            : message;

        switch (level) {
            case 'error':
                console.error(logMessage);
                break;
            case 'warn':
                console.warn(logMessage);
                break;
            case 'info':
                console.info(logMessage);
                break;
            case 'debug':
                console.debug(logMessage);
                break;
        }
    }
}
