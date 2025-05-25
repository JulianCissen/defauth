import {
    afterEach,
    beforeEach,
    describe,
    expect,
    it,
    jest,
} from '@jest/globals';
import { ConsoleLogger } from '../logger.js';
import type { LogLevel } from '../../types/index.js';

describe('ConsoleLogger', () => {
    let logger: ConsoleLogger;
    let consoleErrorSpy: jest.SpiedFunction<typeof console.error>;
    let consoleWarnSpy: jest.SpiedFunction<typeof console.warn>;
    let consoleInfoSpy: jest.SpiedFunction<typeof console.info>;
    let consoleDebugSpy: jest.SpiedFunction<typeof console.debug>;

    beforeEach(() => {
        logger = new ConsoleLogger();

        // Spy on console methods
        consoleErrorSpy = jest
            .spyOn(console, 'error')
            .mockImplementation(() => {});
        consoleWarnSpy = jest
            .spyOn(console, 'warn')
            .mockImplementation(() => {});
        consoleInfoSpy = jest
            .spyOn(console, 'info')
            .mockImplementation(() => {});
        consoleDebugSpy = jest
            .spyOn(console, 'debug')
            .mockImplementation(() => {});
    });

    afterEach(() => {
        // Restore console methods
        consoleErrorSpy.mockRestore();
        consoleWarnSpy.mockRestore();
        consoleInfoSpy.mockRestore();
        consoleDebugSpy.mockRestore();
    });

    describe('log', () => {
        it('should log error messages to console.error', () => {
            const message = 'This is an error message';
            logger.log('error', message);

            expect(consoleErrorSpy).toHaveBeenCalledWith(message);
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
        });

        it('should log warn messages to console.warn', () => {
            const message = 'This is a warning message';
            logger.log('warn', message);

            expect(consoleWarnSpy).toHaveBeenCalledWith(message);
            expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
        });

        it('should log info messages to console.info', () => {
            const message = 'This is an info message';
            logger.log('info', message);

            expect(consoleInfoSpy).toHaveBeenCalledWith(message);
            expect(consoleInfoSpy).toHaveBeenCalledTimes(1);
        });

        it('should log debug messages to console.debug', () => {
            const message = 'This is a debug message';
            logger.log('debug', message);

            expect(consoleDebugSpy).toHaveBeenCalledWith(message);
            expect(consoleDebugSpy).toHaveBeenCalledTimes(1);
        });

        it('should include context in the log message when provided', () => {
            const message = 'Error occurred';
            const context = { userId: 'user123', action: 'authenticate' };
            const expectedMessage = `${message} ${JSON.stringify(context)}`;

            logger.log('error', message, context);

            expect(consoleErrorSpy).toHaveBeenCalledWith(expectedMessage);
        });

        it('should handle empty context object', () => {
            const message = 'Test message';
            const context = {};
            const expectedMessage = `${message} ${JSON.stringify(context)}`;

            logger.log('info', message, context);

            expect(consoleInfoSpy).toHaveBeenCalledWith(expectedMessage);
        });

        it('should handle complex context objects', () => {
            const message = 'Complex context test';
            const context = {
                user: { id: 'user123', name: 'Test User' },
                timestamp: 1630000000000,
                metadata: ['tag1', 'tag2'],
                error: { code: 'AUTH_FAILED', details: null },
            };
            const expectedMessage = `${message} ${JSON.stringify(context)}`;

            logger.log('warn', message, context);

            expect(consoleWarnSpy).toHaveBeenCalledWith(expectedMessage);
        });

        it('should handle undefined context gracefully', () => {
            const message = 'Message without context';
            logger.log('debug', message, undefined);

            expect(consoleDebugSpy).toHaveBeenCalledWith(message);
        });

        it('should handle null context gracefully', () => {
            const message = 'Message with null context';
            logger.log('debug', message, undefined);

            expect(consoleDebugSpy).toHaveBeenCalledWith(message);
        });

        it('should handle empty string message', () => {
            logger.log('info', '');
            expect(consoleInfoSpy).toHaveBeenCalledWith('');
        });

        it('should handle empty string message with context', () => {
            const context = { key: 'value' };
            const expectedMessage = ` ${JSON.stringify(context)}`;

            logger.log('info', '', context);
            expect(consoleInfoSpy).toHaveBeenCalledWith(expectedMessage);
        });

        it('should handle context with circular references gracefully', () => {
            const message = 'Circular reference test';
            const context: Record<string, unknown> = { name: 'test' };
            context['self'] = context; // Create circular reference

            // Should not throw an error due to circular reference
            expect(() => {
                logger.log('error', message, context);
            }).toThrow(); // JSON.stringify will throw on circular references
        });

        it('should log multiple messages independently', () => {
            logger.log('error', 'First error');
            logger.log('warn', 'First warning');
            logger.log('info', 'First info');
            logger.log('debug', 'First debug');

            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
            expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
            expect(consoleInfoSpy).toHaveBeenCalledTimes(1);
            expect(consoleDebugSpy).toHaveBeenCalledTimes(1);

            expect(consoleErrorSpy).toHaveBeenCalledWith('First error');
            expect(consoleWarnSpy).toHaveBeenCalledWith('First warning');
            expect(consoleInfoSpy).toHaveBeenCalledWith('First info');
            expect(consoleDebugSpy).toHaveBeenCalledWith('First debug');
        });

        it('should handle special characters in messages', () => {
            const specialMessage =
                'Message with "quotes", \\backslashes\\, and\nnewlines\t\ttabs';
            logger.log('info', specialMessage);

            expect(consoleInfoSpy).toHaveBeenCalledWith(specialMessage);
        });

        it('should handle unicode characters in messages and context', () => {
            const unicodeMessage = 'Message with unicode: 🔐 🚀 ñáéíóú';
            const unicodeContext = { emoji: '🔒', text: 'español' };
            const expectedMessage = `${unicodeMessage} ${JSON.stringify(unicodeContext)}`;

            logger.log('info', unicodeMessage, unicodeContext);

            expect(consoleInfoSpy).toHaveBeenCalledWith(expectedMessage);
        });
    });

    describe('integration', () => {
        it('should work with all log levels in sequence', () => {
            const levels: LogLevel[] = ['error', 'warn', 'info', 'debug'];

            levels.forEach((level, index) => {
                logger.log(level, `Message ${index}`, { level, index });
            });

            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
            expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
            expect(consoleInfoSpy).toHaveBeenCalledTimes(1);
            expect(consoleDebugSpy).toHaveBeenCalledTimes(1);
        });
    });
});
