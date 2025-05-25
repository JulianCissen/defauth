---
applyTo: '**/*.{ts}'
---
- Don't fix linting errors. I will fix them myself.
- Keep function size in mind. Functions should be small and focused. If you're editing a function, consider if it can be split into smaller functions.
- Keep component size in mind. Components should be small and focused. If you're editing a component, consider splitting it up if it has multiple responsibilities or grows too large.
- Don't add unnecessary comments. If the code is self-explanatory, no comment is needed.
- Don't add unnecessary type annotations. TypeScript can infer types in many cases, and adding redundant annotations can clutter the code.
- Add JSDoc comments for public functions and classes. Use the `@param` tag for parameters and `@returns` for return values. Make sure to add JSDoc also for all function styles (declaration, expression and arrow).
- Focus on readability and maintainability. Write code that is easy to understand and follow, even if it means being more verbose.
