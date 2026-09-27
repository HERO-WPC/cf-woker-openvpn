// Resolve a path relative to the repository root (from an ESM module in test/).
// This keeps the test scripts runnable after cloning, without machine-specific
// absolute paths.
import { fileURLToPath } from 'node:url';

export const root = (...parts) => fileURLToPath(new URL('../' + parts.join('/'), import.meta.url));