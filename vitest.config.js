/**
 * Vitest configuration for leakline frontend tests.
 *
 * Install the required dev dependencies before running:
 *   npm install --save-dev vitest @testing-library/react @testing-library/jest-dom jsdom
 *
 * Then run:
 *   npx vitest run          # run all tests once
 *   npx vitest              # watch mode
 *   npx vitest --coverage   # with coverage (also needs @vitest/coverage-v8)
 */

import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    // Use jsdom to provide a browser-like DOM environment.
    environment: 'jsdom',

    // Automatically import @testing-library/jest-dom matchers in every test file.
    setupFiles: ['./src/__tests__/setup.js'],

    // Glob pattern that finds all test files in __tests__ directories.
    include: ['src/__tests__/**/*.test.{js,jsx}'],

    // Treat .css imports as empty modules (prevents jsdom import errors).
    css: false,

    // Suppress noisy React act() warnings in the Vitest output.
    globals: false,
  },
});
