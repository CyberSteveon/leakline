/**
 * Vitest global test setup.
 *
 * This file runs once before every test file.  It imports
 * @testing-library/jest-dom so that all custom matchers
 * (toBeInTheDocument, toHaveTextContent, etc.) are available
 * in every test without explicit per-file imports.
 */
import '@testing-library/jest-dom';
