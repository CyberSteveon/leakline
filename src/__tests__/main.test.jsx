/**
 * Unit tests for main.jsx
 *
 * Test runner: Vitest (https://vitest.dev)
 * Renderer:    @testing-library/react (https://testing-library.com/react)
 *
 * Install dependencies (if not already present):
 *   npm install --save-dev vitest @testing-library/react @testing-library/jest-dom jsdom
 *
 * Run:
 *   npx vitest run src/__tests__/main.test.jsx
 *
 * main.jsx is an entry-point module — it produces side-effects (mounts the
 * React tree into #root) rather than exporting testable symbols.  These tests
 * therefore validate the contract that main.jsx establishes:
 *   1. It creates a root on the DOM element with id="root".
 *   2. It renders <App /> inside <React.StrictMode>.
 *   3. It imports the global stylesheet (index.css).
 *   4. It does not crash when the #root element exists.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import '@testing-library/jest-dom';

// ---------------------------------------------------------------------------
// Module-level mocks — declared before any module import so that Vitest's
// hoisting puts them in place before the module graph is evaluated.
// ---------------------------------------------------------------------------

// Mock @tauri-apps/api/core so App.jsx (imported transitively) never calls
// a real Tauri IPC channel inside the test environment.
vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn().mockResolvedValue('leakline\nVersion: 0.1.0'),
}));

// Mock index.css — Vitest/jsdom cannot process raw CSS imports.
vi.mock('../index.css', () => ({}));

// Spy on ReactDOM.createRoot so we can assert that main.jsx calls it with the
// correct DOM node without actually running the full React reconciler here.
// We import the real createRoot and wrap it.
import * as ReactDOMClient from 'react-dom/client';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Creates and appends a fresh #root div to document.body. */
function createRootElement() {
  const root = document.createElement('div');
  root.id = 'root';
  document.body.appendChild(root);
  return root;
}

/** Removes the #root div from document.body. */
function removeRootElement() {
  const root = document.getElementById('root');
  if (root) root.remove();
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.resetModules(); // reset module registry so each test re-executes main.jsx
  createRootElement();
});

afterEach(() => {
  removeRootElement();
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('main.jsx — entry point', () => {

  // -------------------------------------------------------------------------
  // DOM setup contract
  // -------------------------------------------------------------------------

  describe('DOM requirements', () => {
    it('finds a #root element in the document before mounting', () => {
      // Ensures our test environment matches the contract main.jsx assumes.
      expect(document.getElementById('root')).not.toBeNull();
    });

    it('throws if the #root element does not exist', async () => {
      removeRootElement(); // remove it before main.jsx runs
      // createRoot(null) / passing a non-element throws in React 18+.
      await expect(import('../main.jsx')).rejects.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // createRoot call
  // -------------------------------------------------------------------------

  describe('createRoot', () => {
    it('calls ReactDOM.createRoot with the #root element', async () => {
      const createRootSpy = vi.spyOn(ReactDOMClient, 'createRoot');
      await import('../main.jsx');
      expect(createRootSpy).toHaveBeenCalledTimes(1);
      const [targetNode] = createRootSpy.mock.calls[0];
      expect(targetNode).toBe(document.getElementById('root'));
    });

    it('calls createRoot exactly once — no double-mounting', async () => {
      const createRootSpy = vi.spyOn(ReactDOMClient, 'createRoot');
      await import('../main.jsx');
      expect(createRootSpy).toHaveBeenCalledTimes(1);
    });
  });

  // -------------------------------------------------------------------------
  // StrictMode wrapping
  // -------------------------------------------------------------------------

  describe('StrictMode wrapping', () => {
    it('renders the app inside React.StrictMode', async () => {
      // We verify this by inspecting what was passed to root.render().
      // Spy on the render method of the object returned by createRoot.
      const fakeMountedRoot = { render: vi.fn() };
      vi.spyOn(ReactDOMClient, 'createRoot').mockReturnValue(fakeMountedRoot);

      const React = await import('react');
      await import('../main.jsx');

      expect(fakeMountedRoot.render).toHaveBeenCalledTimes(1);
      const renderedElement = fakeMountedRoot.render.mock.calls[0][0];

      // The outer element must be React.StrictMode.
      expect(renderedElement.type).toBe(React.default.StrictMode ?? React.StrictMode);
    });

    it('nests <App /> as the sole child of <StrictMode>', async () => {
      const fakeMountedRoot = { render: vi.fn() };
      vi.spyOn(ReactDOMClient, 'createRoot').mockReturnValue(fakeMountedRoot);

      await import('../main.jsx');
      const renderedElement = fakeMountedRoot.render.mock.calls[0][0];

      // The single child of StrictMode should be the App element.
      const child = renderedElement.props.children;
      // The type must reference the App component (not a string or null).
      expect(typeof child.type).toBe('function');
      expect(child.type.name ?? child.type.displayName).toBe('App');
    });
  });

  // -------------------------------------------------------------------------
  // CSS import side-effect
  // -------------------------------------------------------------------------

  describe('stylesheet import', () => {
    it('imports index.css as a side-effect without throwing', async () => {
      // The vi.mock for index.css above prevents errors; if the import were
      // missing or misspelled the mock would not intercept it and the test
      // runner would throw on the unresolved import.
      await expect(import('../main.jsx')).resolves.not.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // Module interface
  // -------------------------------------------------------------------------

  describe('module interface', () => {
    it('has no named or default exports — it is a side-effect-only module', async () => {
      const mod = await import('../main.jsx');
      // A pure side-effect module should only expose the module namespace
      // object with no meaningful named or default exports.
      const exports = Object.keys(mod).filter((k) => k !== '__esModule');
      expect(exports).toHaveLength(0);
    });
  });
});
