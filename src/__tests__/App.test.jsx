/**
 * Unit tests for App.jsx
 *
 * Test runner: Vitest (https://vitest.dev)
 * Renderer:    @testing-library/react (https://testing-library.com/react)
 *
 * Install dependencies (if not already present):
 *   npm install --save-dev vitest @testing-library/react @testing-library/jest-dom jsdom
 *
 * Run:
 *   npx vitest run src/__tests__/App.test.jsx
 *   # or via the npm script added in vitest.config.js: npm test
 *
 * The @tauri-apps/api/core module is automatically mocked below so the tests
 * run in a pure Node/jsdom environment without a Tauri host.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import '@testing-library/jest-dom';
import React from 'react';

// ---------------------------------------------------------------------------
// Mock @tauri-apps/api/core before importing App so the module system sees
// the mock when App.jsx is evaluated for the first time.
// ---------------------------------------------------------------------------
vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

// Import after mocking so the mock is in place.
import { invoke } from '@tauri-apps/api/core';
import App from '../App.jsx';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Renders <App /> and returns the Testing Library utilities. */
function renderApp() {
  return render(<App />);
}

/** Resolves the pending invoke promise and flushes React state updates. */
async function flushInvoke() {
  await act(async () => {
    // waitFor drains the microtask queue so useEffect + setState settle.
    await waitFor(() => {});
  });
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

beforeEach(() => {
  // Reset the mock before each test to avoid cross-test pollution.
  vi.resetAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('App', () => {
  // -------------------------------------------------------------------------
  // Initial render
  // -------------------------------------------------------------------------

  describe('initial render', () => {
    it('renders a div wrapper without crashing', () => {
      invoke.mockResolvedValue('leakline\nVersion: 0.1.0');
      const { container } = renderApp();
      expect(container.querySelector('div')).toBeInTheDocument();
    });

    it('shows the initial placeholder value "0" before the IPC call resolves', () => {
      // Invoke never resolves during this test — simulates a slow IPC call.
      invoke.mockReturnValue(new Promise(() => {}));
      renderApp();
      expect(screen.getByText('0')).toBeInTheDocument();
    });
  });

  // -------------------------------------------------------------------------
  // useEffect → invoke('app_info')
  // -------------------------------------------------------------------------

  describe('IPC call on mount', () => {
    it('calls invoke with the command name "app_info" exactly once on mount', async () => {
      invoke.mockResolvedValue('leakline\nVersion: 0.1.0');
      renderApp();
      await flushInvoke();
      expect(invoke).toHaveBeenCalledTimes(1);
      expect(invoke).toHaveBeenCalledWith('app_info');
    });

    it('does not call invoke with any extra arguments', async () => {
      invoke.mockResolvedValue('leakline\nVersion: 0.1.0');
      renderApp();
      await flushInvoke();
      // The call must be invoke('app_info') — no payload object, no options.
      expect(invoke).toHaveBeenCalledWith('app_info');
      const [command, ...extraArgs] = invoke.mock.calls[0];
      expect(command).toBe('app_info');
      expect(extraArgs).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // State update after IPC resolves
  // -------------------------------------------------------------------------

  describe('displaying app info returned by the backend', () => {
    it('renders the app name returned by invoke', async () => {
      invoke.mockResolvedValue('leakline\nVersion: 0.1.0');
      renderApp();
      await waitFor(() => expect(screen.getByText('leakline\nVersion: 0.1.0')).toBeInTheDocument());
    });

    it('replaces the initial "0" placeholder with the resolved value', async () => {
      const appInfo = 'leakline\nVersion: 0.1.0';
      invoke.mockResolvedValue(appInfo);
      renderApp();
      await waitFor(() => {
        expect(screen.queryByText('0')).not.toBeInTheDocument();
        expect(screen.getByText(appInfo)).toBeInTheDocument();
      });
    });

    it('renders arbitrary strings returned by the backend verbatim', async () => {
      const arbitraryResponse = 'my-app\nVersion: 99.0.0-beta';
      invoke.mockResolvedValue(arbitraryResponse);
      renderApp();
      await waitFor(() =>
        expect(screen.getByText(arbitraryResponse)).toBeInTheDocument()
      );
    });

    it('renders an empty string without errors when the backend returns ""', async () => {
      invoke.mockResolvedValue('');
      const { container } = renderApp();
      await flushInvoke();
      // The div should exist but be empty (or contain only whitespace).
      const wrapper = container.querySelector('div');
      expect(wrapper).toBeInTheDocument();
      expect(wrapper.textContent).toBe('');
    });
  });

  // -------------------------------------------------------------------------
  // Error handling (invoke rejects)
  // -------------------------------------------------------------------------

  describe('IPC error handling', () => {
    it('keeps displaying the initial "0" value when invoke rejects', async () => {
      // Suppress the unhandled-rejection console noise during the test.
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      invoke.mockRejectedValue(new Error('IPC failure'));
      renderApp();
      await flushInvoke();
      // App.jsx has no .catch(), so the state stays at the initial value.
      expect(screen.getByText('0')).toBeInTheDocument();
      consoleSpy.mockRestore();
    });
  });

  // -------------------------------------------------------------------------
  // DOM structure
  // -------------------------------------------------------------------------

  describe('DOM structure', () => {
    it('wraps its content in exactly one top-level div', async () => {
      invoke.mockResolvedValue('leakline\nVersion: 0.1.0');
      const { container } = renderApp();
      await flushInvoke();
      // The root rendered by render() is a <div> wrapper added by RTL.
      // The component itself renders one <div> child.
      const divs = container.querySelectorAll('div');
      expect(divs).toHaveLength(1);
    });

    it('does not render any buttons, inputs, or form elements', async () => {
      invoke.mockResolvedValue('leakline\nVersion: 0.1.0');
      const { container } = renderApp();
      await flushInvoke();
      expect(container.querySelector('button')).toBeNull();
      expect(container.querySelector('input')).toBeNull();
      expect(container.querySelector('form')).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // React.StrictMode double-invocation (development mode behaviour)
  // -------------------------------------------------------------------------

  describe('React StrictMode compatibility', () => {
    it('renders correctly when wrapped in React.StrictMode', async () => {
      invoke.mockResolvedValue('leakline\nVersion: 0.1.0');
      render(
        <React.StrictMode>
          <App />
        </React.StrictMode>
      );
      await waitFor(() =>
        expect(screen.getByText('leakline\nVersion: 0.1.0')).toBeInTheDocument()
      );
    });

    it('still reaches a stable final state under StrictMode double-invoke', async () => {
      // StrictMode calls effects twice in development. Both calls should
      // resolve the same string and the final rendered text must be stable.
      invoke.mockResolvedValue('leakline\nVersion: 0.1.0');
      render(
        <React.StrictMode>
          <App />
        </React.StrictMode>
      );
      await waitFor(() => {
        const text = screen.getByText('leakline\nVersion: 0.1.0');
        expect(text).toBeInTheDocument();
      });
    });
  });
});
