import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import React from 'react';

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

import { invoke } from '@tauri-apps/api/core';
import App from '../src/App.jsx';

describe('App Component (Additional Tests)', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders the initial state as "0"', () => {
    invoke.mockReturnValue(new Promise(() => {}));
    render(<App />);
    expect(screen.getByText('0')).toBeDefined();
  });

  it('fetches app_info and displays it correctly', async () => {
    invoke.mockResolvedValue('leakline\nVersion: 0.1.0');
    render(<App />);
    
    await waitFor(() => {
      expect(screen.getByText('leakline\nVersion: 0.1.0')).toBeDefined();
    });
    
    expect(invoke).toHaveBeenCalledWith('app_info');
    expect(invoke).toHaveBeenCalledTimes(1);
  });
});
