import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from './App';
import { OperatorApi } from './api';

afterEach(cleanup);
function api() {
  return new OperatorApi(
    vi.fn<typeof fetch>().mockImplementation((url) => {
      if (url === '/api/operator/bootstrap')
        return Promise.resolve(
          new Response(
            JSON.stringify({ csrf: 'synthetic', backend: 'sqlcipher', service_mode: false }),
          ),
        );
      return Promise.resolve(
        new Response(JSON.stringify({ error: 'authentication_failed' }), { status: 401 }),
      );
    }),
  );
}
describe('operator entry', () => {
  it('defaults to dark and changes appearance without browser persistence', async () => {
    const user = userEvent.setup();
    render(<App api={api()} />);
    expect(document.documentElement.dataset['theme']).toBe('dark');
    await user.click(screen.getByRole('button', { name: 'Switch to light mode' }));
    expect(document.documentElement.dataset['theme']).toBe('light');
    expect(localStorage.length).toBe(0);
  });
  it('keeps unauthenticated credential changes disabled and clears a submitted password', async () => {
    const user = userEvent.setup();
    render(<App api={api()} />);
    expect(screen.getByRole('button', { name: 'Add credential' })).toBeDisabled();
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Open vault' })).toBeEnabled();
    });
    await user.type(screen.getByLabelText('Vault passphrase'), 'synthetic rejected passphrase');
    await user.click(screen.getByRole('button', { name: 'Open vault' }));
    await screen.findByRole('alert');
    expect(screen.getByLabelText('Vault passphrase')).toHaveValue('');
    expect(screen.getByRole('button', { name: 'Add credential' })).toBeDisabled();
  });
});
