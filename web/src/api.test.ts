import { describe, expect, it, vi } from 'vitest';
import { Effect } from 'effect';
import { OperatorApi } from './api';

function respond(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
describe('operator transport', () => {
  it('refuses malformed metadata instead of trusting an untyped response', async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(
        respond({ connections: [{ id: 'demo/one', value: 'must-not-be-rendered' }] }),
      );
    await expect(Effect.runPromise(new OperatorApi(fetcher).connections())).rejects.toThrow(
      'supported format',
    );
  });
  it('never retries a failed mutation or displays secret-bearing server text', async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(respond({ error: 'must-not-display-secret' }, 409));
    await expect(
      Effect.runPromise(new OperatorApi(fetcher).add('demo/one', 'api.example.test', 'synthetic')),
    ).rejects.toThrow('refused');
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('keeps csrf in memory and sends credentials only to a fixed local path', async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        respond({ csrf: 'login-csrf', backend: 'sqlcipher', service_mode: false }),
      )
      .mockResolvedValueOnce(respond({ csrf: 'session-csrf', expires_in: 900 }))
      .mockResolvedValueOnce(respond({ action: 'connect_add' }));
    const api = new OperatorApi(fetcher);
    await Effect.runPromise(api.bootstrap());
    await Effect.runPromise(api.signIn('synthetic passphrase'));
    await Effect.runPromise(api.add('demo/one', 'api.example.test', 'synthetic value'));
    const call = fetcher.mock.calls[2];
    expect(call?.[0]).toBe('/api/operator/manage');
    expect(call?.[1]?.headers).toEqual({
      'X-AV-CSRF': 'session-csrf',
      'Content-Type': 'application/json',
    });
    expect(call?.[1]?.credentials).toBe('same-origin');
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });
});
