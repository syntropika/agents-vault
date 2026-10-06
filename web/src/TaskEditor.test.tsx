import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { TaskEditor } from './TaskEditor';
afterEach(cleanup);
it('preserves exact empty and multiline arguments without evaluating shell expressions', async () => {
  const onSave = vi.fn();
  render(
    <TaskEditor
      disabled={false}
      onSave={onSave}
      records={[
        {
          format: 1,
          id: 'test/cli',
          provider: 'test',
          host: 'api.example.test',
          active: true,
          version: 2,
        },
      ]}
      configuration={{
        editable: true,
        capacity: 1,
        revision: 'synthetic',
        recipe: {
          connection: 'test/cli',
          connection_version: 2,
          host: 'api.example.test',
          command: ['/usr/bin/true', '', 'hello\nworld', '$(no-shell)'],
          max_connects: 2,
          max_requests: 3,
          max_runtime_seconds: 20,
          upstream_addr: '127.0.0.1:19443',
          upstream_ca_der: '/test/ca.der',
        },
      }}
    />,
  );
  await userEvent.setup().click(screen.getByRole('button', { name: 'Save action' }));
  expect(onSave).toHaveBeenCalledWith(
    expect.objectContaining({
      command: ['/usr/bin/true', '', 'hello\nworld', '$(no-shell)'],
      connection_version: 2,
    }),
  );
});
