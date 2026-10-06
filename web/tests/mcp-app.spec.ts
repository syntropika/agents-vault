import { resolve } from 'node:path';
import { build } from 'rolldown';
import { Client } from '@modelcontextprotocol/client';
import type { CallToolRequest, CallToolResult } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { Schema } from 'effect';
const Enrollment = Schema.Struct({ pairing_id: Schema.String, authorized: Schema.Boolean });
const Reviewed = Schema.Struct({
  review: Schema.Struct({ id: Schema.String }),
  review_digest: Schema.String,
});
test('official App bridge approves and denies through the real Rust MCP adapter', async ({
  page,
}, info) => {
  test.setTimeout(90000);
  const socket = process.env['AV_MCP_TEST_SOCKET'];
  const ca = process.env['AV_MCP_TEST_CA'];
  if (!socket || !ca)
    throw new Error('Set AV_MCP_TEST_SOCKET and AV_MCP_TEST_CA for the disposable broker');
  const name = `mcp/${info.project.name}_${String(Date.now())}`;
  const api = page.context().request;
  const bootstrap = await api.get('/api/operator/bootstrap');
  const login = await api.post('/api/operator/session', {
    headers: {
      Origin: 'http://127.0.0.1:14323',
      'X-AV-CSRF': ((await bootstrap.json()) as { csrf: string }).csrf,
    },
    data: { passphrase: 'synthetic-preview-passphrase' },
  });
  expect(login.ok()).toBe(true);
  const csrf = ((await login.json()) as { csrf: string }).csrf;
  const headers = { Origin: 'http://127.0.0.1:14323', 'X-AV-CSRF': csrf };
  const manage = (data: unknown) => api.post('/api/operator/manage', { headers, data });
  expect(
    (
      await manage({
        action: 'connect_add',
        id: name,
        host: 'api.test.example.test',
        value: 'av-synthetic-mcp-browser-only',
      })
    ).ok(),
  ).toBe(true);
  const current = await manage({ action: 'task_show' });
  const revision = ((await current.json()) as { revision: string | null }).revision;
  const recipe = {
    connection: name,
    connection_version: 1,
    host: 'api.test.example.test',
    command: ['/usr/bin/true'],
    max_connects: 2,
    max_requests: 3,
    max_runtime_seconds: 20,
    upstream_addr: '127.0.0.1:19443',
    upstream_ca_der: ca,
  };
  expect((await manage({ action: 'task_save', expected_revision: revision, recipe })).ok()).toBe(
    true,
  );
  expect((await manage({ action: 'connect_grant', id: name, expected_version: 1 })).ok()).toBe(
    true,
  );
  expect((await api.post('/api/operator/unlock', { headers, data: {} })).ok()).toBe(true);
  const client = new Client(
    { name: 'independent-app-test', version: '0.1.0' },
    {
      capabilities: {
        extensions: { 'io.modelcontextprotocol/ui': { mimeTypes: ['text/html;profile=mcp-app'] } },
      },
    },
  );
  const transport = new StdioClientTransport({
    command: resolve('../target/debug/av-mcp'),
    env: { AVD_AGENT_SOCKET: socket },
  });
  try {
    await client.connect(transport);
    const initial = await client.callTool({ name: 'connect_approval', arguments: {} });
    const pair = Schema.decodeUnknownSync(Enrollment)(initial.structuredContent);
    expect(pair.authorized).toBe(false);
    const beforeEnrollment = await client.callTool({
      name: 'request_proxy_task',
      arguments: {
        connection: name,
        connection_version: 1,
        host: recipe.host,
        command: recipe.command,
      },
    });
    expect(beforeEnrollment.isError).toBe(true);
    const resource = await client.readResource({ uri: 'ui://agents-vault/approval.html' });
    const first = resource.contents[0];
    if (!first || !('text' in first)) throw new Error('Missing embedded App');
    await page.exposeFunction('avCallTool', (params: CallToolRequest['params']) =>
      client.callTool(params),
    );
    await page.setContent(
      '<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width,initial-scale=1"/><title>MCP SDK test host</title><style>body{background:#171717}</style></head><body></body></html>',
    );
    await page.evaluate(
      ({ html, result }) => {
        window.avAppHtml = html;
        window.avInitialResult = result;
      },
      { html: first.text, result: initial },
    );
    const bundled = await build({
      input: resolve('tests/app-host.ts'),
      platform: 'browser',
      output: { format: 'es', codeSplitting: false },
    });
    const code = bundled.output.find((item) => item.type === 'chunk');
    if (!code) throw new Error('Missing bridge script');
    await page.addScriptTag({ type: 'module', content: code.code });
    const frame = page.frameLocator('iframe');
    await expect(frame.getByText(pair.pairing_id, { exact: true })).toBeVisible();
    expect(
      (
        await api.post('/api/operator/mcp', {
          headers,
          data: { pairing_id: pair.pairing_id, approve: true },
        })
      ).ok(),
    ).toBe(true);
    await frame.getByRole('button', { name: 'Refresh connection' }).click();
    await expect(frame.getByRole('heading', { name: 'Session connected' })).toBeVisible();
    const args = {
      connection: name,
      connection_version: 1,
      host: recipe.host,
      command: recipe.command,
    };
    const request = await client.callTool({ name: 'request_proxy_task', arguments: args });
    const task = Schema.decodeUnknownSync(Reviewed)(request.structuredContent);
    await page.evaluate((result: CallToolResult) => window.avDeliverResult(result), request);
    await expect(frame.getByRole('heading', { name: 'Approve this action?' })).toBeVisible();
    await expect(frame.getByText('20 seconds · 3 requests · 2 connections')).toBeVisible();
    expect(await frame.locator('body').textContent()).not.toContain(
      'av-synthetic-mcp-browser-only',
    );
    await frame.getByRole('button', { name: 'Approve action', exact: true }).click();
    await expect(frame.getByText('Approved for one attempt within 60 seconds')).toBeVisible();
    await expect(frame.getByRole('button', { name: 'Approve action', exact: true })).toBeDisabled();
    const replay = await client.callTool({
      name: 'decide_task',
      arguments: { request_id: task.review.id, review_digest: task.review_digest, approve: true },
    });
    expect(replay.isError).toBe(true);
    const denied = await client.callTool({ name: 'request_proxy_task', arguments: args });
    await page.evaluate((result: CallToolResult) => window.avDeliverResult(result), denied);
    await frame.getByRole('button', { name: 'Deny', exact: true }).click();
    await expect(frame.getByText('denied', { exact: true })).toBeVisible();
    expect(
      (
        await new AxeBuilder({ page })
          .withRules(['color-contrast', 'button-name', 'label'])
          .analyze()
      ).violations,
    ).toEqual([]);
    const capture = process.env['AV_WEB_CAPTURE_ROOT'];
    if (capture)
      await page.screenshot({
        path: resolve(capture, `mcp-app-${info.project.name}.png`),
        fullPage: true,
      });
    expect(
      (
        await api.post('/api/operator/mcp', {
          headers,
          data: { pairing_id: pair.pairing_id, approve: false },
        })
      ).ok(),
    ).toBe(true);
    expect(
      (await client.callTool({ name: 'review_request', arguments: { request_id: task.review.id } }))
        .isError,
    ).toBe(true);
  } finally {
    await client.close();
    await api.post('/api/operator/lock', { headers, data: {} });
  }
});
