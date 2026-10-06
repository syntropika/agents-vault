import { useEffect, useState } from 'react';
import { App as McpApp } from '@modelcontextprotocol/ext-apps';
import { Effect, Schema } from 'effect';
import { ReviewSchema } from './api';
const EnrollmentSchema = Schema.Struct({
  pairing_id: Schema.String,
  authorized: Schema.Boolean,
  expires_in: Schema.Number,
});
const ReviewResultSchema = Schema.Struct({ review: ReviewSchema, review_digest: Schema.String });
const ResultSchema = Schema.Union([EnrollmentSchema, ReviewResultSchema]);
type Result = typeof ResultSchema.Type;
function displayCommand(command: readonly string[] | undefined) {
  if (!command) return '';
  return JSON.stringify(command, null, 2).replace(
    /[\u202a-\u202e\u2066-\u2069]/gu,
    (char) => `\\u${char.charCodeAt(0).toString(16)}`,
  );
}
export function McpApproval() {
  const [app] = useState(() => new McpApp({ name: 'Agents Vault approvals', version: '0.1.0' }));
  const [data, setData] = useState<Result | null>(null);
  const [error, setError] = useState('');
  const [connected, setConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    document.documentElement.dataset['theme'] = 'dark';
    app.addEventListener('hostcontextchanged', (context) => {
      if (context.theme) document.documentElement.dataset['theme'] = context.theme;
    });
    app.addEventListener('toolresult', (result) => {
      if (!active) return;
      const parsed = Schema.decodeUnknownExit(ResultSchema)(result.structuredContent);
      if (parsed._tag === 'Success' && !result.isError) {
        setData(parsed.value);
        setError('');
      } else
        setError(
          'The action could not be loaded. Check your vault and MCP enrollment, then refresh.',
        );
    });
    app.addEventListener('toolcancelled', () => {
      if (active) setError('The tool was cancelled. No approval was submitted by this view.');
    });
    void app.connect().then(
      () => {
        if (active) {
          setConnected(true);
          document.documentElement.dataset['theme'] = app.getHostContext()?.theme ?? 'dark';
        }
      },
      () => {
        if (active)
          setError('This view requires an MCP Apps host. Reopen it from a compatible client.');
      },
    );
    return () => {
      active = false;
      void app.close();
    };
  }, [app]);
  async function call(name: string, args: Record<string, unknown>) {
    if (busy || !connected) return;
    setBusy(true);
    setError('');
    try {
      const result = await Effect.runPromise(
        Effect.tryPromise({
          try: () => app.callServerTool({ name, arguments: args }, { timeout: 10000 }),
          catch: () => new Error('Cannot reach the broker. Refresh before retrying a decision.'),
        }),
      );
      if (result.isError)
        throw new Error(
          'The broker refused this action. Enrollment may have expired, or the action was already decided.',
        );
      const parsed = await Effect.runPromise(
        Schema.decodeUnknownEffect(ResultSchema)(result.structuredContent),
      );
      setData(parsed);
    } catch {
      setError('The action could not be confirmed. Refresh the action before retrying.');
    } finally {
      setBusy(false);
    }
  }
  const review = data && 'review' in data ? data.review : null;
  const pending = review?.state === 'pending';
  const enrollment = data && 'pairing_id' in data ? data : null;
  return (
    <main className="mcp-approval" aria-busy={busy}>
      <h1>{review ? 'Approve this action?' : 'Connect approvals'}</h1>
      <p className="fine-print">Credentials stay in your local vault.</p>
      {error && (
        <p className="error-banner" role="alert">
          {error}
        </p>
      )}
      {enrollment && (
        <>
          <h2>{enrollment.authorized ? 'Session connected' : 'Authorize this session'}</h2>
          <p>
            {enrollment.authorized
              ? 'You can now request an action from this harness.'
              : 'Open Agents Vault locally. In Settings, connect the MCP session with this exact ID.'}
          </p>
          <code className="mcp-id">{enrollment.pairing_id}</code>
          <p className="fine-print">
            {enrollment.expires_in} seconds remaining. Never enter your vault passphrase in chat.
          </p>
          <button
            className="button secondary"
            disabled={busy || !connected}
            onClick={() => {
              void call('approval_session_status', {});
            }}
          >
            Refresh connection
          </button>
        </>
      )}
      {review && (
        <>
          <dl className="mcp-review">
            <div>
              <dt>Credential</dt>
              <dd>
                {review.operation.connection} · v{review.task_policy?.connection_version}
              </dd>
            </div>
            <div>
              <dt>Destination</dt>
              <dd>{review.task_policy?.host ?? review.operation.target}</dd>
            </div>
            <div>
              <dt>Command arguments</dt>
              <dd>
                <pre>{displayCommand(review.task_policy?.command)}</pre>
              </dd>
            </div>
            <div>
              <dt>Limits</dt>
              <dd>
                {review.task_policy?.max_runtime_seconds} seconds ·{' '}
                {review.task_policy?.max_requests} requests · {review.task_policy?.max_connects}{' '}
                connections
              </dd>
            </div>
            <div>
              <dt>Request</dt>
              <dd>
                <code>{review.id}</code>
              </dd>
            </div>
            <div>
              <dt>Status</dt>
              <dd>
                {typeof review.state === 'string'
                  ? review.state
                  : 'Approved for one attempt within 60 seconds'}
              </dd>
            </div>
          </dl>
          <div className="editor-actions">
            <button
              className="button primary"
              disabled={busy || !connected || !pending}
              onClick={() => {
                if (data && 'review_digest' in data)
                  void call('decide_task', {
                    request_id: review.id,
                    review_digest: data.review_digest,
                    approve: true,
                  });
              }}
            >
              Approve action
            </button>
            <button
              className="button secondary"
              disabled={busy || !connected || !pending}
              onClick={() => {
                if (data && 'review_digest' in data)
                  void call('decide_task', {
                    request_id: review.id,
                    review_digest: data.review_digest,
                    approve: false,
                  });
              }}
            >
              Deny
            </button>
            <button
              className="text-button"
              disabled={busy || !connected}
              onClick={() => {
                void call('review_request', { request_id: review.id });
              }}
            >
              Refresh action
            </button>
          </div>
          <p className="fine-print">
            Approval does not start the command. Resume this exact request through av.
          </p>
        </>
      )}
      {!data && !error && <p role="status">Waiting for the action from your MCP host…</p>}
    </main>
  );
}
