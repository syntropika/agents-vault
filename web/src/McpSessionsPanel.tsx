import type { McpSessions } from './api';
export function McpSessionsPanel({
  sessions,
  disabled,
  onDecision,
}: {
  sessions: McpSessions['sessions'];
  disabled: boolean;
  onDecision: (id: string, approve: boolean) => void;
}) {
  return (
    <section className="mcp-sessions" aria-labelledby="mcp-sessions-title">
      <h3 id="mcp-sessions-title">MCP approvals</h3>
      <p className="fine-print">
        Enable actions, call connect_approval in your MCP client, then refresh this page. Connect
        only the exact session ID displayed in its App. The enrolled harness can submit your
        decisions for 15 minutes.
      </p>
      {sessions.length === 0 ? (
        <p className="fine-print">No MCP sessions waiting to connect.</p>
      ) : (
        sessions.map((session) => (
          <div className="mcp-session" key={session.id}>
            <div>
              <code>{session.id}</code>
              <p className="fine-print">
                {session.authorized ? 'Connected' : 'Waiting for authorization'} ·{' '}
                {session.expires_in} seconds remaining
              </p>
            </div>
            <div className="editor-actions">
              {!session.authorized && (
                <button
                  className="button primary"
                  disabled={disabled}
                  onClick={() => {
                    onDecision(session.id, true);
                  }}
                >
                  Connect session
                </button>
              )}
              <button
                className="button secondary"
                disabled={disabled}
                onClick={() => {
                  onDecision(session.id, false);
                }}
              >
                {session.authorized ? 'Disconnect' : 'Deny session'}
              </button>
            </div>
          </div>
        ))
      )}
    </section>
  );
}
