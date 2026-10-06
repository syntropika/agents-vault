import { useEffect, useRef, useState } from 'react';
import type { SyntheticEvent, ReactNode } from 'react';
import { Effect } from 'effect';
import {
  ArrowRight,
  Check,
  ChevronRight,
  CircleHelp,
  FileKey2,
  Globe2,
  KeyRound,
  LockKeyhole,
  LogOut,
  Moon,
  Plus,
  RefreshCw,
  RotateCw,
  Search,
  Settings2,
  ShieldCheck,
  Sun,
  TerminalSquare,
  X,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { ApiError, OperatorApi } from './api';
import type { Connection, Detail, Review, Status } from './api';

type View = 'credentials' | 'permissions' | 'approvals' | 'settings';
type Editor = 'add' | 'rotate' | 'permissions' | 'disconnect' | null;
const navigation: readonly { id: View; label: string }[] = [
  { id: 'credentials', label: 'Credentials' },
  { id: 'permissions', label: 'Permissions' },
  { id: 'approvals', label: 'Approvals' },
  { id: 'settings', label: 'Settings' },
];
function Icon({ icon: Component }: { icon: LucideIcon }) {
  return <Component size={18} strokeWidth={1.65} aria-hidden="true" />;
}
function Setting({
  icon,
  title,
  description,
  children,
}: {
  icon: LucideIcon;
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <div className="setting-row">
      <span className="setting-icon">
        <Icon icon={icon} />
      </span>
      <div className="setting-label">
        <strong>{title}</strong>
        <span>{description}</span>
      </div>
      <div className="setting-value">{children}</div>
    </div>
  );
}
function Empty({
  icon,
  title,
  children,
}: {
  icon: LucideIcon;
  title: string;
  children: ReactNode;
}) {
  return (
    <div className="empty-state">
      <span className="empty-icon">
        <Icon icon={icon} />
      </span>
      <h2>{title}</h2>
      <p>{children}</p>
    </div>
  );
}
export function App({ api: suppliedApi }: { api?: OperatorApi }) {
  const [api] = useState(() => suppliedApi ?? new OperatorApi());
  const [view, setView] = useState<View>('credentials');
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [authenticated, setAuthenticated] = useState(false);
  const [ready, setReady] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [status, setStatus] = useState<Status | null>(null);
  const [records, setRecords] = useState<readonly Connection[]>([]);
  const [selected, setSelected] = useState<Detail | null>(null);
  const [requests, setRequests] = useState<readonly Review[]>([]);
  const [search, setSearch] = useState('');
  const [editor, setEditor] = useState<Editor>(null);
  const selection = useRef(0);
  const mounted = useRef(true);
  const editorTitle = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    mounted.current = true;
    const controller = new AbortController();
    void Effect.runPromise(api.bootstrap(), { signal: controller.signal }).then(
      () => {
        if (mounted.current) setReady(true);
      },
      () => {
        if (mounted.current && !controller.signal.aborted)
          setError('Cannot reach the local vault. Start the broker, then retry.');
      },
    );
    return () => {
      mounted.current = false;
      controller.abort();
    };
  }, [api]);
  useEffect(() => {
    document.documentElement.dataset['theme'] = theme;
  }, [theme]);
  useEffect(() => {
    if (editor) editorTitle.current?.focus();
  }, [editor]);
  async function run<A>(
    effect: Effect.Effect<A, ApiError>,
    success: (result: A) => void,
  ): Promise<void> {
    if (busy) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const result = await Effect.runPromise(effect);
      if (mounted.current) success(result);
    } catch (cause) {
      if (mounted.current) {
        setError(
          cause instanceof Error
            ? cause.message
            : 'The operation could not be completed. Try again.',
        );
        if (cause instanceof ApiError && cause.status === 401) {
          setAuthenticated(false);
          setRecords([]);
          setSelected(null);
          setRequests([]);
          setEditor(null);
        }
      }
    } finally {
      if (mounted.current) setBusy(false);
    }
  }
  function snapshot() {
    return Effect.gen(function* () {
      const status = yield* api.status();
      const records = status.locked ? (yield* api.connections()).connections : null;
      const requests = (yield* api.requests()).requests;
      return { status, records, requests };
    });
  }
  function applySnapshot(result: {
    status: Status;
    records: readonly Connection[] | null;
    requests: readonly Review[];
  }) {
    setStatus(result.status);
    if (result.records) setRecords(result.records);
    setRequests(result.requests);
  }
  async function signIn(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const password = new FormData(form).get('passphrase');
    form.reset();
    if (typeof password !== 'string') return;
    await run(
      Effect.gen(function* () {
        yield* api.bootstrap();
        yield* api.signIn(password);
        return yield* snapshot();
      }),
      (result) => {
        applySnapshot(result);
        setAuthenticated(true);
        setReady(true);
      },
    );
  }
  function refresh() {
    if (!authenticated) {
      void run(api.bootstrap(), () => {
        setReady(true);
      });
      return;
    }
    void run(snapshot(), (result) => {
      applySnapshot(result);
      setSelected(null);
      setEditor(null);
    });
  }
  function select(record: Connection) {
    const version = ++selection.current;
    void run(api.detail(record.id), (detail) => {
      if (version === selection.current) {
        setSelected(detail);
        setEditor(null);
      }
    });
  }
  function changeView(next: View) {
    setView(next);
    setEditor(null);
    setError('');
    setNotice('');
  }
  function mutation(effect: Effect.Effect<unknown, ApiError>, message: string) {
    void run(effect.pipe(Effect.flatMap(() => snapshot())), (result) => {
      applySnapshot(result);
      setSelected(null);
      setEditor(null);
      setNotice(message);
    });
  }
  function submitCredential(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const fields = new FormData(form);
    const value = fields.get('value');
    const id = fields.get('id');
    const host = fields.get('host');
    form.reset();
    if (typeof value !== 'string') return;
    if (editor === 'add' && typeof id === 'string' && typeof host === 'string')
      mutation(
        api.add(id, host, value),
        'Credential added. Configure its permitted task before use.',
      );
    else if (editor === 'rotate' && selected)
      mutation(
        api.change('connect_replace', selected.connection, value),
        'Credential rotated. Previous permissions were revoked.',
      );
  }
  const filtered = records.filter((record) =>
    `${record.id} ${record.host}`.toLowerCase().includes(search.toLowerCase()),
  );
  const grant = selected?.policy?.grants[0];
  const isLocked = status?.locked ?? true;
  const connection = selected?.connection;
  return (
    <div className="app-stage">
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <div className="app-shell">
        <header className="app-header">
          <a className="brand" href="/" aria-label="Agents Vault home">
            <span className="brand-mark">
              <Icon icon={LockKeyhole} />
            </span>
            <span>Agents Vault</span>
          </a>
          <nav aria-label="Main navigation" className="segmented-nav">
            {navigation.map((item) => (
              <button
                type="button"
                key={item.id}
                aria-current={view === item.id ? 'page' : undefined}
                onClick={() => {
                  changeView(item.id);
                }}
              >
                {item.label}
                {item.id === 'approvals' &&
                  requests.some((request) => request.state === 'pending') && (
                    <span className="notification-dot" aria-label="Pending requests" />
                  )}
              </button>
            ))}
          </nav>
          <div className="header-actions">
            <button
              type="button"
              className="icon-button"
              aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
              onClick={() => {
                setTheme(theme === 'dark' ? 'light' : 'dark');
              }}
            >
              <Icon icon={theme === 'dark' ? Sun : Moon} />
            </button>
            <span className="session-label">
              <Icon icon={LockKeyhole} />
              {authenticated ? 'Local session' : 'Locked session'}
            </span>
            {authenticated && (
              <button
                type="button"
                className="icon-button"
                aria-label="Sign out"
                disabled={busy}
                onClick={() => {
                  void run(api.signOut(), () => {
                    setAuthenticated(false);
                    setRecords([]);
                    setSelected(null);
                    setRequests([]);
                    setStatus(null);
                  });
                }}
              >
                <Icon icon={LogOut} />
              </button>
            )}
          </div>
        </header>
        <main id="main" className="main-content" aria-busy={busy}>
          <div className="page-heading">
            <div>
              <h1>{navigation.find((item) => item.id === view)?.label}</h1>
              <p>
                {view === 'credentials'
                  ? 'Your credentials. Your rules.'
                  : view === 'permissions'
                    ? 'Decide where and how a credential can be used.'
                    : view === 'approvals'
                      ? 'Review the exact task before granting access.'
                      : 'Manage your local vault and workspace.'}
              </p>
            </div>
            <div className="heading-actions">
              {authenticated && (
                <button
                  className="icon-button"
                  type="button"
                  aria-label="Refresh vault"
                  disabled={busy}
                  onClick={refresh}
                >
                  <Icon icon={RefreshCw} />
                </button>
              )}
              {(view === 'credentials' || view === 'permissions') && (
                <button
                  type="button"
                  className="button primary"
                  disabled={!authenticated || busy || !isLocked}
                  onClick={() => {
                    setEditor('add');
                  }}
                >
                  <Icon icon={Plus} />
                  Add credential
                </button>
              )}
            </div>
          </div>
          {error && (
            <div className="feedback error" role="alert">
              <Icon icon={CircleHelp} />
              <span>{error}</span>
              {!authenticated && (
                <button className="text-button" type="button" disabled={busy} onClick={refresh}>
                  Retry connection
                </button>
              )}
            </div>
          )}
          {notice && (
            <div className="feedback" role="status">
              <Icon icon={Check} />
              {notice}
            </div>
          )}
          {!authenticated ? (
            <div className="locked-layout">
              <div className="locked-copy">
                <span className="large-key">
                  <Icon icon={KeyRound} />
                </span>
                <h2>Make access intentional.</h2>
                <p>
                  Keep credentials local. Choose their destination, control their use, and approve
                  tasks when they need access.
                </p>
                <div className="locked-features">
                  <span>
                    <Icon icon={Globe2} />
                    Exact destinations
                  </span>
                  <span>
                    <Icon icon={ShieldCheck} />
                    Explicit permissions
                  </span>
                  <span>
                    <Icon icon={FileKey2} />
                    Separate task approvals
                  </span>
                </div>
              </div>
              <section className="signin-panel" aria-labelledby="signin-title">
                <h2 id="signin-title">Open your local vault</h2>
                <p>
                  Sign in once for a 15-minute operator session. Your passphrase stays between this
                  page and the local broker.
                </p>
                <form
                  onSubmit={(event) => {
                    void signIn(event);
                  }}
                >
                  <label htmlFor="passphrase">Vault passphrase</label>
                  <input
                    id="passphrase"
                    name="passphrase"
                    type="password"
                    autoComplete="current-password"
                    required
                    maxLength={4096}
                    disabled={busy}
                  />
                  <button className="button primary" type="submit" disabled={!ready || busy}>
                    {busy ? 'Opening vault…' : 'Open vault'}
                    <Icon icon={ArrowRight} />
                  </button>
                </form>
                <p className="fine-print">
                  Unlocking the operator interface does not approve a task.
                </p>
              </section>
            </div>
          ) : (
            <>
              {status && !status.service_mode && (
                <div className="development-note">
                  Development vault · local testing; installed custody has not been verified.
                </div>
              )}
              {(view === 'credentials' || view === 'permissions') && (
                <>
                  {!isLocked && (
                    <div className="feedback" role="status">
                      <Icon icon={LockKeyhole} />
                      <span>
                        Task execution is enabled. Pause it in Settings before editing credentials.
                      </span>
                    </div>
                  )}
                  <div className="settings-layout">
                    <aside className="credential-selector" aria-label="Credential selector">
                      <div className="selector-title">
                        <h2>Local credentials</h2>
                        <span className="count">{records.length}</span>
                      </div>
                      <label className="search-field">
                        <Icon icon={Search} />
                        <span className="sr-only">Search credentials</span>
                        <input
                          value={search}
                          onChange={(event) => {
                            setSearch(event.target.value);
                          }}
                          placeholder="Search credentials…"
                          type="search"
                        />
                      </label>
                      <div className="credential-list">
                        {filtered.map((record) => (
                          <button
                            type="button"
                            className="credential-row"
                            key={record.id}
                            aria-pressed={connection?.id === record.id}
                            disabled={busy || !isLocked}
                            onClick={() => {
                              select(record);
                            }}
                          >
                            <span className="row-icon">
                              <Icon icon={KeyRound} />
                            </span>
                            <span className="record-label">
                              <strong>{record.id}</strong>
                              <span>{record.active ? record.host : 'Disconnected'}</span>
                            </span>
                            <Icon icon={ChevronRight} />
                          </button>
                        ))}
                        {filtered.length === 0 && (
                          <p className="list-empty">
                            {search
                              ? 'No matching credentials. Try another name or host.'
                              : 'Your vault is empty. Add a credential to begin.'}
                          </p>
                        )}
                      </div>
                      <p className="selector-note">
                        <Icon icon={ShieldCheck} />
                        Stored values are never shown here.
                      </p>
                    </aside>
                    <section className="credential-detail" aria-label="Credential details">
                      {editor === 'add' || editor === 'rotate' ? (
                        <section className="editor" aria-labelledby="editor-title">
                          <div className="detail-heading">
                            <div>
                              <h2 id="editor-title" ref={editorTitle} tabIndex={-1}>
                                {editor === 'add' ? 'Add credential' : 'Rotate credential'}
                              </h2>
                              <p>
                                {editor === 'add'
                                  ? 'Store the value, then configure permitted use.'
                                  : 'Replacing the value revokes previous permissions.'}
                              </p>
                            </div>
                            <button
                              type="button"
                              className="icon-button"
                              aria-label="Cancel credential editing"
                              disabled={busy}
                              onClick={() => {
                                setEditor(null);
                              }}
                            >
                              <Icon icon={X} />
                            </button>
                          </div>
                          <form className="credential-form" onSubmit={submitCredential}>
                            {editor === 'add' && (
                              <>
                                <label htmlFor="credential-id">Credential name</label>
                                <input
                                  id="credential-id"
                                  name="id"
                                  placeholder="service/account"
                                  pattern="[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?/[a-z0-9_-]{1,64}"
                                  maxLength={128}
                                  required
                                  disabled={busy}
                                />
                                <p className="field-hint">Use a service/account reference.</p>
                                <label htmlFor="credential-host">Allowed host</label>
                                <input
                                  id="credential-host"
                                  name="host"
                                  placeholder="api.example.com"
                                  pattern="[a-z0-9.-]+"
                                  maxLength={253}
                                  required
                                  disabled={busy}
                                />
                                <p className="field-hint">
                                  Exact hostname, without a scheme or path.
                                </p>
                              </>
                            )}
                            <label htmlFor="credential-value">
                              {editor === 'add' ? 'Credential value' : 'New credential value'}
                            </label>
                            <input
                              id="credential-value"
                              name="value"
                              type="password"
                              autoComplete="off"
                              maxLength={4096}
                              required
                              disabled={busy}
                            />
                            <p className="field-hint">
                              The value is sent directly to your local vault.
                            </p>
                            <div className="editor-actions">
                              <button className="button primary" type="submit" disabled={busy}>
                                {busy
                                  ? 'Saving…'
                                  : editor === 'add'
                                    ? 'Save credential'
                                    : 'Replace credential'}
                              </button>
                              <button
                                className="button secondary"
                                type="button"
                                disabled={busy}
                                onClick={() => {
                                  setEditor(null);
                                }}
                              >
                                Cancel
                              </button>
                            </div>
                          </form>
                        </section>
                      ) : connection ? (
                        <>
                          <div className="detail-heading">
                            <div>
                              <h2>
                                {connection.id}
                                <span className="version">v{connection.version}</span>
                              </h2>
                              <p>{connection.host}</p>
                            </div>
                            {!connection.active && <span className="badge">Disconnected</span>}
                          </div>
                          <div className="settings-group">
                            <Setting
                              icon={Globe2}
                              title="Allowed destination"
                              description="The exact host this credential belongs to."
                            >
                              <span>{connection.host}</span>
                            </Setting>
                            <Setting
                              icon={ArrowRight}
                              title="Delivery"
                              description="How the configured task receives access."
                            >
                              {grant
                                ? grant.request.delivery === 'direct'
                                  ? 'Environment'
                                  : 'Local proxy'
                                : 'Not configured'}
                            </Setting>
                            <Setting
                              icon={ShieldCheck}
                              title="Approval"
                              description="When a task needs your confirmation."
                            >
                              {grant
                                ? grant.approval === 'every_run'
                                  ? 'Ask every time'
                                  : 'Preapproved'
                                : 'No access granted'}
                            </Setting>
                            <Setting
                              icon={TerminalSquare}
                              title="Permitted task"
                              description="Only an operator-configured task can be granted."
                            >
                              <span>
                                {grant
                                  ? `${grant.request.executable} ${grant.request.arguments.join(' ')}`
                                  : 'Not configured'}
                              </span>
                            </Setting>
                          </div>
                          {editor === 'permissions' ? (
                            <section
                              className="inline-permissions"
                              aria-labelledby="permissions-title"
                            >
                              <h3 id="permissions-title">Task permissions</h3>
                              <p>
                                Grant the broker’s configured task for this host and version. It
                                will require approval on every run. A mismatched or missing task is
                                refused.
                              </p>
                              <div className="editor-actions">
                                <button
                                  type="button"
                                  className="button primary"
                                  disabled={busy || !connection.active || !isLocked}
                                  onClick={() => {
                                    mutation(
                                      api.change('connect_grant', connection),
                                      'Configured task granted. Each run requires approval.',
                                    );
                                  }}
                                >
                                  Grant configured task
                                </button>
                                <button
                                  type="button"
                                  className="button secondary"
                                  disabled={busy || !grant || !isLocked}
                                  onClick={() => {
                                    mutation(
                                      api.change('connect_revoke', connection),
                                      'All permissions revoked.',
                                    );
                                  }}
                                >
                                  Revoke access
                                </button>
                                <button
                                  type="button"
                                  className="text-button"
                                  onClick={() => {
                                    setEditor(null);
                                  }}
                                >
                                  Cancel
                                </button>
                              </div>
                            </section>
                          ) : (
                            <div className="detail-actions">
                              <button
                                type="button"
                                className="button primary"
                                disabled={busy || !connection.active || !isLocked}
                                onClick={() => {
                                  setEditor('permissions');
                                }}
                              >
                                <Icon icon={Settings2} />
                                Edit permissions
                              </button>
                              <button
                                type="button"
                                className="button secondary"
                                disabled={busy || !connection.active || !isLocked}
                                onClick={() => {
                                  setEditor('rotate');
                                }}
                              >
                                <Icon icon={RotateCw} />
                                Rotate credential
                              </button>
                            </div>
                          )}
                          {editor === 'disconnect' ? (
                            <div className="disconnect-confirm">
                              <p>
                                Disconnect {connection.id}? Its stored value and permissions will be
                                removed. You can reconnect by adding a new credential.
                              </p>
                              <div className="editor-actions">
                                <button
                                  type="button"
                                  className="button secondary"
                                  disabled={busy}
                                  onClick={() => {
                                    mutation(
                                      api.change('connect_disconnect', connection),
                                      'Credential disconnected.',
                                    );
                                  }}
                                >
                                  Confirm disconnect
                                </button>
                                <button
                                  type="button"
                                  className="text-button"
                                  onClick={() => {
                                    setEditor(null);
                                  }}
                                >
                                  Cancel
                                </button>
                              </div>
                            </div>
                          ) : (
                            connection.active && (
                              <button
                                type="button"
                                className="text-button disconnect"
                                disabled={busy || !isLocked}
                                onClick={() => {
                                  setEditor('disconnect');
                                }}
                              >
                                Disconnect credential
                              </button>
                            )
                          )}
                          <p className="detail-note">
                            <Icon icon={CircleHelp} />
                            Adding a credential does not grant access.
                          </p>
                        </>
                      ) : (
                        <Empty
                          icon={KeyRound}
                          title={records.length ? 'Choose a credential' : 'A clean start'}
                        >
                          {records.length
                            ? 'Select a credential to inspect its destination and permitted use.'
                            : 'Add your first credential. Its value stays out of lists and task reviews.'}
                        </Empty>
                      )}
                    </section>
                  </div>
                </>
              )}
              {view === 'approvals' && (
                <section className="approval-list" aria-label="Task approvals">
                  {requests.length === 0 ? (
                    <Empty icon={ShieldCheck} title="No requests to review">
                      Enable task execution in Settings. New requests from av or MCP will appear
                      here. Refresh to check for changes.
                    </Empty>
                  ) : (
                    requests.map((request) => (
                      <article className="approval-request" key={request.id}>
                        <div className="detail-heading">
                          <div>
                            <h2>{request.operation.connection}</h2>
                            <p>{request.task_policy?.host ?? request.operation.target}</p>
                          </div>
                          <span className="badge">
                            {typeof request.state === 'string' ? request.state : 'approved'}
                          </span>
                        </div>
                        <pre className="command">
                          {request.task_policy
                            ? request.task_policy.command
                                .map((part) => JSON.stringify(part))
                                .join(' ')
                            : `${request.operation.action} ${request.operation.target}`}
                        </pre>
                        <dl className="task-limits">
                          <div>
                            <dt>Credential version</dt>
                            <dd>{request.task_policy?.connection_version ?? 'Unversioned'}</dd>
                          </div>
                          <div>
                            <dt>Runtime limit</dt>
                            <dd>{request.task_policy?.max_runtime_seconds ?? '—'} seconds</dd>
                          </div>
                          <div>
                            <dt>Request limit</dt>
                            <dd>{request.task_policy?.max_requests ?? '—'}</dd>
                          </div>
                          <div>
                            <dt>Connection limit</dt>
                            <dd>{request.task_policy?.max_connects ?? '—'}</dd>
                          </div>
                        </dl>
                        <div className="editor-actions">
                          <button
                            className="button primary"
                            type="button"
                            disabled={busy || request.state !== 'pending'}
                            onClick={() => {
                              mutation(
                                api.decide(request, true),
                                'Task approved for one execution attempt within 60 seconds.',
                              );
                            }}
                          >
                            <Icon icon={Check} />
                            Approve task
                          </button>
                          <button
                            className="button secondary"
                            type="button"
                            disabled={busy || request.state !== 'pending'}
                            onClick={() => {
                              mutation(api.decide(request, false), 'Task denied.');
                            }}
                          >
                            <Icon icon={X} />
                            Deny
                          </button>
                        </div>
                        <p className="fine-print">
                          Approval does not start the command. Resume the reviewed request through
                          av.
                        </p>
                      </article>
                    ))
                  )}
                </section>
              )}
              {view === 'settings' && (
                <section className="workspace-settings">
                  <h2>Local workspace</h2>
                  <div className="settings-group">
                    <Setting
                      icon={LockKeyhole}
                      title="Task execution"
                      description={
                        isLocked
                          ? 'Credentials can be managed while tasks are paused.'
                          : 'New tasks can request approval.'
                      }
                    >
                      <button
                        className="button secondary"
                        type="button"
                        disabled={busy}
                        onClick={() => {
                          if (isLocked) {
                            void run(
                              api.unlock().pipe(Effect.flatMap(() => snapshot())),
                              applySnapshot,
                            );
                          } else {
                            void run(api.lock(), () => {
                              setAuthenticated(false);
                              setRecords([]);
                              setSelected(null);
                              setRequests([]);
                              setStatus(null);
                              setNotice('Task execution paused. Sign in to manage credentials.');
                            });
                          }
                        }}
                      >
                        {isLocked ? 'Enable tasks' : 'Pause and lock'}
                      </button>
                    </Setting>
                    <Setting
                      icon={Moon}
                      title="Appearance"
                      description="Dark mode is the default for this workspace."
                    >
                      <button
                        className="button secondary"
                        type="button"
                        onClick={() => {
                          setTheme(theme === 'dark' ? 'light' : 'dark');
                        }}
                      >
                        {theme === 'dark' ? 'Use light mode' : 'Use dark mode'}
                      </button>
                    </Setting>
                    <Setting
                      icon={FileKey2}
                      title="Storage"
                      description="Native keyring adapters will be available in a future integration."
                    >
                      SQLCipher
                    </Setting>
                  </div>
                  <p className="fine-print">
                    Operator sessions expire after 15 minutes. Locking the broker ends existing
                    sessions.
                  </p>
                </section>
              )}
            </>
          )}
        </main>
        <footer className="app-footer">
          <span>
            <Icon icon={LockKeyhole} />
            Local vault
          </span>
          <span>Credentials stay out of task reviews.</span>
        </footer>
      </div>
    </div>
  );
}
