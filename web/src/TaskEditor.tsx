import { useState } from 'react';
import type { SyntheticEvent } from 'react';
import type { Connection, TaskConfiguration, TaskRecipe } from './api';
export function TaskEditor({
  configuration,
  records,
  disabled,
  onSave,
}: {
  configuration: TaskConfiguration | null;
  records: readonly Connection[];
  disabled: boolean;
  onSave: (recipe: TaskRecipe) => void;
}) {
  const recipe = configuration?.recipe;
  const [selectedId, setSelectedId] = useState(recipe?.connection ?? '');
  const selected = records.find((record) => record.id === selectedId);
  const [argumentsList, setArgumentsList] = useState<readonly string[]>(
    () => recipe?.command.slice(1) ?? [],
  );
  function submit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const text = (name: string) => {
      const value = data.get(name);
      return typeof value === 'string' ? value : '';
    };
    const connection = records.find((record) => record.id === text('connection'));
    if (!connection?.active) return;
    onSave({
      connection: connection.id,
      connection_version: connection.version,
      host: connection.host,
      command: [text('executable'), ...argumentsList],
      max_connects: Number(text('max_connects')),
      max_requests: Number(text('max_requests')),
      max_runtime_seconds: Number(text('max_runtime_seconds')),
      upstream_addr: text('upstream_addr'),
      upstream_ca_der: text('upstream_ca_der'),
    });
  }
  const blocked = disabled || configuration?.editable === false;
  return (
    <section className="workspace-settings task-editor" aria-labelledby="task-title">
      <h2 id="task-title">{recipe ? 'Configured action' : 'Create an action'}</h2>
      <p className="fine-print">
        One action can be active in this broker. Saving changes revokes its previous permissions.
        Grant access again from Permissions.
      </p>
      {disabled && (
        <p className="notice">Pause and lock action execution, then sign in to edit this action.</p>
      )}
      {configuration?.editable === false && (
        <p className="notice">This guest action is managed by the service installer.</p>
      )}
      <form onSubmit={submit}>
        <fieldset disabled={blocked}>
          <label htmlFor="task-connection">Credential</label>
          <select
            id="task-connection"
            name="connection"
            value={selectedId}
            onChange={(event) => {
              setSelectedId(event.currentTarget.value);
            }}
            required
          >
            <option value="" disabled>
              Select a credential
            </option>
            {records
              .filter((record) => record.active)
              .map((record) => (
                <option key={record.id} value={record.id}>
                  {record.id} · {record.host} · v{record.version}
                </option>
              ))}
          </select>
          {selected?.active && (
            <p className="field-hint task-destination">
              <span>Destination</span>
              <strong>{selected.host}</strong>
              <span>Credential version {selected.version}</span>
            </p>
          )}
          <label htmlFor="task-executable">Executable</label>
          <input
            id="task-executable"
            name="executable"
            defaultValue={recipe?.command[0] ?? ''}
            placeholder="/absolute/path/to/your-cli"
            maxLength={4096}
            required
            pattern="/.*"
          />
          <div className="task-arguments">
            {argumentsList.map((argument, index) => (
              <div key={index}>
                <label htmlFor={`task-argument-${String(index)}`}>Argument {index + 1}</label>
                <div className="argument-row">
                  <textarea
                    id={`task-argument-${String(index)}`}
                    rows={1}
                    maxLength={4096}
                    value={argument}
                    onChange={(event) => {
                      const value = event.currentTarget.value;
                      setArgumentsList((current) =>
                        current.map((part, i) => (i === index ? value : part)),
                      );
                    }}
                  />
                  <button
                    className="text-button"
                    type="button"
                    aria-label={`Remove argument ${String(index + 1)}`}
                    onClick={() => {
                      setArgumentsList((current) => current.filter((_, i) => i !== index));
                    }}
                  >
                    Remove
                  </button>
                </div>
              </div>
            ))}
            <button
              className="button secondary"
              type="button"
              disabled={argumentsList.length >= 31}
              onClick={() => {
                setArgumentsList((current) => [...current, '']);
              }}
            >
              Add argument
            </button>
            <p className="field-hint">
              Each field is one exact argument, including spaces, empty values, and line breaks.
              Shell expressions are not evaluated.
            </p>
          </div>
          <div className="task-limits">
            <div>
              <label htmlFor="task-runtime">Maximum seconds</label>
              <input
                id="task-runtime"
                name="max_runtime_seconds"
                type="number"
                min={1}
                max={60}
                defaultValue={recipe?.max_runtime_seconds ?? 30}
                required
              />
            </div>
            <div>
              <label htmlFor="task-requests">Maximum requests</label>
              <input
                id="task-requests"
                name="max_requests"
                type="number"
                min={1}
                max={16}
                defaultValue={recipe?.max_requests ?? 4}
                required
              />
            </div>
            <div>
              <label htmlFor="task-connects">Maximum connections</label>
              <input
                id="task-connects"
                name="max_connects"
                type="number"
                min={1}
                max={8}
                defaultValue={recipe?.max_connects ?? 2}
                required
              />
            </div>
          </div>
          <details open={!recipe} className="task-transport">
            <summary>Test destination</summary>
            <p className="field-hint">
              This implementation supports a local test server and synthetic credentials.
            </p>
            <label htmlFor="task-upstream">Local server address</label>
            <input
              id="task-upstream"
              name="upstream_addr"
              defaultValue={recipe?.upstream_addr ?? ''}
              placeholder="127.0.0.1:port"
              maxLength={64}
              required
            />
            <label htmlFor="task-ca">Server CA file</label>
            <input
              id="task-ca"
              name="upstream_ca_der"
              defaultValue={recipe?.upstream_ca_der ?? ''}
              placeholder="/absolute/path/to/ca.der"
              maxLength={4096}
              required
              pattern="/.*"
            />
          </details>
          <div className="editor-actions">
            <button className="button primary" type="submit">
              {recipe ? 'Save action' : 'Create action'}
            </button>
          </div>
        </fieldset>
      </form>
    </section>
  );
}
