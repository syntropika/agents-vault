import { Data, Effect, Schema } from 'effect';

export const ConnectionSchema = Schema.Struct({
  format: Schema.Number,
  id: Schema.String,
  provider: Schema.String,
  host: Schema.String,
  active: Schema.Boolean,
  version: Schema.Number,
});
export type Connection = typeof ConnectionSchema.Type;
const GrantSchema = Schema.Struct({
  approval: Schema.Literals(['every_run', 'preapproved']),
  request: Schema.Struct({
    executable: Schema.String,
    arguments: Schema.Array(Schema.String),
    delivery: Schema.Literals(['direct', 'proxy_preview', 'protected_proxy']),
    host: Schema.NullOr(Schema.String),
  }),
});
export const DetailSchema = Schema.Struct({
  connection: ConnectionSchema,
  policy: Schema.NullOr(Schema.Struct({ grants: Schema.Array(GrantSchema) })),
});
export type Detail = typeof DetailSchema.Type;
const RequestStateSchema = Schema.Union([
  Schema.Literals(['pending', 'denied', 'exhausted']),
  Schema.Struct({
    approved: Schema.Struct({ expires_at: Schema.Number, remaining: Schema.Number }),
  }),
]);
const ReviewSchema = Schema.Struct({
  id: Schema.String,
  operation: Schema.Struct({
    connection: Schema.String,
    action: Schema.String,
    target: Schema.String,
  }),
  state: RequestStateSchema,
  task_policy: Schema.optionalKey(
    Schema.Struct({
      host: Schema.String,
      command: Schema.Array(Schema.String),
      connection_version: Schema.optionalKey(Schema.Number),
      max_connects: Schema.Number,
      max_requests: Schema.Number,
      max_runtime_seconds: Schema.Number,
    }),
  ),
});
export type Review = typeof ReviewSchema.Type;
export const BootstrapSchema = Schema.Struct({
  csrf: Schema.String,
  backend: Schema.Literal('sqlcipher'),
  service_mode: Schema.Boolean,
});
export const StatusSchema = Schema.Struct({
  locked: Schema.Boolean,
  backend: Schema.Literal('sqlcipher'),
  service_mode: Schema.Boolean,
});
export type Status = typeof StatusSchema.Type;
const SessionSchema = Schema.Struct({ csrf: Schema.String, expires_in: Schema.Number });
const ConnectionsSchema = Schema.Struct({ connections: Schema.Array(ConnectionSchema) });
const ReviewsSchema = Schema.Struct({ requests: Schema.Array(ReviewSchema) });
const OkSchema = Schema.Struct({ ok: Schema.Boolean });
const MutationSchema = Schema.Struct({ action: Schema.String });
const DecisionSchema = Schema.Struct({ state: RequestStateSchema });

export class ApiError extends Data.TaggedError('ApiError')<{
  readonly status: number;
  readonly message: string;
}> {}
const messages: Readonly<Record<string, string>> = {
  authentication_failed: 'The passphrase was not accepted. Try again.',
  authentication_throttled: 'Please wait a moment before trying again.',
  management_refused:
    'The change was refused. Pause task execution and refresh the record; check the configured task and credential version.',
  decision_refused: 'This request changed, expired, or was already decided. Refresh the requests.',
  session_required: 'Sign in to your local vault to continue.',
  session_expired: 'Your session expired. Sign in again.',
  session_changed: 'The vault was locked. Sign in again.',
};
export class OperatorApi {
  private csrf = '';
  constructor(private readonly fetcher: typeof fetch = (input, init) => fetch(input, init)) {}
  private request<A>(path: string, schema: Schema.ConstraintDecoder<A>, payload?: unknown) {
    return Effect.gen({ self: this }, function* () {
      const response = yield* Effect.tryPromise({
        try: (signal) =>
          this.fetcher(`/api/operator/${path}`, {
            method: payload === undefined ? 'GET' : 'POST',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: {
              'X-AV-CSRF': this.csrf,
              ...(payload === undefined ? {} : { 'Content-Type': 'application/json' }),
            },
            ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
            signal,
          }),
        catch: () =>
          new ApiError({
            status: 0,
            message:
              'Cannot reach the local vault. Check that the broker is running and try again.',
          }),
      });
      const input: unknown = yield* Effect.tryPromise({
        try: () => response.json() as Promise<unknown>,
        catch: () =>
          new ApiError({
            status: response.status,
            message: 'The vault returned an unreadable response.',
          }),
      });
      if (!response.ok) {
        const error = Schema.decodeUnknownExit(Schema.Struct({ error: Schema.String }))(input);
        const code = error._tag === 'Success' ? error.value.error : '';
        return yield* Effect.fail(
          new ApiError({
            status: response.status,
            message: messages[code] ?? 'The vault refused this operation. Refresh and try again.',
          }),
        );
      }
      return yield* Schema.decodeUnknownEffect(schema)(input).pipe(
        Effect.mapError(
          () =>
            new ApiError({
              status: 0,
              message: 'The vault response does not match the supported format.',
            }),
        ),
      );
    }).pipe(
      Effect.timeout('10 seconds'),
      Effect.mapError((error) =>
        error instanceof ApiError
          ? error
          : new ApiError({
              status: 0,
              message:
                'The local vault took too long to respond. Refresh before retrying a change.',
            }),
      ),
    );
  }
  bootstrap() {
    return this.request('bootstrap', BootstrapSchema).pipe(
      Effect.tap((result) =>
        Effect.sync(() => {
          this.csrf = result.csrf;
        }),
      ),
    );
  }
  signIn(passphrase: string) {
    return this.request('session', SessionSchema, { passphrase }).pipe(
      Effect.tap((result) =>
        Effect.sync(() => {
          this.csrf = result.csrf;
        }),
      ),
    );
  }
  status() {
    return this.request('status', StatusSchema);
  }
  connections() {
    return this.request('manage', ConnectionsSchema, { action: 'connect_list' });
  }
  detail(id: string) {
    return this.request('manage', DetailSchema, { action: 'connect_show', id });
  }
  add(id: string, host: string, value: string) {
    return this.request('manage', MutationSchema, { action: 'connect_add', id, host, value });
  }
  change(
    action: 'connect_replace' | 'connect_disconnect' | 'connect_revoke' | 'connect_grant',
    record: Connection,
    value?: string,
  ) {
    return this.request('manage', MutationSchema, {
      action,
      id: record.id,
      expected_version: record.version,
      ...(value === undefined ? {} : { value }),
    });
  }
  requests() {
    return this.request('requests', ReviewsSchema);
  }
  decide(request: Review, approve: boolean) {
    return this.request('decide', DecisionSchema, { request_id: request.id, approve });
  }
  unlock() {
    return this.request('unlock', OkSchema, {});
  }
  lock() {
    return this.request('lock', OkSchema, {}).pipe(
      Effect.tap(() =>
        Effect.sync(() => {
          this.csrf = '';
        }),
      ),
    );
  }
  signOut() {
    return this.request('logout', OkSchema, {}).pipe(
      Effect.tap(() =>
        Effect.sync(() => {
          this.csrf = '';
        }),
      ),
    );
  }
}
