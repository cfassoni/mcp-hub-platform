# Architecture Specification: `@mcphub/core` Contracts & Runtime Primitives (`TSK-01.2` / #3)

- **Task:** `TSK-01.2` (GitHub Issue `#3`)
- **Tier:** Complex (`AGENTS.md §0`)
- **Status:** Accepted (Approved by PO on 2026-11-23)
- **Target Workspace:** `packages/mcp-core` (`@mcphub/core`)
- **Canonical Standards & References:**
  - `AGENTS.md` (Decision Benchmark, Upstream Contract Inviolability, TypeScript / Web Standards portability)
  - `docs/rules/core-invariants.md` §§1–6
  - `tsconfig.base.json` (`strict`, `noUncheckedIndexedAccess`, `noImplicitOverride`, `isolatedModules`, `verbatimModuleSyntax`, `NodeNext` ESM)
  - `eslint.config.js` (`typescript-eslint` recommended — zero `any`, zero `{}` empty object types)

---

## 1. Scope & Explicit Non-Scope

### 1.1 Scope

Defines the canonical public TypeScript interfaces, discriminated unions, record schemas, and pure Web-Standard runtime primitives exported by `@mcphub/core` (`packages/mcp-core`):

1. **Plugin Contract (`contracts/plugin.ts`):** `PluginCategory`, `PluginMetadata`, `PluginAuthType`, `PluginLoginFieldType`, `PluginLoginField`, `PluginLoginPrompt`, `UpstreamValidationResult`, `PluginAuthRequirements`, `PluginExecutionContext`, strongly typed MCP primitive contracts (`JsonPrimitive`, `JsonValue`, `JsonSchema`, `ToolInputSchema`, `ToolAnnotations`, `ToolContentBlock`, `TextResourceContent`, `BlobResourceContent`, `ResourceContent`, `ResourceDefinition`, `ToolResult`, `ToolDefinition`, `PromptArgument`, `PromptRole`, `PromptMessage`, `PromptResult`, `PromptDefinition`), and `IMcpPlugin`.
2. **Storage & Vault Contract (`contracts/storage.ts`):** `IsoUtcTimestamp`, `EncryptedPayload`, entity records (`UserRecord`, `UserCredentialRecord`, `OAuthClientKind`, `OAuthClientRecord`, `OAuthAuthCodeRecord`, `OAuthTokenRecord`, `WebSessionRecord`), method DTOs, and the async `IStorageDriver` persistence abstraction.
3. **Sanitized Upstream Error Boundary (`errors/upstream-client-error.ts`):** `sanitizeUpstreamText` and `UpstreamClientError` (`UpstreamClientErrorOptions`).
4. **Slug Validation Guards (`validation/slug.ts`):** `PLUGIN_SLUG_MAX_LENGTH`, `PLUGIN_SLUG_REGEX`, `isValidPluginSlug`, and `assertValidPluginSlug`.
5. **Barrel & Liveness Preservation (`index.ts`):** Re-exports all contracts, guards, and error primitives alongside existing `PLATFORM_NAME`, `HealthPayload`, and `createHealthPayload`.

### 1.2 Explicit Non-Scope

- AES-256-GCM encryption/decryption implementation (`TSK-01.3` / `#4`).
- Node.js 26 `node:sqlite` WAL storage driver implementation (`TSK-01.4` / `#5`).
- Cloudflare Workers D1 storage driver implementation (`TSK-01.5` / `#6`, deferred to Post-MVP).
- Hono gateway HTTP routes, Streamable HTTP transport (`2026-07-28`), RFC 8414/9728 discovery endpoints, OAuth 2.1 handshake/DCR/CIMD Anti-SSRF fetchers (`Epics 02–03`).
- Concrete plugin connectors (e.g., `plugins/fiainvest`, `Epic 04`) and onboarding web UI (`apps/hub-web`, `Epic 05`).
- Third-party schema-validation runtime dependencies (e.g., Zod); `@mcphub/core` remains zero-runtime-dependency.

---

## 2. Plugin Contract (`IMcpPlugin`)

All symbols in this section live in `packages/mcp-core/src/contracts/plugin.ts` as pure TypeScript types and interfaces (zero runtime overhead, zero `any`).

### 2.1 Metadata & Authentication Requirements

```ts
export type PluginCategory = 'investments' | 'productivity' | 'utilities';

export interface PluginMetadata {
  readonly id: string;
  readonly slug: string;
  readonly name: string;
  readonly description: string;
  readonly category: PluginCategory;
  readonly version: string;
  /** Optional BCP-47 locale tag for user-facing MCP/UI copy (defaults to 'en-US'; e.g., 'pt-BR'). */
  readonly locale?: string;
}

export type PluginAuthType = 'oauth2' | 'credentials' | 'apikey' | 'none';

export type PluginLoginFieldType = 'text' | 'password' | 'email' | 'url';

export interface PluginLoginField {
  readonly name: string;
  readonly label: string;
  readonly type: PluginLoginFieldType;
  readonly required: boolean;
  readonly placeholder?: string;
  readonly helpText?: string;
}

export interface PluginLoginPrompt {
  readonly title: string;
  readonly description?: string;
  readonly fields: readonly PluginLoginField[];
  readonly submitLabel?: string;
}

export type UpstreamValidationResult =
  | {
      readonly valid: true;
      readonly upstreamAccountId: string;
      readonly email?: string;
      readonly credentials: Readonly<Record<string, unknown>>;
      /** ISO-8601 UTC timestamp when upstream credentials/tokens expire, if bounded. */
      readonly expiresAt?: string;
    }
  | {
      readonly valid: false;
      /** Sanitized, user-safe failure description (never raw secrets/tokens). */
      readonly error: string;
    };

export interface PluginAuthRequirements {
  readonly authType: PluginAuthType;
  readonly scopes?: readonly string[];
  readonly loginPrompt?: PluginLoginPrompt;
  readonly validateUpstream?: (
    input: Readonly<Record<string, unknown>>,
    signal?: AbortSignal,
  ) => Promise<UpstreamValidationResult>;
  readonly refreshUpstream?: (
    credentials: Readonly<Record<string, unknown>>,
    signal?: AbortSignal,
  ) => Promise<UpstreamValidationResult>;
}
```

**Contract Rules (`2.1`):**
- `metadata.slug` MUST satisfy `isValidPluginSlug(metadata.slug)`. Gateway registration MUST reject invalid slugs at startup via `assertValidPluginSlug`.
- `metadata.version` MUST follow SemVer (`MAJOR.MINOR.PATCH`).
- `validateUpstream` is optional on the TypeScript interface solely so `authType: 'none'` plugins omit it without dead boilerplate; plugins declaring `'credentials'` or `'apikey'` MUST provide both `loginPrompt` and `validateUpstream`.
- `refreshUpstream` is optional; when present, gateway/plugin code invokes it for transparent HTTP `401` upstream token renewal (`docs/rules/core-invariants.md §5`).
- `UpstreamValidationResult` is strictly discriminated on `valid`: when `valid: false`, `error` MUST already be sanitized against secret leakage (`sanitizeUpstreamText`).

### 2.2 Isolated Execution Context

```ts
export interface PluginExecutionContext {
  readonly userId: string;
  readonly pluginSlug: string;
  readonly credentials: Readonly<Record<string, unknown>> | null;
  updateCredentials(next: Readonly<Record<string, unknown>>): Promise<void>;
  readonly signal?: AbortSignal;
}
```

**Isolation Invariants (`2.2`):**
- `IStorageDriver`, `ENCRYPTION_MASTER_KEY`, raw SQL handles, other tenants' credentials, and other plugins' credentials MUST NEVER be exposed on or reachable through `PluginExecutionContext`.
- `credentials` is `null` when `authType === 'none'` (or before initial authentication). For authenticated routes (`TSK-03.3`), the gateway decrypts strictly `(userId, pluginSlug)` and supplies a read-only object view.
- `updateCredentials(next)` is a gateway-owned callback bound strictly to `(ctx.userId, ctx.pluginSlug)` that re-encrypts (`TSK-01.3`) and persists updated upstream tokens (e.g., after transparent `401` refresh) without exposing encryption keys or storage APIs to plugins.
- `signal` propagates request abort/timeout (`AbortSignal`) from the gateway down to upstream `fetch` calls.

### 2.3 Strictly Typed MCP Primitives

```ts
export type JsonPrimitive = string | number | boolean | null;

export type JsonValue =
  | JsonPrimitive
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

export interface JsonSchema {
  readonly type?: 'object' | 'array' | 'string' | 'number' | 'integer' | 'boolean' | 'null';
  readonly description?: string;
  readonly enum?: readonly (string | number | boolean)[];
  readonly default?: JsonValue;
  readonly properties?: Readonly<Record<string, JsonSchema>>;
  readonly required?: readonly string[];
  readonly items?: JsonSchema;
  readonly additionalProperties?: boolean | JsonSchema;
  readonly minimum?: number;
  readonly maximum?: number;
  readonly minLength?: number;
  readonly maxLength?: number;
  readonly pattern?: string;
  readonly format?: string;
}

export interface ToolInputSchema extends JsonSchema {
  readonly type: 'object';
}

export interface ToolAnnotations {
  readonly title?: string;
  readonly readOnlyHint?: boolean;
  readonly destructiveHint?: boolean;
  readonly idempotentHint?: boolean;
  readonly openWorldHint?: boolean;
}

export interface TextResourceContent {
  readonly uri: string;
  readonly mimeType?: string;
  readonly text: string;
}

export interface BlobResourceContent {
  readonly uri: string;
  readonly mimeType?: string;
  readonly blob: string;
}

export type ResourceContent = TextResourceContent | BlobResourceContent;

export interface ResourceDefinition {
  readonly uri: string;
  readonly name: string;
  readonly description?: string;
  readonly mimeType?: string;
  read(uri: string): Promise<readonly ResourceContent[]>;
}

export type ToolContentBlock =
  | { readonly type: 'text'; readonly text: string }
  | { readonly type: 'image'; readonly data: string; readonly mimeType: string }
  | { readonly type: 'resource'; readonly resource: ResourceContent };

export interface ToolResult {
  readonly content: readonly ToolContentBlock[];
  readonly structuredContent?: Readonly<Record<string, unknown>>;
  readonly isError?: boolean;
}

export interface ToolDefinition {
  readonly name: string;
  readonly title?: string;
  readonly description: string;
  readonly inputSchema: ToolInputSchema;
  readonly annotations?: ToolAnnotations;
  execute(args: Readonly<Record<string, unknown>>): Promise<ToolResult>;
}

export interface PromptArgument {
  readonly name: string;
  readonly description?: string;
  readonly required?: boolean;
}

export type PromptRole = 'user' | 'assistant';

export interface PromptMessage {
  readonly role: PromptRole;
  readonly content: ToolContentBlock;
}

export interface PromptResult {
  readonly description?: string;
  readonly messages: readonly PromptMessage[];
}

export interface PromptDefinition {
  readonly name: string;
  readonly title?: string;
  readonly description?: string;
  readonly arguments?: readonly PromptArgument[];
  get(args: Readonly<Record<string, string>>): Promise<PromptResult>;
}
```

### 2.4 `IMcpPlugin` Interface

```ts
export interface IMcpPlugin {
  readonly metadata: PluginMetadata;
  getAuthRequirements(): PluginAuthRequirements;
  registerResources(ctx: PluginExecutionContext): Promise<readonly ResourceDefinition[]>;
  registerTools(ctx: PluginExecutionContext): Promise<readonly ToolDefinition[]>;
  registerPrompts(ctx: PluginExecutionContext): Promise<readonly PromptDefinition[]>;
}
```

---

## 3. Storage & Vault Contract (`IStorageDriver`)

All symbols in this section live in `packages/mcp-core/src/contracts/storage.ts` as pure TypeScript types and interfaces.

### 3.1 Timestamps & Encrypted Vault Envelope

- **ISO-8601 UTC Timestamp Format:** All timestamp fields and temporal comparison arguments use `IsoUtcTimestamp = string`, formatted strictly as canonical UTC ISO-8601 strings (`YYYY-MM-DDTHH:mm:ss.sssZ`, i.e., `Date.prototype.toISOString()`). Canonical UTC string formatting guarantees deterministic lexical ordering (`<`, `>`, `<=`, `>=`) across TypeScript, SQLite `TEXT`, and Cloudflare D1 `TEXT`.

```ts
export type IsoUtcTimestamp = string;

export interface EncryptedPayload {
  readonly ciphertext: string;
  readonly iv: string;
  readonly authTag: string;
  readonly keyVersion?: number;
}
```

- `ciphertext`, `iv` (12-byte AES-GCM nonce), and `authTag` (16-byte GCM tag) are encoded strings produced/consumed by `TSK-01.3`.
- Plaintext upstream credentials/tokens MUST NEVER appear in any storage record.

### 3.2 Persistence Entity Records

```ts
export interface UserRecord {
  readonly id: string;
  readonly email: string;
  readonly createdAt: IsoUtcTimestamp;
  readonly updatedAt: IsoUtcTimestamp;
  readonly lastActivityAt: IsoUtcTimestamp;
}

export interface UserCredentialRecord {
  readonly userId: string;
  readonly pluginSlug: string;
  readonly encryptedPayload: EncryptedPayload;
  readonly expiresAt?: IsoUtcTimestamp;
  readonly createdAt: IsoUtcTimestamp;
  readonly updatedAt: IsoUtcTimestamp;
}

export type OAuthClientKind = 'cimd' | 'dcr' | 'static';

export type OAuthTokenEndpointAuthMethod =
  | 'none'
  | 'client_secret_post'
  | 'client_secret_basic';

export interface OAuthClientRecord {
  readonly clientId: string;
  readonly kind: OAuthClientKind;
  readonly clientName?: string;
  readonly redirectUris: readonly string[];
  readonly scope?: string;
  readonly tokenEndpointAuthMethod?: OAuthTokenEndpointAuthMethod;
  /** Optional cache expiration (used for 1-hour CIMD metadata TTL). */
  readonly expiresAt?: IsoUtcTimestamp;
  readonly createdAt: IsoUtcTimestamp;
  readonly updatedAt: IsoUtcTimestamp;
}

export interface OAuthAuthCodeRecord {
  readonly codeHash: string;
  readonly clientId: string;
  readonly userId: string;
  readonly pluginSlug: string;
  readonly redirectUri: string;
  readonly codeChallenge: string;
  readonly codeChallengeMethod: 'S256';
  readonly scope: string;
  readonly expiresAt: IsoUtcTimestamp;
  readonly usedAt?: IsoUtcTimestamp;
  readonly createdAt: IsoUtcTimestamp;
}

export interface OAuthTokenRecord {
  readonly tokenHash: string;
  readonly userId: string;
  readonly clientId: string;
  readonly pluginSlug: string;
  readonly scope: string;
  readonly expiresAt: IsoUtcTimestamp;
  readonly revokedAt?: IsoUtcTimestamp;
  readonly createdAt: IsoUtcTimestamp;
}

export interface WebSessionRecord {
  readonly cookieHash: string;
  readonly userId: string;
  readonly expiresAt: IsoUtcTimestamp;
  readonly createdAt: IsoUtcTimestamp;
}
```

**Entity Invariants (`3.2`):**
- **Hashed Secret Tokens Only:** `OAuthAuthCodeRecord.codeHash`, `OAuthTokenRecord.tokenHash`, and `WebSessionRecord.cookieHash` store cryptographic digests (SHA-256 hex/base64url) — never plaintext codes, tokens, or session cookies.
- **PKCE `S256` Only:** `OAuthAuthCodeRecord.codeChallengeMethod` is strictly `'S256'`; `plain` is unrepresentable in the type system.
- **Tenant Isolation:** `UserCredentialRecord` is uniquely keyed by `(userId, pluginSlug)`. `OAuthTokenRecord` and `OAuthAuthCodeRecord` carry explicit `(userId, clientId, pluginSlug)` scope.
- **Cascading Purge (`ON DELETE CASCADE`):** Deleting a `UserRecord` (specifically via `purgeInactiveUsers`) MUST cascade-delete all referencing `UserCredentialRecord`, `OAuthAuthCodeRecord`, `OAuthTokenRecord`, and `WebSessionRecord` rows.

### 3.3 Method Input DTOs & `IStorageDriver` Interface

```ts
export interface UpsertUserInput {
  readonly id: string;
  readonly email: string;
  readonly nowIso: IsoUtcTimestamp;
}

export interface UpsertUserCredentialInput {
  readonly userId: string;
  readonly pluginSlug: string;
  readonly encryptedPayload: EncryptedPayload;
  readonly expiresAt?: IsoUtcTimestamp;
  readonly nowIso: IsoUtcTimestamp;
}

export interface UpsertOAuthClientInput {
  readonly clientId: string;
  readonly kind: OAuthClientKind;
  readonly clientName?: string;
  readonly redirectUris: readonly string[];
  readonly scope?: string;
  readonly tokenEndpointAuthMethod?: OAuthTokenEndpointAuthMethod;
  readonly expiresAt?: IsoUtcTimestamp;
  readonly nowIso: IsoUtcTimestamp;
}

export type SaveAuthCodeInput = Omit<OAuthAuthCodeRecord, 'usedAt'>;

export type IssueAccessTokenInput = Omit<OAuthTokenRecord, 'revokedAt'>;

export interface IStorageDriver {
  migrate(): Promise<void>;
  close(): Promise<void>;

  upsertUser(input: UpsertUserInput): Promise<UserRecord>;
  getUserById(userId: string): Promise<UserRecord | null>;
  getUserByEmail(email: string): Promise<UserRecord | null>;
  touchUserActivity(userId: string, activityAtIso: IsoUtcTimestamp): Promise<boolean>;
  purgeInactiveUsers(cutoffIso: IsoUtcTimestamp): Promise<number>;

  upsertUserCredential(input: UpsertUserCredentialInput): Promise<UserCredentialRecord>;
  getUserCredential(userId: string, pluginSlug: string): Promise<UserCredentialRecord | null>;
  deleteUserCredential(userId: string, pluginSlug: string): Promise<boolean>;

  upsertOAuthClient(input: UpsertOAuthClientInput): Promise<OAuthClientRecord>;
  getOAuthClient(clientId: string): Promise<OAuthClientRecord | null>;

  saveAuthCode(input: SaveAuthCodeInput): Promise<void>;
  consumeAuthCode(codeHash: string, nowIso: IsoUtcTimestamp): Promise<OAuthAuthCodeRecord | null>;

  issueAccessToken(input: IssueAccessTokenInput): Promise<OAuthTokenRecord>;
  getActiveTokenByHash(
    tokenHash: string,
    nowIso: IsoUtcTimestamp,
  ): Promise<OAuthTokenRecord | null>;
  revokeClientTokens(
    userId: string,
    clientId: string,
    revokedAtIso: IsoUtcTimestamp,
  ): Promise<number>;

  createWebSession(input: WebSessionRecord): Promise<WebSessionRecord>;
  getActiveWebSessionByHash(
    cookieHash: string,
    nowIso: IsoUtcTimestamp,
  ): Promise<WebSessionRecord | null>;
  deleteWebSessionByHash(cookieHash: string): Promise<boolean>;
}
```

### 3.4 Exact Method Semantics & Failure / Not-Found Matrix

| Method | Input | Return | Not-Found / Expired / Failure Semantics |
| :--- | :--- | :--- | :--- |
| `migrate()` | — | `Promise<void>` | Idempotently applies schema, indexes, WAL/FK pragmas; rejects on DDL/I/O error. |
| `close()` | — | `Promise<void>` | Releases driver resources; idempotent if already closed; rejects only on fatal teardown error. |
| `upsertUser(input)` | `UpsertUserInput` | `Promise<UserRecord>` | Normalizes `email` (`trim().toLowerCase()`). Inserts with `createdAt = updatedAt = lastActivityAt = nowIso`, or updates existing `id` preserving `createdAt`. Rejects if normalized `email` belongs to a different `id`. |
| `getUserById(userId)` | `string` | `Promise<UserRecord \| null>` | Returns `null` when no user exists for `userId`. |
| `getUserByEmail(email)` | `string` | `Promise<UserRecord \| null>` | Normalizes `email` (`trim().toLowerCase()`); returns `null` when not found. |
| `touchUserActivity(userId, activityAtIso)` | `string`, `IsoUtcTimestamp` | `Promise<boolean>` | Sets `lastActivityAt = activityAtIso` and `updatedAt = activityAtIso`. Returns `true` if updated, `false` if `userId` does not exist. |
| `purgeInactiveUsers(cutoffIso)` | `IsoUtcTimestamp` | `Promise<number>` | Permanently deletes users with `lastActivityAt < cutoffIso` (strictly less than) triggering `ON DELETE CASCADE`; returns deleted user count (`0` if none). |
| `upsertUserCredential(input)` | `UpsertUserCredentialInput` | `Promise<UserCredentialRecord>` | Upserts strictly by `(userId, pluginSlug)`, preserving `createdAt` on update and setting `updatedAt = nowIso`. Rejects if `userId` does not exist (FK violation) or slug invalid. |
| `getUserCredential(userId, pluginSlug)` | `string`, `string` | `Promise<UserCredentialRecord \| null>` | Returns `null` if no record exists for exact `(userId, pluginSlug)` pair. |
| `deleteUserCredential(userId, pluginSlug)` | `string`, `string` | `Promise<boolean>` | Deletes exact `(userId, pluginSlug)` row; returns `true` if deleted, `false` if not found. |
| `upsertOAuthClient(input)` | `UpsertOAuthClientInput` | `Promise<OAuthClientRecord>` | Upserts by `clientId`, preserving `createdAt` on update and setting `updatedAt = nowIso`. |
| `getOAuthClient(clientId)` | `string` | `Promise<OAuthClientRecord \| null>` | Returns `null` if `clientId` is absent. Callers inspect `expiresAt` for CIMD TTL freshness. |
| `saveAuthCode(input)` | `SaveAuthCodeInput` | `Promise<void>` | Inserts unconsumed PKCE `S256` code (`usedAt` omitted/null). Rejects on duplicate `codeHash` or missing `userId` FK. |
| `consumeAuthCode(codeHash, nowIso)` | `string`, `IsoUtcTimestamp` | `Promise<OAuthAuthCodeRecord \| null>` | Atomically verifies `usedAt IS NULL` and `expiresAt > nowIso`, sets `usedAt = nowIso`, and returns consumed record. Returns `null` if missing, already used, or `expiresAt <= nowIso`. |
| `issueAccessToken(input)` | `IssueAccessTokenInput` | `Promise<OAuthTokenRecord>` | Within a single atomic transaction: sets `revokedAt = input.createdAt` on all active (`revokedAt IS NULL`) tokens for `(input.userId, input.clientId)`, then inserts new token with `revokedAt = undefined`. Rejects on duplicate `tokenHash` or missing `userId` FK. |
| `getActiveTokenByHash(tokenHash, nowIso)` | `string`, `IsoUtcTimestamp` | `Promise<OAuthTokenRecord \| null>` | Returns record iff `revokedAt IS NULL` and `expiresAt > nowIso`; otherwise returns `null` (not found, revoked, or expired). |
| `revokeClientTokens(userId, clientId, revokedAtIso)` | `string`, `string`, `IsoUtcTimestamp` | `Promise<number>` | Sets `revokedAt = revokedAtIso` on all active (`revokedAt IS NULL`) tokens for `(userId, clientId)`; returns count of newly revoked tokens (`0` if none). |
| `createWebSession(input)` | `WebSessionRecord` | `Promise<WebSessionRecord>` | Inserts `mcphub_session` digest record. Rejects on duplicate `cookieHash` or missing `userId` FK. |
| `getActiveWebSessionByHash(cookieHash, nowIso)` | `string`, `IsoUtcTimestamp` | `Promise<WebSessionRecord \| null>` | Returns record iff `expiresAt > nowIso`; otherwise returns `null` (not found or expired). |
| `deleteWebSessionByHash(cookieHash)` | `string` | `Promise<boolean>` | Deletes session matching `cookieHash`; returns `true` if deleted, `false` if not found. |

---

## 4. Sanitized Upstream Error Boundary & Slug Validation Guards

### 4.1 `sanitizeUpstreamText` (`errors/upstream-client-error.ts`)

```ts
export function sanitizeUpstreamText(input: string): string;
```

**Canonical Redaction Behavior:**
`sanitizeUpstreamText(input)` deterministically returns a scrubbed copy of `input` replacing sensitive credentials with `[REDACTED]` using linear-time (ReDoS-safe) regular expressions while keeping non-sensitive diagnostic text intact:

1. **Multiline Sensitive HTTP Header Lines:** At line starts (`^`), headers matching `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, or `X-Api-Key` (case-insensitive) have their entire header value replaced (`Authorization: [REDACTED]`, `Cookie: [REDACTED]`, `Set-Cookie: [REDACTED]`, `X-Api-Key: [REDACTED]`).
2. **Inline Auth Schemes (`Bearer` / `Basic`):** `Bearer <credentials>` and `Basic <credentials>` (case-insensitive scheme names) are scrubbed to `Bearer [REDACTED]` and `Basic [REDACTED]`.
3. **JWT Tokens (`eyJ...`):** Base64url-encoded 3-segment JWT tokens matching `/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g` are replaced with `[REDACTED]`.
4. **URL Query Parameters:** Query parameters (`?...` / `&...`) whose key matches sensitive keys below have their value replaced while keeping the key name and delimiter (`?api_key=[REDACTED]&symbol=PETR4`).
5. **JSON-Like & Inline Key/Value Pairs (`key: value` / `key=value`):** Case-insensitive sensitive keys covering `password`, `token`, `access`, `refresh`, `secret`, `authorization`, `cookie`, `api_key`, `apiKey` (including snake/camel/kebab compound token/secret/key names such as `access_token`, `accessToken`, `refresh_token`, `refreshToken`, `client_secret`, `x-api-key`, `set-cookie`) have their quoted or unquoted scalar value replaced with `"[REDACTED]"` (when quoted) or `[REDACTED]` (when unquoted).
6. **Prose Preservation:** Ordinary error prose containing English words like `"Invalid token expired"` or `"Unauthorized access"` without `:` / `=` delimiters or `Bearer` / `Basic` / `eyJ` token prefixes MUST NOT be over-redacted.

### 4.2 `UpstreamClientError` (`errors/upstream-client-error.ts`)

```ts
export interface UpstreamClientErrorOptions {
  readonly message: string;
  readonly status: number;
  readonly pluginSlug: string;
  readonly upstreamEndpoint: string;
  readonly sanitizedBody?: string;
  readonly retryable?: boolean;
}

export class UpstreamClientError extends Error {
  override readonly name = 'UpstreamClientError';
  readonly status: number;
  readonly pluginSlug: string;
  readonly upstreamEndpoint: string;
  readonly sanitizedBody?: string;
  readonly retryable: boolean;

  constructor(options: UpstreamClientErrorOptions);
}
```

**Error Boundary Invariants (`4.2`):**
- Constructor MUST pass `options.message`, `options.upstreamEndpoint`, and (when defined) `options.sanitizedBody` through `sanitizeUpstreamText` before storing or passing to `super(...)`.
- `this.name` MUST equal `'UpstreamClientError'` and `err instanceof UpstreamClientError` and `err instanceof Error` MUST evaluate `true`.
- `retryable` uses `options.retryable` when explicitly provided; otherwise defaults deterministically to `options.status === 408 || options.status === 429 || options.status >= 500`.
- `UpstreamClientError` MUST NOT accept or retain an unsanitized `cause` property so crash loggers cannot accidentally emit raw upstream credentials.
- `UpstreamClientError` MUST NOT throw secondary slug-validation errors on `options.pluginSlug` during upstream failure handling.

### 4.3 Slug Validation Guards (`validation/slug.ts`)

```ts
export const PLUGIN_SLUG_MAX_LENGTH = 64;
export const PLUGIN_SLUG_REGEX = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

export function isValidPluginSlug(slug: string): boolean;
export function assertValidPluginSlug(slug: string): string;
```

**Slug Validation Rules (`4.3`):**
- `isValidPluginSlug(slug)` returns `true` iff `slug.length >= 1 && slug.length <= PLUGIN_SLUG_MAX_LENGTH` AND `PLUGIN_SLUG_REGEX.test(slug)` is `true`. Rejects empty strings, lengths `> 64`, uppercase characters, underscores, spaces, path traversal (`..`, `/`, `\`), leading/trailing hyphens, and consecutive hyphens (`--`).
- `assertValidPluginSlug(slug)` returns `slug` unchanged when `isValidPluginSlug(slug)` is `true`; otherwise throws an `Error` with a clear fixed-format message (`'Invalid plugin slug: must be 1..64 lowercase alphanumeric characters separated by single hyphens'`), avoiding echoing unbounded untrusted input.

---

## 5. Module Layout, Invariants & Verification Criteria

### 5.1 Canonical Module Layout & Exports

```text
packages/mcp-core/src/
├── contracts/
│   ├── plugin.ts                 # Plugin metadata, auth, execution context, MCP primitives, IMcpPlugin
│   └── storage.ts                # EncryptedPayload, Vault/OAuth/SSO records, DTOs, IStorageDriver
├── errors/
│   └── upstream-client-error.ts  # sanitizeUpstreamText, UpstreamClientError, UpstreamClientErrorOptions
├── validation/
│   └── slug.ts                   # PLUGIN_SLUG_MAX_LENGTH, PLUGIN_SLUG_REGEX, isValidPluginSlug, assertValidPluginSlug
└── index.ts                      # Barrel re-exporting all contracts, guards, errors + existing health exports
```

**Build & Import Invariants:**
- All relative imports/re-exports inside `packages/mcp-core/src/` MUST use explicit `.js` extensions (`NodeNext` ESM) and `export type` for type-only exports (`verbatimModuleSyntax: true`).
- `packages/mcp-core/src/` MUST contain **zero** `node:*` imports, runtime environment reads (`process.env`), or third-party dependencies.
- `packages/mcp-core/src/index.ts` MUST preserve `PLATFORM_NAME`, `HealthPayload`, and `createHealthPayload` without breaking changes.

### 5.2 Traceability Matrix (`docs/rules/core-invariants.md`)

| `core-invariants.md` Section | Spec Mapping (`mcp-core-contracts.md`) |
| :--- | :--- |
| **§1 Protocol & Transport Fidelity** | §2.3 (`ResourceDefinition`, `ToolDefinition`, `PromptDefinition` matching official MCP primitives without ad-hoc manifest fields) and §4.3 (slug rules backing `/:slug/mcp` Streamable HTTP routing). |
| **§2 OAuth 2.1, Universal Client Triad & Anti-SSRF** | §3.2–3.4 (`OAuthClientKind = 'cimd' \| 'dcr' \| 'static'`, `OAuthClientRecord` with 1h CIMD `expiresAt`, PKCE `S256`-only `OAuthAuthCodeRecord` + atomic `consumeAuthCode`, hashed `tokenHash` / `cookieHash`, atomic prior-token revocation in `issueAccessToken`). |
| **§3 Multi-Tenant Vault, Cryptography & Zero-Trust Privacy** | §2.2 (`PluginExecutionContext` isolating `IStorageDriver` and `ENCRYPTION_MASTER_KEY`), §3.1–3.4 (`EncryptedPayload`, `(userId, pluginSlug)` isolation on `UserCredentialRecord`, `touchUserActivity` + cascading `purgeInactiveUsers`). |
| **§4 Secrets, Logging & Memory Hygiene** | §2.1 (`UpstreamValidationResult` sanitized `error`), §3.2 (digest-only auth codes/tokens/sessions), §4.1–4.2 (`sanitizeUpstreamText` + `UpstreamClientError` scrubbing Bearer/Basic, JWTs, sensitive keys across `message`, `upstreamEndpoint`, and `sanitizedBody`). |
| **§5 Upstream Contract Inviolability & Resilience** | §2.1–2.3 (`validateUpstream`, `refreshUpstream`, `updateCredentials`, `signal`, pass-through `Readonly<Record<string, unknown>>` and `structuredContent`), §4.2 (`UpstreamClientError.retryable`). |
| **§6 Isomorphic Portability & Plugin Decoupling** | §1, §2.4, §5.1 (pure TypeScript + Web Standards `AbortSignal`, zero `node:*` imports, `IStorageDriver` abstraction for SQLite/D1 portability, `IMcpPlugin` decoupling, `PluginMetadata.locale` supporting `'pt-BR'` connectors). |

### 5.3 Verification Criteria (QA Red-Test & Coder Gates)

1. **Pre-Implementation Red Tests (`Step 2`):**
   - `packages/mcp-core/test/*.test.ts` imports all exported contracts, guards, and `UpstreamClientError` from `@mcphub/core` and fails reproducibly before implementation.
   - Type-level tests (`vitest` `expectTypeOf` + `tsc --noEmit`) assert strict discriminated unions (`UpstreamValidationResult`, `ResourceContent`), `OAuthAuthCodeRecord['codeChallengeMethod']` literal `'S256'`, `PluginExecutionContext` isolation, and all 20 `IStorageDriver` signatures without `any`.
2. **Executable Runtime Coverage (`Step 3`):**
   - `isValidPluginSlug` and `assertValidPluginSlug` pass valid slugs (`1..64` chars, hyphens) and reject invalid cases (empty, `>64`, uppercase, underscores, path traversal, leading/trailing/double hyphens).
   - `sanitizeUpstreamText` and `UpstreamClientError` scrub Bearer/Basic headers, JWTs (`eyJ...`), JSON-like key/value pairs, URL query params, and HTTP header lines across `message`, `upstreamEndpoint`, and `sanitizedBody`, preserve `name === 'UpstreamClientError'`, resolve `retryable` defaults/overrides, and keep non-secret prose intact.
   - Static check/test confirms zero `node:*` imports under `packages/mcp-core/src/`.
3. **Final Gate (`npm run build && npm run gate`):**
   - Zero ESLint errors, zero Prettier issues, clean `tsc --noEmit` across all workspaces, clean ESM `.js`/`.d.ts` emission in `packages/mcp-core/dist/`, and **100% statement coverage** across `packages/mcp-core/src/**`.
