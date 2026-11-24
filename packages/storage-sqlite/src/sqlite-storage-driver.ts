import { DatabaseSync } from 'node:sqlite';
import {
  assertValidPluginSlug,
  type IStorageDriver,
  type IsoUtcTimestamp,
  type IssueAccessTokenInput,
  type OAuthAuthCodeRecord,
  type OAuthClientKind,
  type OAuthClientRecord,
  type OAuthTokenEndpointAuthMethod,
  type OAuthTokenRecord,
  type SaveAuthCodeInput,
  type UpsertOAuthClientInput,
  type UpsertUserCredentialInput,
  type UpsertUserInput,
  type UserCredentialRecord,
  type UserRecord,
  type WebSessionRecord,
} from '@mcphub/core';

const DEFAULT_BUSY_TIMEOUT_MS = 5000;

const SCHEMA_SQL = `
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_activity_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_last_activity_at
  ON users (last_activity_at);

CREATE TABLE IF NOT EXISTS user_credentials (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  plugin_slug TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  iv TEXT NOT NULL,
  auth_tag TEXT NOT NULL,
  key_version INTEGER,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (user_id, plugin_slug)
);

CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('cimd', 'dcr', 'static')),
  client_name TEXT,
  redirect_uris TEXT NOT NULL,
  scope TEXT,
  token_endpoint_auth_method TEXT CHECK (
    token_endpoint_auth_method IS NULL OR
    token_endpoint_auth_method IN ('none', 'client_secret_post', 'client_secret_basic')
  ),
  expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_auth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  plugin_slug TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL CHECK (code_challenge_method = 'S256'),
  scope TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_user_id
  ON oauth_auth_codes (user_id);

CREATE TABLE IF NOT EXISTS oauth_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL,
  plugin_slug TEXT NOT NULL,
  scope TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user_client_active
  ON oauth_tokens (user_id, client_id)
  WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS web_sessions (
  cookie_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_web_sessions_user_id
  ON web_sessions (user_id);
`;

type UserRow = {
  id: string;
  email: string;
  created_at: string;
  updated_at: string;
  last_activity_at: string;
};

type UserCredentialRow = {
  user_id: string;
  plugin_slug: string;
  ciphertext: string;
  iv: string;
  auth_tag: string;
  key_version: number | null;
  expires_at: string | null;
  created_at: string;
  updated_at: string;
};

type OAuthClientRow = {
  client_id: string;
  kind: OAuthClientKind;
  client_name: string | null;
  redirect_uris: string;
  scope: string | null;
  token_endpoint_auth_method: OAuthTokenEndpointAuthMethod | null;
  expires_at: string | null;
  created_at: string;
  updated_at: string;
};

type ConsumedAuthCodeRow = {
  code_hash: string;
  client_id: string;
  user_id: string;
  plugin_slug: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: 'S256';
  scope: string;
  expires_at: string;
  used_at: string;
  created_at: string;
};

type ActiveTokenRow = {
  token_hash: string;
  user_id: string;
  client_id: string;
  plugin_slug: string;
  scope: string;
  expires_at: string;
  created_at: string;
};

type WebSessionRow = {
  cookie_hash: string;
  user_id: string;
  expires_at: string;
  created_at: string;
};

/** Configuration options for instantiating {@link SqliteStorageDriver}. */
export interface SqliteStorageDriverOptions {
  /** SQLite database file path or `':memory:'` for ephemeral test instances. */
  readonly filename: string;
  /** SQLite lock busy timeout in milliseconds (defaults to `5000`). */
  readonly busyTimeoutMs?: number;
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function mapUserRow(row: UserRow): UserRecord {
  return {
    id: row.id,
    email: row.email,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastActivityAt: row.last_activity_at,
  };
}

function mapUserCredentialRow(row: UserCredentialRow): UserCredentialRecord {
  return {
    userId: row.user_id,
    pluginSlug: row.plugin_slug,
    encryptedPayload: {
      ciphertext: row.ciphertext,
      iv: row.iv,
      authTag: row.auth_tag,
      ...(row.key_version !== null ? { keyVersion: row.key_version } : {}),
    },
    ...(row.expires_at !== null ? { expiresAt: row.expires_at } : {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapOAuthClientRow(row: OAuthClientRow): OAuthClientRecord {
  return {
    clientId: row.client_id,
    kind: row.kind,
    ...(row.client_name !== null ? { clientName: row.client_name } : {}),
    redirectUris: JSON.parse(row.redirect_uris) as readonly string[],
    ...(row.scope !== null ? { scope: row.scope } : {}),
    ...(row.token_endpoint_auth_method !== null
      ? { tokenEndpointAuthMethod: row.token_endpoint_auth_method }
      : {}),
    ...(row.expires_at !== null ? { expiresAt: row.expires_at } : {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapConsumedAuthCodeRow(row: ConsumedAuthCodeRow): OAuthAuthCodeRecord {
  return {
    codeHash: row.code_hash,
    clientId: row.client_id,
    userId: row.user_id,
    pluginSlug: row.plugin_slug,
    redirectUri: row.redirect_uri,
    codeChallenge: row.code_challenge,
    codeChallengeMethod: row.code_challenge_method,
    scope: row.scope,
    expiresAt: row.expires_at,
    usedAt: row.used_at,
    createdAt: row.created_at,
  };
}

function mapActiveTokenRow(row: ActiveTokenRow): OAuthTokenRecord {
  return {
    tokenHash: row.token_hash,
    userId: row.user_id,
    clientId: row.client_id,
    pluginSlug: row.plugin_slug,
    scope: row.scope,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
  };
}

function mapWebSessionRow(row: WebSessionRow): WebSessionRecord {
  return {
    cookieHash: row.cookie_hash,
    userId: row.user_id,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
  };
}

/**
 * Node.js 26 `node:sqlite` implementation of {@link IStorageDriver} using WAL mode,
 * foreign-key enforcement (`ON DELETE CASCADE`), and 100% parameterized queries.
 */
export class SqliteStorageDriver implements IStorageDriver {
  private readonly db: DatabaseSync;

  constructor(options: SqliteStorageDriverOptions) {
    const trimmedFilename = options.filename.trim();
    if (trimmedFilename.length === 0) {
      throw new RangeError('SQLite filename must be a non-empty string');
    }

    const busyTimeoutMs = options.busyTimeoutMs ?? DEFAULT_BUSY_TIMEOUT_MS;
    if (!Number.isSafeInteger(busyTimeoutMs) || busyTimeoutMs < 0) {
      throw new RangeError('SQLite busyTimeoutMs must be a non-negative safe integer');
    }

    this.db = new DatabaseSync(trimmedFilename, {
      enableForeignKeyConstraints: true,
      timeout: busyTimeoutMs,
    });
  }

  async migrate(): Promise<void> {
    this.db.exec(SCHEMA_SQL);
  }

  async close(): Promise<void> {
    if (!this.db.isOpen) {
      return;
    }
    this.db.close();
  }

  async upsertUser(input: UpsertUserInput): Promise<UserRecord> {
    const email = normalizeEmail(input.email);
    const row = this.db
      .prepare(
        `INSERT INTO users (id, email, created_at, updated_at, last_activity_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           email = excluded.email,
           updated_at = excluded.updated_at
         RETURNING id, email, created_at, updated_at, last_activity_at`,
      )
      .get(input.id, email, input.nowIso, input.nowIso, input.nowIso) as UserRow;

    return mapUserRow(row);
  }

  async getUserById(userId: string): Promise<UserRecord | null> {
    const row = this.db
      .prepare('SELECT id, email, created_at, updated_at, last_activity_at FROM users WHERE id = ?')
      .get(userId) as UserRow | undefined;

    return row ? mapUserRow(row) : null;
  }

  async getUserByEmail(email: string): Promise<UserRecord | null> {
    const row = this.db
      .prepare(
        'SELECT id, email, created_at, updated_at, last_activity_at FROM users WHERE email = ?',
      )
      .get(normalizeEmail(email)) as UserRow | undefined;

    return row ? mapUserRow(row) : null;
  }

  async touchUserActivity(userId: string, activityAtIso: IsoUtcTimestamp): Promise<boolean> {
    const result = this.db
      .prepare('UPDATE users SET last_activity_at = ?, updated_at = ? WHERE id = ?')
      .run(activityAtIso, activityAtIso, userId);

    return Number(result.changes) > 0;
  }

  async purgeInactiveUsers(cutoffIso: IsoUtcTimestamp): Promise<number> {
    const result = this.db.prepare('DELETE FROM users WHERE last_activity_at < ?').run(cutoffIso);
    return Number(result.changes);
  }

  async upsertUserCredential(input: UpsertUserCredentialInput): Promise<UserCredentialRecord> {
    assertValidPluginSlug(input.pluginSlug);

    const row = this.db
      .prepare(
        `INSERT INTO user_credentials (
           user_id, plugin_slug, ciphertext, iv, auth_tag, key_version, expires_at, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id, plugin_slug) DO UPDATE SET
           ciphertext = excluded.ciphertext,
           iv = excluded.iv,
           auth_tag = excluded.auth_tag,
           key_version = excluded.key_version,
           expires_at = excluded.expires_at,
           updated_at = excluded.updated_at
         RETURNING user_id, plugin_slug, ciphertext, iv, auth_tag, key_version, expires_at, created_at, updated_at`,
      )
      .get(
        input.userId,
        input.pluginSlug,
        input.encryptedPayload.ciphertext,
        input.encryptedPayload.iv,
        input.encryptedPayload.authTag,
        input.encryptedPayload.keyVersion ?? null,
        input.expiresAt ?? null,
        input.nowIso,
        input.nowIso,
      ) as UserCredentialRow;

    return mapUserCredentialRow(row);
  }

  async getUserCredential(
    userId: string,
    pluginSlug: string,
  ): Promise<UserCredentialRecord | null> {
    const row = this.db
      .prepare(
        `SELECT user_id, plugin_slug, ciphertext, iv, auth_tag, key_version, expires_at, created_at, updated_at
         FROM user_credentials
         WHERE user_id = ? AND plugin_slug = ?`,
      )
      .get(userId, pluginSlug) as UserCredentialRow | undefined;

    return row ? mapUserCredentialRow(row) : null;
  }

  async deleteUserCredential(userId: string, pluginSlug: string): Promise<boolean> {
    const result = this.db
      .prepare('DELETE FROM user_credentials WHERE user_id = ? AND plugin_slug = ?')
      .run(userId, pluginSlug);

    return Number(result.changes) > 0;
  }

  async upsertOAuthClient(input: UpsertOAuthClientInput): Promise<OAuthClientRecord> {
    const row = this.db
      .prepare(
        `INSERT INTO oauth_clients (
           client_id, kind, client_name, redirect_uris, scope, token_endpoint_auth_method, expires_at, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(client_id) DO UPDATE SET
           kind = excluded.kind,
           client_name = excluded.client_name,
           redirect_uris = excluded.redirect_uris,
           scope = excluded.scope,
           token_endpoint_auth_method = excluded.token_endpoint_auth_method,
           expires_at = excluded.expires_at,
           updated_at = excluded.updated_at
         RETURNING client_id, kind, client_name, redirect_uris, scope, token_endpoint_auth_method, expires_at, created_at, updated_at`,
      )
      .get(
        input.clientId,
        input.kind,
        input.clientName ?? null,
        JSON.stringify(input.redirectUris),
        input.scope ?? null,
        input.tokenEndpointAuthMethod ?? null,
        input.expiresAt ?? null,
        input.nowIso,
        input.nowIso,
      ) as OAuthClientRow;

    return mapOAuthClientRow(row);
  }

  async getOAuthClient(clientId: string): Promise<OAuthClientRecord | null> {
    const row = this.db
      .prepare(
        `SELECT client_id, kind, client_name, redirect_uris, scope, token_endpoint_auth_method, expires_at, created_at, updated_at
         FROM oauth_clients
         WHERE client_id = ?`,
      )
      .get(clientId) as OAuthClientRow | undefined;

    return row ? mapOAuthClientRow(row) : null;
  }

  async saveAuthCode(input: SaveAuthCodeInput): Promise<void> {
    assertValidPluginSlug(input.pluginSlug);

    this.db
      .prepare(
        `INSERT INTO oauth_auth_codes (
           code_hash, client_id, user_id, plugin_slug, redirect_uri, code_challenge, code_challenge_method, scope, expires_at, used_at, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`,
      )
      .run(
        input.codeHash,
        input.clientId,
        input.userId,
        input.pluginSlug,
        input.redirectUri,
        input.codeChallenge,
        input.codeChallengeMethod,
        input.scope,
        input.expiresAt,
        input.createdAt,
      );
  }

  async consumeAuthCode(
    codeHash: string,
    nowIso: IsoUtcTimestamp,
  ): Promise<OAuthAuthCodeRecord | null> {
    const row = this.db
      .prepare(
        `UPDATE oauth_auth_codes
         SET used_at = ?
         WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?
         RETURNING code_hash, client_id, user_id, plugin_slug, redirect_uri, code_challenge, code_challenge_method, scope, expires_at, used_at, created_at`,
      )
      .get(nowIso, codeHash, nowIso) as ConsumedAuthCodeRow | undefined;

    return row ? mapConsumedAuthCodeRow(row) : null;
  }

  async issueAccessToken(input: IssueAccessTokenInput): Promise<OAuthTokenRecord> {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db
        .prepare(
          'UPDATE oauth_tokens SET revoked_at = ? WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL',
        )
        .run(input.createdAt, input.userId, input.clientId);

      this.db
        .prepare(
          `INSERT INTO oauth_tokens (
             token_hash, user_id, client_id, plugin_slug, scope, expires_at, revoked_at, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?)`,
        )
        .run(
          input.tokenHash,
          input.userId,
          input.clientId,
          input.pluginSlug,
          input.scope,
          input.expiresAt,
          input.createdAt,
        );

      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }

    return {
      tokenHash: input.tokenHash,
      userId: input.userId,
      clientId: input.clientId,
      pluginSlug: input.pluginSlug,
      scope: input.scope,
      expiresAt: input.expiresAt,
      createdAt: input.createdAt,
    };
  }

  async getActiveTokenByHash(
    tokenHash: string,
    nowIso: IsoUtcTimestamp,
  ): Promise<OAuthTokenRecord | null> {
    const row = this.db
      .prepare(
        `SELECT token_hash, user_id, client_id, plugin_slug, scope, expires_at, created_at
         FROM oauth_tokens
         WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?`,
      )
      .get(tokenHash, nowIso) as ActiveTokenRow | undefined;

    return row ? mapActiveTokenRow(row) : null;
  }

  async revokeClientTokens(
    userId: string,
    clientId: string,
    revokedAtIso: IsoUtcTimestamp,
  ): Promise<number> {
    const result = this.db
      .prepare(
        'UPDATE oauth_tokens SET revoked_at = ? WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL',
      )
      .run(revokedAtIso, userId, clientId);

    return Number(result.changes);
  }

  async createWebSession(input: WebSessionRecord): Promise<WebSessionRecord> {
    this.db
      .prepare(
        'INSERT INTO web_sessions (cookie_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)',
      )
      .run(input.cookieHash, input.userId, input.expiresAt, input.createdAt);

    return {
      cookieHash: input.cookieHash,
      userId: input.userId,
      expiresAt: input.expiresAt,
      createdAt: input.createdAt,
    };
  }

  async getActiveWebSessionByHash(
    cookieHash: string,
    nowIso: IsoUtcTimestamp,
  ): Promise<WebSessionRecord | null> {
    const row = this.db
      .prepare(
        'SELECT cookie_hash, user_id, expires_at, created_at FROM web_sessions WHERE cookie_hash = ? AND expires_at > ?',
      )
      .get(cookieHash, nowIso) as WebSessionRow | undefined;

    return row ? mapWebSessionRow(row) : null;
  }

  async deleteWebSessionByHash(cookieHash: string): Promise<boolean> {
    const result = this.db
      .prepare('DELETE FROM web_sessions WHERE cookie_hash = ?')
      .run(cookieHash);

    return Number(result.changes) > 0;
  }
}

/** Creates a new {@link SqliteStorageDriver} instance configured for Node.js 26 `node:sqlite`. */
export function createSqliteStorageDriver(
  options: SqliteStorageDriverOptions,
): SqliteStorageDriver {
  return new SqliteStorageDriver(options);
}
