/** Canonical UTC ISO-8601 timestamp (`YYYY-MM-DDTHH:mm:ss.sssZ`) enabling lexical comparison. */
export type IsoUtcTimestamp = string;

/** Encrypted vault envelope produced by Web Crypto AES-256-GCM sealing. */
export interface EncryptedPayload {
  readonly ciphertext: string;
  readonly iv: string;
  readonly authTag: string;
  readonly keyVersion?: number;
}

/** Persisted platform user identity and inactivity tracking record. */
export interface UserRecord {
  readonly id: string;
  readonly email: string;
  readonly createdAt: IsoUtcTimestamp;
  readonly updatedAt: IsoUtcTimestamp;
  readonly lastActivityAt: IsoUtcTimestamp;
}

/** Per-tenant, per-plugin encrypted upstream credential vault record. */
export interface UserCredentialRecord {
  readonly userId: string;
  readonly pluginSlug: string;
  readonly encryptedPayload: EncryptedPayload;
  readonly expiresAt?: IsoUtcTimestamp;
  readonly createdAt: IsoUtcTimestamp;
  readonly updatedAt: IsoUtcTimestamp;
}

/** Registered OAuth 2.1 client provisioning classification. */
export type OAuthClientKind = 'cimd' | 'dcr' | 'static';

/** Supported OAuth 2.1 token endpoint client authentication methods. */
export type OAuthTokenEndpointAuthMethod = 'none' | 'client_secret_post' | 'client_secret_basic';

/** Persisted OAuth 2.1 client metadata (including cached CIMD documents). */
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

/** Hashed PKCE S256 authorization code record persisted during OAuth 2.1 handshakes. */
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

/** Hashed OAuth 2.1 access token record scoped to `(userId, clientId, pluginSlug)`. */
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

/** Hashed portal SSO session cookie record (`mcphub_session`). */
export interface WebSessionRecord {
  readonly cookieHash: string;
  readonly userId: string;
  readonly expiresAt: IsoUtcTimestamp;
  readonly createdAt: IsoUtcTimestamp;
}

/** Input payload for creating or updating a platform user record. */
export interface UpsertUserInput {
  readonly id: string;
  readonly email: string;
  readonly nowIso: IsoUtcTimestamp;
}

/** Input payload for creating or replacing encrypted upstream credentials for `(userId, pluginSlug)`. */
export interface UpsertUserCredentialInput {
  readonly userId: string;
  readonly pluginSlug: string;
  readonly encryptedPayload: EncryptedPayload;
  readonly expiresAt?: IsoUtcTimestamp;
  readonly nowIso: IsoUtcTimestamp;
}

/** Input payload for registering or refreshing an OAuth 2.1 client record. */
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

/** Input payload for persisting a freshly issued, unconsumed PKCE S256 auth code. */
export type SaveAuthCodeInput = Omit<OAuthAuthCodeRecord, 'usedAt'>;

/** Input payload for issuing a new active OAuth 2.1 access token. */
export type IssueAccessTokenInput = Omit<OAuthTokenRecord, 'revokedAt'>;

/** Runtime-portable async persistence abstraction backed by SQLite or Cloudflare D1. */
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
