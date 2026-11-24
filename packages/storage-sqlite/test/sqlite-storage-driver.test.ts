/// <reference types="node" />
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  createAesGcmCipher,
  type IStorageDriver,
  type OAuthAuthCodeRecord,
  type OAuthClientRecord,
  type OAuthTokenRecord,
  type UserCredentialRecord,
  type UserRecord,
  type WebSessionRecord,
} from '@mcphub/core';
import {
  createSqliteStorageDriver,
  SqliteStorageDriver,
  type SqliteStorageDriverOptions,
} from '@mcphub/storage-sqlite';
import { afterEach, describe, expect, expectTypeOf, it } from 'vitest';

const TEST_MASTER_KEY_HEX = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

const openDrivers: SqliteStorageDriver[] = [];

async function createMemoryDriver(): Promise<SqliteStorageDriver> {
  const driver = createSqliteStorageDriver({ filename: ':memory:' });
  openDrivers.push(driver);
  await driver.migrate();
  return driver;
}

afterEach(async () => {
  while (openDrivers.length > 0) {
    const driver = openDrivers.pop();
    if (driver) {
      await driver.close();
    }
  }
});

describe('@mcphub/storage-sqlite public contracts & construction', () => {
  it('implements IStorageDriver and preserves strict factory types', () => {
    expectTypeOf<SqliteStorageDriver>().toMatchTypeOf<IStorageDriver>();
    expectTypeOf(createSqliteStorageDriver).toEqualTypeOf<
      (options: SqliteStorageDriverOptions) => SqliteStorageDriver
    >();
  });

  it.each([
    ['empty filename', ''],
    ['whitespace filename', '   \t\n '],
  ])('rejects invalid filename (%s)', (_label, badFilename) => {
    expect(() => createSqliteStorageDriver({ filename: badFilename })).toThrow();
  });

  it.each([
    ['negative timeout', -1],
    ['fractional timeout', 12.5],
    ['NaN timeout', Number.NaN],
    ['Infinity timeout', Number.POSITIVE_INFINITY],
  ])('rejects invalid busyTimeoutMs (%s)', (_label, badTimeout) => {
    expect(() =>
      createSqliteStorageDriver({ filename: ':memory:', busyTimeoutMs: badTimeout }),
    ).toThrow();
  });

  it('configures WAL mode and foreign keys on file-backed databases with idempotent migrate and close', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'mcphub-sqlite-'));
    const dbPath = join(tempDir, 'vault.sqlite');
    const driver = createSqliteStorageDriver({ filename: dbPath, busyTimeoutMs: 2500 });

    try {
      await driver.migrate();
      await driver.migrate();

      const inspector = new DatabaseSync(dbPath);
      try {
        const journalRow = inspector.prepare('PRAGMA journal_mode').get() as {
          journal_mode: string;
        };
        const fkRow = inspector.prepare('PRAGMA foreign_keys').get() as {
          foreign_keys: number;
        };

        expect(journalRow.journal_mode.toLowerCase()).toBe('wal');
        expect(fkRow.foreign_keys).toBe(1);
      } finally {
        inspector.close();
      }

      await driver.close();
      await driver.close();

      await expect(driver.getUserById('user-1')).rejects.toThrow();
    } finally {
      await driver.close();
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});

describe('SqliteStorageDriver user lifecycle & cascading inactivity purge', () => {
  it('upserts users with normalized email, preserves createdAt on update, and rejects email collisions', async () => {
    const driver = await createMemoryDriver();

    const created = await driver.upsertUser({
      id: 'user-1',
      email: '  Alice.Investor@Example.COM ',
      nowIso: '2026-11-01T10:00:00.000Z',
    });

    expect(created).toEqual<UserRecord>({
      id: 'user-1',
      email: 'alice.investor@example.com',
      createdAt: '2026-11-01T10:00:00.000Z',
      updatedAt: '2026-11-01T10:00:00.000Z',
      lastActivityAt: '2026-11-01T10:00:00.000Z',
    });

    const updated = await driver.upsertUser({
      id: 'user-1',
      email: 'ALICE.NEW@Example.com',
      nowIso: '2026-11-02T12:00:00.000Z',
    });

    expect(updated).toEqual<UserRecord>({
      id: 'user-1',
      email: 'alice.new@example.com',
      createdAt: '2026-11-01T10:00:00.000Z',
      updatedAt: '2026-11-02T12:00:00.000Z',
      lastActivityAt: '2026-11-01T10:00:00.000Z',
    });

    await expect(
      driver.upsertUser({
        id: 'user-2',
        email: '  Alice.New@example.com ',
        nowIso: '2026-11-02T13:00:00.000Z',
      }),
    ).rejects.toThrow();

    expect(await driver.getUserById('user-1')).toEqual(updated);
    expect(await driver.getUserById('missing-user')).toBeNull();
    expect(await driver.getUserByEmail('  ALICE.NEW@EXAMPLE.COM  ')).toEqual(updated);
    expect(await driver.getUserByEmail('absent@example.com')).toBeNull();
  });

  it('touches user activity timestamps and returns false for unknown user', async () => {
    const driver = await createMemoryDriver();
    await driver.upsertUser({
      id: 'user-1',
      email: 'user1@example.com',
      nowIso: '2026-11-01T00:00:00.000Z',
    });

    expect(await driver.touchUserActivity('user-1', '2026-11-10T08:30:00.000Z')).toBe(true);
    expect(await driver.touchUserActivity('unknown', '2026-11-10T08:30:00.000Z')).toBe(false);

    expect(await driver.getUserById('user-1')).toEqual<UserRecord>({
      id: 'user-1',
      email: 'user1@example.com',
      createdAt: '2026-11-01T00:00:00.000Z',
      updatedAt: '2026-11-10T08:30:00.000Z',
      lastActivityAt: '2026-11-10T08:30:00.000Z',
    });
  });

  it('purges users strictly older than cutoffIso and cascades deletions across all child tables', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'mcphub-cascade-'));
    const dbPath = join(tempDir, 'cascade.sqlite');
    const driver = createSqliteStorageDriver({ filename: dbPath });

    try {
      await driver.migrate();

      await driver.upsertUser({
        id: 'user-stale',
        email: 'stale@example.com',
        nowIso: '2026-09-01T00:00:00.000Z',
      });
      await driver.upsertUser({
        id: 'user-boundary',
        email: 'boundary@example.com',
        nowIso: '2026-10-01T00:00:00.000Z',
      });
      await driver.upsertUser({
        id: 'user-active',
        email: 'active@example.com',
        nowIso: '2026-11-01T00:00:00.000Z',
      });

      for (const userId of ['user-stale', 'user-active']) {
        await driver.upsertUserCredential({
          userId,
          pluginSlug: 'fiainvest',
          encryptedPayload: {
            ciphertext: `ct-${userId}`,
            iv: `iv-${userId}`,
            authTag: `tag-${userId}`,
            keyVersion: 1,
          },
          nowIso: '2026-11-01T00:00:00.000Z',
        });
        await driver.saveAuthCode({
          codeHash: `code-hash-${userId}`,
          clientId: 'claude-web',
          userId,
          pluginSlug: 'fiainvest',
          redirectUri: 'https://claude.ai/api/mcp/auth_callback',
          codeChallenge: 'challenge-123',
          codeChallengeMethod: 'S256',
          scope: 'portfolio:read',
          expiresAt: '2026-12-01T00:00:00.000Z',
          createdAt: '2026-11-01T00:00:00.000Z',
        });
        await driver.issueAccessToken({
          tokenHash: `token-hash-${userId}`,
          userId,
          clientId: 'claude-web',
          pluginSlug: 'fiainvest',
          scope: 'portfolio:read',
          expiresAt: '2026-12-01T00:00:00.000Z',
          createdAt: '2026-11-01T00:00:00.000Z',
        });
        await driver.createWebSession({
          cookieHash: `cookie-hash-${userId}`,
          userId,
          expiresAt: '2026-12-01T00:00:00.000Z',
          createdAt: '2026-11-01T00:00:00.000Z',
        });
      }

      expect(await driver.purgeInactiveUsers('2026-08-01T00:00:00.000Z')).toBe(0);
      expect(await driver.purgeInactiveUsers('2026-10-01T00:00:00.000Z')).toBe(1);

      expect(await driver.getUserById('user-stale')).toBeNull();
      expect(await driver.getUserById('user-boundary')).not.toBeNull();
      expect(await driver.getUserById('user-active')).not.toBeNull();

      expect(await driver.getUserCredential('user-stale', 'fiainvest')).toBeNull();
      expect(
        await driver.getActiveTokenByHash('token-hash-user-stale', '2026-11-02T00:00:00.000Z'),
      ).toBeNull();
      expect(
        await driver.getActiveWebSessionByHash(
          'cookie-hash-user-stale',
          '2026-11-02T00:00:00.000Z',
        ),
      ).toBeNull();
      expect(
        await driver.consumeAuthCode('code-hash-user-stale', '2026-11-02T00:00:00.000Z'),
      ).toBeNull();

      expect(await driver.getUserCredential('user-active', 'fiainvest')).not.toBeNull();
      expect(
        await driver.getActiveTokenByHash('token-hash-user-active', '2026-11-02T00:00:00.000Z'),
      ).not.toBeNull();
      expect(
        await driver.getActiveWebSessionByHash(
          'cookie-hash-user-active',
          '2026-11-02T00:00:00.000Z',
        ),
      ).not.toBeNull();

      await driver.close();

      const inspector = new DatabaseSync(dbPath);
      try {
        for (const table of [
          'user_credentials',
          'oauth_auth_codes',
          'oauth_tokens',
          'web_sessions',
        ]) {
          const countRow = inspector
            .prepare(`SELECT COUNT(*) AS count FROM ${table} WHERE user_id = ?`)
            .get('user-stale') as { count: number };
          expect(countRow.count).toBe(0);
        }
      } finally {
        inspector.close();
      }
    } finally {
      await driver.close();
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});

describe('SqliteStorageDriver encrypted credentials & tenant isolation', () => {
  it('upserts, isolates by (userId, pluginSlug), deletes, and validates slugs and FKs', async () => {
    const driver = await createMemoryDriver();
    await driver.upsertUser({
      id: 'user-1',
      email: 'u1@example.com',
      nowIso: '2026-11-01T00:00:00.000Z',
    });
    await driver.upsertUser({
      id: 'user-2',
      email: 'u2@example.com',
      nowIso: '2026-11-01T00:00:00.000Z',
    });

    const first = await driver.upsertUserCredential({
      userId: 'user-1',
      pluginSlug: 'fiainvest',
      encryptedPayload: {
        ciphertext: 'cipher-1',
        iv: 'iv-1',
        authTag: 'tag-1',
        keyVersion: 1,
      },
      expiresAt: '2026-11-15T00:00:00.000Z',
      nowIso: '2026-11-01T01:00:00.000Z',
    });

    expect(first).toEqual<UserCredentialRecord>({
      userId: 'user-1',
      pluginSlug: 'fiainvest',
      encryptedPayload: {
        ciphertext: 'cipher-1',
        iv: 'iv-1',
        authTag: 'tag-1',
        keyVersion: 1,
      },
      expiresAt: '2026-11-15T00:00:00.000Z',
      createdAt: '2026-11-01T01:00:00.000Z',
      updatedAt: '2026-11-01T01:00:00.000Z',
    });

    const updated = await driver.upsertUserCredential({
      userId: 'user-1',
      pluginSlug: 'fiainvest',
      encryptedPayload: {
        ciphertext: 'cipher-2',
        iv: 'iv-2',
        authTag: 'tag-2',
      },
      nowIso: '2026-11-02T01:00:00.000Z',
    });

    expect(updated).toEqual<UserCredentialRecord>({
      userId: 'user-1',
      pluginSlug: 'fiainvest',
      encryptedPayload: {
        ciphertext: 'cipher-2',
        iv: 'iv-2',
        authTag: 'tag-2',
      },
      createdAt: '2026-11-01T01:00:00.000Z',
      updatedAt: '2026-11-02T01:00:00.000Z',
    });
    expect('expiresAt' in updated).toBe(false);
    expect('keyVersion' in updated.encryptedPayload).toBe(false);

    await driver.upsertUserCredential({
      userId: 'user-2',
      pluginSlug: 'fiainvest',
      encryptedPayload: { ciphertext: 'u2-cipher', iv: 'u2-iv', authTag: 'u2-tag' },
      nowIso: '2026-11-01T00:00:00.000Z',
    });

    expect(await driver.getUserCredential('user-1', 'kinvo')).toBeNull();
    expect(await driver.getUserCredential('user-2', 'fiainvest')).toMatchObject({
      userId: 'user-2',
      encryptedPayload: { ciphertext: 'u2-cipher' },
    });

    await expect(
      driver.upsertUserCredential({
        userId: 'missing-user',
        pluginSlug: 'fiainvest',
        encryptedPayload: { ciphertext: 'c', iv: 'i', authTag: 't' },
        nowIso: '2026-11-01T00:00:00.000Z',
      }),
    ).rejects.toThrow();

    await expect(
      driver.upsertUserCredential({
        userId: 'user-1',
        pluginSlug: '../bad-slug',
        encryptedPayload: { ciphertext: 'c', iv: 'i', authTag: 't' },
        nowIso: '2026-11-01T00:00:00.000Z',
      }),
    ).rejects.toThrow();

    expect(await driver.deleteUserCredential('user-1', 'fiainvest')).toBe(true);
    expect(await driver.deleteUserCredential('user-1', 'fiainvest')).toBe(false);
    expect(await driver.getUserCredential('user-2', 'fiainvest')).not.toBeNull();
  });

  it('round-trips AES-256-GCM sealed credentials without plaintext at rest', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'mcphub-vault-'));
    const dbPath = join(tempDir, 'vault.sqlite');
    const driver = createSqliteStorageDriver({ filename: dbPath });

    try {
      await driver.migrate();
      await driver.upsertUser({
        id: 'user-vault',
        email: 'vault@example.com',
        nowIso: '2026-11-24T00:00:00.000Z',
      });

      const cipher = await createAesGcmCipher({ masterKey: TEST_MASTER_KEY_HEX });
      const secretCreds = { accessToken: 'synthetic-jwt-999', refreshToken: 'synthetic-ref-888' };
      const sealed = await cipher.encryptJson(secretCreds, { aad: 'user-vault:fiainvest' });

      await driver.upsertUserCredential({
        userId: 'user-vault',
        pluginSlug: 'fiainvest',
        encryptedPayload: sealed,
        nowIso: '2026-11-24T00:00:00.000Z',
      });

      const loaded = await driver.getUserCredential('user-vault', 'fiainvest');
      expect(loaded).not.toBeNull();
      expect(
        await cipher.decryptJson(loaded!.encryptedPayload, { aad: 'user-vault:fiainvest' }),
      ).toEqual(secretCreds);

      await driver.close();
      const inspector = new DatabaseSync(dbPath);
      try {
        const raw = inspector
          .prepare('SELECT ciphertext FROM user_credentials WHERE user_id = ?')
          .get('user-vault') as { ciphertext: string };
        expect(raw.ciphertext).not.toContain('synthetic-jwt-999');
        expect(raw.ciphertext).not.toContain('synthetic-ref-888');
      } finally {
        inspector.close();
      }
    } finally {
      await driver.close();
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});

describe('SqliteStorageDriver OAuth clients, auth codes, tokens, and web sessions', () => {
  it('upserts and retrieves OAuth clients across cimd, dcr, and static kinds', async () => {
    const driver = await createMemoryDriver();

    const fullClient = await driver.upsertOAuthClient({
      clientId: 'https://claude.ai/oauth/client-metadata.json',
      kind: 'cimd',
      clientName: 'Claude Web',
      redirectUris: ['https://claude.ai/api/mcp/auth_callback'],
      scope: 'portfolio:read',
      tokenEndpointAuthMethod: 'none',
      expiresAt: '2026-11-24T12:00:00.000Z',
      nowIso: '2026-11-24T11:00:00.000Z',
    });

    expect(fullClient).toEqual<OAuthClientRecord>({
      clientId: 'https://claude.ai/oauth/client-metadata.json',
      kind: 'cimd',
      clientName: 'Claude Web',
      redirectUris: ['https://claude.ai/api/mcp/auth_callback'],
      scope: 'portfolio:read',
      tokenEndpointAuthMethod: 'none',
      expiresAt: '2026-11-24T12:00:00.000Z',
      createdAt: '2026-11-24T11:00:00.000Z',
      updatedAt: '2026-11-24T11:00:00.000Z',
    });

    const refreshedMinimal = await driver.upsertOAuthClient({
      clientId: 'https://claude.ai/oauth/client-metadata.json',
      kind: 'dcr',
      redirectUris: ['https://vscode.dev/redirect', 'http://127.0.0.1:33418/cb'],
      nowIso: '2026-11-24T11:30:00.000Z',
    });

    expect(refreshedMinimal).toEqual<OAuthClientRecord>({
      clientId: 'https://claude.ai/oauth/client-metadata.json',
      kind: 'dcr',
      redirectUris: ['https://vscode.dev/redirect', 'http://127.0.0.1:33418/cb'],
      createdAt: '2026-11-24T11:00:00.000Z',
      updatedAt: '2026-11-24T11:30:00.000Z',
    });
    expect('clientName' in refreshedMinimal).toBe(false);
    expect('scope' in refreshedMinimal).toBe(false);
    expect('tokenEndpointAuthMethod' in refreshedMinimal).toBe(false);
    expect('expiresAt' in refreshedMinimal).toBe(false);

    expect(await driver.getOAuthClient('https://claude.ai/oauth/client-metadata.json')).toEqual(
      refreshedMinimal,
    );
    expect(await driver.getOAuthClient('missing-client')).toBeNull();
  });

  it('saves and atomically consumes PKCE S256 auth codes exactly once before expiry', async () => {
    const driver = await createMemoryDriver();
    await driver.upsertUser({
      id: 'user-1',
      email: 'u1@example.com',
      nowIso: '2026-11-24T00:00:00.000Z',
    });

    const validCode = {
      codeHash: 'hash-valid',
      clientId: 'chatgpt',
      userId: 'user-1',
      pluginSlug: 'fiainvest',
      redirectUri: 'https://chatgpt.com/aip/g-123/oauth/callback',
      codeChallenge: 's256-challenge',
      codeChallengeMethod: 'S256' as const,
      scope: 'portfolio:read',
      expiresAt: '2026-11-24T01:05:00.000Z',
      createdAt: '2026-11-24T01:00:00.000Z',
    };

    await driver.saveAuthCode(validCode);
    await expect(driver.saveAuthCode(validCode)).rejects.toThrow();
    await expect(
      driver.saveAuthCode({ ...validCode, codeHash: 'hash-bad-user', userId: 'missing' }),
    ).rejects.toThrow();
    await expect(
      driver.saveAuthCode({ ...validCode, codeHash: 'hash-bad-slug', pluginSlug: 'INVALID' }),
    ).rejects.toThrow();

    const consumed = await driver.consumeAuthCode('hash-valid', '2026-11-24T01:01:00.000Z');
    expect(consumed).toEqual<OAuthAuthCodeRecord>({
      ...validCode,
      usedAt: '2026-11-24T01:01:00.000Z',
    });

    expect(await driver.consumeAuthCode('hash-valid', '2026-11-24T01:02:00.000Z')).toBeNull();
    expect(await driver.consumeAuthCode('missing-code', '2026-11-24T01:02:00.000Z')).toBeNull();

    await driver.saveAuthCode({
      ...validCode,
      codeHash: 'hash-boundary',
      expiresAt: '2026-11-24T01:10:00.000Z',
    });
    expect(await driver.consumeAuthCode('hash-boundary', '2026-11-24T01:10:00.000Z')).toBeNull();
    expect(await driver.consumeAuthCode('hash-boundary', '2026-11-24T01:11:00.000Z')).toBeNull();
  });

  it('issues tokens with atomic prior-token revocation, rollback on conflict, lookup, and manual revoke', async () => {
    const driver = await createMemoryDriver();
    await driver.upsertUser({
      id: 'user-1',
      email: 'u1@example.com',
      nowIso: '2026-11-24T00:00:00.000Z',
    });
    await driver.upsertUser({
      id: 'user-2',
      email: 'u2@example.com',
      nowIso: '2026-11-24T00:00:00.000Z',
    });

    const token1 = await driver.issueAccessToken({
      tokenHash: 'tok-u1-c1-v1',
      userId: 'user-1',
      clientId: 'client-1',
      pluginSlug: 'fiainvest',
      scope: 'portfolio:read',
      expiresAt: '2026-11-25T00:00:00.000Z',
      createdAt: '2026-11-24T10:00:00.000Z',
    });
    expect(token1).toEqual<OAuthTokenRecord>({
      tokenHash: 'tok-u1-c1-v1',
      userId: 'user-1',
      clientId: 'client-1',
      pluginSlug: 'fiainvest',
      scope: 'portfolio:read',
      expiresAt: '2026-11-25T00:00:00.000Z',
      createdAt: '2026-11-24T10:00:00.000Z',
    });
    expect('revokedAt' in token1).toBe(false);

    const otherClientToken = await driver.issueAccessToken({
      tokenHash: 'tok-u1-c2-v1',
      userId: 'user-1',
      clientId: 'client-2',
      pluginSlug: 'fiainvest',
      scope: 'portfolio:read',
      expiresAt: '2026-11-25T00:00:00.000Z',
      createdAt: '2026-11-24T10:05:00.000Z',
    });
    const otherUserToken = await driver.issueAccessToken({
      tokenHash: 'tok-u2-c1-v1',
      userId: 'user-2',
      clientId: 'client-1',
      pluginSlug: 'fiainvest',
      scope: 'portfolio:read',
      expiresAt: '2026-11-25T00:00:00.000Z',
      createdAt: '2026-11-24T10:05:00.000Z',
    });

    const token2 = await driver.issueAccessToken({
      tokenHash: 'tok-u1-c1-v2',
      userId: 'user-1',
      clientId: 'client-1',
      pluginSlug: 'fiainvest',
      scope: 'portfolio:read',
      expiresAt: '2026-11-25T01:00:00.000Z',
      createdAt: '2026-11-24T11:00:00.000Z',
    });

    expect(
      await driver.getActiveTokenByHash('tok-u1-c1-v1', '2026-11-24T11:01:00.000Z'),
    ).toBeNull();
    expect(await driver.getActiveTokenByHash('tok-u1-c1-v2', '2026-11-24T11:01:00.000Z')).toEqual(
      token2,
    );
    expect(await driver.getActiveTokenByHash('tok-u1-c2-v1', '2026-11-24T11:01:00.000Z')).toEqual(
      otherClientToken,
    );
    expect(await driver.getActiveTokenByHash('tok-u2-c1-v1', '2026-11-24T11:01:00.000Z')).toEqual(
      otherUserToken,
    );

    // Duplicate tokenHash rolls back revocation of token2
    await expect(
      driver.issueAccessToken({
        tokenHash: 'tok-u2-c1-v1',
        userId: 'user-1',
        clientId: 'client-1',
        pluginSlug: 'fiainvest',
        scope: 'portfolio:read',
        expiresAt: '2026-11-25T02:00:00.000Z',
        createdAt: '2026-11-24T12:00:00.000Z',
      }),
    ).rejects.toThrow();
    expect(await driver.getActiveTokenByHash('tok-u1-c1-v2', '2026-11-24T12:01:00.000Z')).toEqual(
      token2,
    );

    // Missing userId FK violation
    await expect(
      driver.issueAccessToken({
        tokenHash: 'tok-missing-user',
        userId: 'missing',
        clientId: 'client-1',
        pluginSlug: 'fiainvest',
        scope: 'portfolio:read',
        expiresAt: '2026-11-25T02:00:00.000Z',
        createdAt: '2026-11-24T12:00:00.000Z',
      }),
    ).rejects.toThrow();

    // Expiry boundary & missing token
    expect(
      await driver.getActiveTokenByHash('tok-u1-c1-v2', '2026-11-25T01:00:00.000Z'),
    ).toBeNull();
    expect(await driver.getActiveTokenByHash('nonexistent', '2026-11-24T12:01:00.000Z')).toBeNull();

    // Manual revocation
    expect(await driver.revokeClientTokens('user-1', 'client-1', '2026-11-24T12:30:00.000Z')).toBe(
      1,
    );
    expect(await driver.revokeClientTokens('user-1', 'client-1', '2026-11-24T12:31:00.000Z')).toBe(
      0,
    );
    expect(
      await driver.getActiveTokenByHash('tok-u1-c1-v2', '2026-11-24T12:31:00.000Z'),
    ).toBeNull();
  });

  it('creates, fetches active, expires, and deletes web sessions', async () => {
    const driver = await createMemoryDriver();
    await driver.upsertUser({
      id: 'user-1',
      email: 'u1@example.com',
      nowIso: '2026-11-24T00:00:00.000Z',
    });

    const session: WebSessionRecord = {
      cookieHash: 'cookie-hash-1',
      userId: 'user-1',
      expiresAt: '2026-12-24T00:00:00.000Z',
      createdAt: '2026-11-24T00:00:00.000Z',
    };

    expect(await driver.createWebSession(session)).toEqual(session);
    await expect(driver.createWebSession(session)).rejects.toThrow();
    await expect(
      driver.createWebSession({ ...session, cookieHash: 'cookie-hash-2', userId: 'missing' }),
    ).rejects.toThrow();

    expect(
      await driver.getActiveWebSessionByHash('cookie-hash-1', '2026-12-23T23:59:59.999Z'),
    ).toEqual(session);
    expect(
      await driver.getActiveWebSessionByHash('cookie-hash-1', '2026-12-24T00:00:00.000Z'),
    ).toBeNull();
    expect(
      await driver.getActiveWebSessionByHash('missing-cookie', '2026-11-25T00:00:00.000Z'),
    ).toBeNull();

    expect(await driver.deleteWebSessionByHash('cookie-hash-1')).toBe(true);
    expect(await driver.deleteWebSessionByHash('cookie-hash-1')).toBe(false);
    expect(
      await driver.getActiveWebSessionByHash('cookie-hash-1', '2026-11-25T00:00:00.000Z'),
    ).toBeNull();
  });
});
