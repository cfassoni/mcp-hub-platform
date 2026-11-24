/// <reference types="node" />
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_HOST,
  DEFAULT_PORT,
  DEFAULT_USER_INACTIVITY_TTL_DAYS,
  formatSessionCookie,
  MCPHUB_SESSION_COOKIE_NAME,
  parseGatewayConfig,
  resolvePublicUrl,
} from '../src/config.js';
import * as gatewayBarrel from '../src/index.js';

const SYNTHETIC_KEY_HEX = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

describe('gateway Web-Standards configuration & cookie helpers', () => {
  it('re-exports config helpers and constants from the gateway barrel', () => {
    expect(gatewayBarrel.parseGatewayConfig).toBe(parseGatewayConfig);
    expect(gatewayBarrel.resolvePublicUrl).toBe(resolvePublicUrl);
    expect(gatewayBarrel.formatSessionCookie).toBe(formatSessionCookie);
    expect(gatewayBarrel.MCPHUB_SESSION_COOKIE_NAME).toBe('mcphub_session');
    expect(DEFAULT_HOST).toBe('0.0.0.0');
    expect(DEFAULT_PORT).toBe(8787);
    expect(DEFAULT_USER_INACTIVITY_TTL_DAYS).toBe(60);
  });

  it('parses valid config with defaults and normalizes trailing root slash on APP_BASE_URL', () => {
    const config = parseGatewayConfig({
      APP_BASE_URL: 'https://staging-mcp.example.com/',
      SQLITE_PATH: '/data/mcphub.sqlite',
      ENCRYPTION_MASTER_KEY: SYNTHETIC_KEY_HEX,
    });

    expect(config).toEqual({
      host: '0.0.0.0',
      port: 8787,
      appBaseUrl: 'https://staging-mcp.example.com',
      sqlitePath: '/data/mcphub.sqlite',
      encryptionMasterKey: SYNTHETIC_KEY_HEX,
      userInactivityTtlDays: 60,
    });
  });

  it('parses explicit HOST, PORT (including 0), and USER_INACTIVITY_TTL_DAYS overrides', () => {
    const config = parseGatewayConfig({
      HOST: '127.0.0.1',
      PORT: '0',
      APP_BASE_URL: 'https://mcp.example.com:8443',
      SQLITE_PATH: ':memory:',
      ENCRYPTION_MASTER_KEY: SYNTHETIC_KEY_HEX,
      USER_INACTIVITY_TTL_DAYS: '30',
    });

    expect(config).toEqual({
      host: '127.0.0.1',
      port: 0,
      appBaseUrl: 'https://mcp.example.com:8443',
      sqlitePath: ':memory:',
      encryptionMasterKey: SYNTHETIC_KEY_HEX,
      userInactivityTtlDays: 30,
    });
  });

  it.each([
    ['missing APP_BASE_URL', {}],
    ['empty APP_BASE_URL', { APP_BASE_URL: '   ' }],
    ['non-HTTPS APP_BASE_URL', { APP_BASE_URL: 'http://localhost:8787' }],
    ['malformed APP_BASE_URL', { APP_BASE_URL: 'not-a-url' }],
    ['embedded credentials', { APP_BASE_URL: 'https://user:pass@example.com' }],
    ['non-root pathname', { APP_BASE_URL: 'https://example.com/prefix' }],
    ['query string', { APP_BASE_URL: 'https://example.com/?x=1' }],
    ['hash fragment', { APP_BASE_URL: 'https://example.com/#top' }],
  ])('rejects invalid APP_BASE_URL (%s)', (_label, override) => {
    expect(() =>
      parseGatewayConfig({
        SQLITE_PATH: ':memory:',
        ENCRYPTION_MASTER_KEY: SYNTHETIC_KEY_HEX,
        ...override,
      }),
    ).toThrow();
  });

  it.each([
    ['empty HOST', { HOST: '  ' }],
    ['whitespace inside HOST', { HOST: '127.0.0.1 evil' }],
    ['negative PORT', { PORT: '-1' }],
    ['PORT > 65535', { PORT: '65536' }],
    ['fractional PORT', { PORT: '80.5' }],
    ['non-numeric PORT', { PORT: 'abc' }],
    ['missing SQLITE_PATH', { SQLITE_PATH: undefined }],
    ['empty SQLITE_PATH', { SQLITE_PATH: '   ' }],
    ['zero USER_INACTIVITY_TTL_DAYS', { USER_INACTIVITY_TTL_DAYS: '0' }],
    ['negative USER_INACTIVITY_TTL_DAYS', { USER_INACTIVITY_TTL_DAYS: '-5' }],
    ['non-numeric USER_INACTIVITY_TTL_DAYS', { USER_INACTIVITY_TTL_DAYS: 'sixty' }],
  ])('rejects invalid non-secret env settings (%s)', (_label, override) => {
    expect(() =>
      parseGatewayConfig({
        APP_BASE_URL: 'https://mcp.example.com',
        SQLITE_PATH: ':memory:',
        ENCRYPTION_MASTER_KEY: SYNTHETIC_KEY_HEX,
        ...override,
      }),
    ).toThrow();
  });

  it('rejects missing, weak, or all-zero ENCRYPTION_MASTER_KEY without echoing it', () => {
    expect(() =>
      parseGatewayConfig({
        APP_BASE_URL: 'https://mcp.example.com',
        SQLITE_PATH: ':memory:',
      }),
    ).toThrow();

    const weakSecrets = [
      'too-weak-secret-passphrase-for-aes-gcm',
      '0000000000000000000000000000000000000000000000000000000000000000',
    ];

    for (const secret of weakSecrets) {
      let caught: unknown;
      try {
        parseGatewayConfig({
          APP_BASE_URL: 'https://mcp.example.com',
          SQLITE_PATH: ':memory:',
          ENCRYPTION_MASTER_KEY: secret,
        });
      } catch (error) {
        caught = error;
      }

      expect(caught).toBeInstanceOf(Error);
      expect((caught as Error).message).not.toContain(secret);
    }
  });

  it('resolves public URLs against authoritative APP_BASE_URL and rejects origin escapes', () => {
    expect(resolvePublicUrl('https://staging.example.com/', '/fiainvest/mcp?x=1')).toBe(
      'https://staging.example.com/fiainvest/mcp?x=1',
    );
    expect(
      resolvePublicUrl('https://prod.example.com', '/.well-known/oauth-protected-resource'),
    ).toBe('https://prod.example.com/.well-known/oauth-protected-resource');

    expect(() => resolvePublicUrl('https://prod.example.com', '//evil.com/mcp')).toThrow();
    expect(() => resolvePublicUrl('https://prod.example.com', 'https://evil.com/mcp')).toThrow();
    expect(() => resolvePublicUrl('https://prod.example.com', '/bad\\path')).toThrow();
    expect(() => resolvePublicUrl('https://prod.example.com', '/bad\npath')).toThrow();
  });

  it('formats host-only mcphub_session cookie without Domain attribute for staging/prod isolation', () => {
    const cookie = formatSessionCookie('session_digest_token_123', 2592000);
    expect(cookie).toBe(
      `${MCPHUB_SESSION_COOKIE_NAME}=session_digest_token_123; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax`,
    );
    expect(cookie).not.toMatch(/\bDomain=/i);

    expect(formatSessionCookie('expired_token', 0)).toBe(
      `${MCPHUB_SESSION_COOKIE_NAME}=expired_token; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
    );

    expect(() => formatSessionCookie('', 60)).toThrow();
    expect(() => formatSessionCookie('bad;value', 60)).toThrow();
    expect(() => formatSessionCookie('bad\nvalue', 60)).toThrow();
    expect(() => formatSessionCookie('valid_value', -1)).toThrow();
    expect(() => formatSessionCookie('valid_value', 1.5)).toThrow();
  });

  it('keeps isomorphic gateway index.ts and config.ts free of node:*, process.env, and Buffer', () => {
    const indexPath = fileURLToPath(new URL('../src/index.ts', import.meta.url));
    const configPath = fileURLToPath(new URL('../src/config.ts', import.meta.url));

    for (const filePath of [indexPath, configPath]) {
      const source = readFileSync(filePath, 'utf8');
      expect(source).not.toMatch(/['"]node:[^'"]+['"]/);
      expect(source).not.toMatch(/\bprocess\.env\b/);
      expect(source).not.toMatch(/\bBuffer\b/);
    }
  });
});
