import { parseMasterKey } from '@mcphub/core';

/** Canonical host-only session cookie name for portal and OAuth 2.1 SSO flows. */
export const MCPHUB_SESSION_COOKIE_NAME = 'mcphub_session' as const;

/** Default HTTP bind host inside rootless OCI containers. */
export const DEFAULT_HOST = '0.0.0.0' as const;

/** Default HTTP listen port behind cloudflared local ingress tunnels. */
export const DEFAULT_PORT = 8787 as const;

/** Default user inactivity purge threshold in days (`core-invariants.md §3`). */
export const DEFAULT_USER_INACTIVITY_TTL_DAYS = 60 as const;

/** Runtime environment key-value input map accepted by {@link parseGatewayConfig}. */
export type GatewayEnvInput = Readonly<Record<string, string | undefined>>;

/** Validated runtime configuration for an isolated gateway instance. */
export interface GatewayConfig {
  readonly host: string;
  readonly port: number;
  readonly appBaseUrl: string;
  readonly sqlitePath: string;
  readonly encryptionMasterKey: string;
  readonly userInactivityTtlDays: number;
}

function parseIntegerRange(
  raw: string | undefined,
  defaultValue: number,
  minValue: number,
  maxValue: number,
  label: string,
): number {
  if (raw === undefined) {
    return defaultValue;
  }

  const trimmed = raw.trim();
  if (!/^\d+$/.test(trimmed)) {
    throw new RangeError(`${label} must be an integer between ${minValue} and ${maxValue}`);
  }

  const parsed = Number(trimmed);
  if (!Number.isSafeInteger(parsed) || parsed < minValue || parsed > maxValue) {
    throw new RangeError(`${label} must be an integer between ${minValue} and ${maxValue}`);
  }

  return parsed;
}

/** Validates and normalizes `APP_BASE_URL` to a root HTTPS origin string without trailing slash. */
export function parseAppBaseUrl(raw: string | undefined): string {
  const trimmed = raw?.trim() ?? '';
  if (trimmed.length === 0) {
    throw new RangeError('APP_BASE_URL is required and must be an HTTPS origin');
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new RangeError('APP_BASE_URL must be a valid HTTPS origin URL');
  }

  if (parsed.protocol !== 'https:') {
    throw new RangeError('APP_BASE_URL must use the https: protocol');
  }

  if (parsed.username.length > 0 || parsed.password.length > 0) {
    throw new RangeError('APP_BASE_URL must not contain embedded credentials');
  }

  if (parsed.pathname !== '/' || parsed.search.length > 0 || parsed.hash.length > 0) {
    throw new RangeError('APP_BASE_URL must be a root origin without path, query, or fragment');
  }

  return parsed.origin;
}

/**
 * Validates environment settings for `@mcphub/gateway`, enforcing `APP_BASE_URL`
 * as an authoritative HTTPS origin and validating `ENCRYPTION_MASTER_KEY` without echoing secrets.
 */
export function parseGatewayConfig(env: GatewayEnvInput): GatewayConfig {
  const host = env.HOST === undefined ? DEFAULT_HOST : env.HOST.trim();
  if (host.length === 0 || /\s/.test(host)) {
    throw new RangeError('HOST must be a non-empty hostname or IP without whitespace');
  }

  const port = parseIntegerRange(env.PORT, DEFAULT_PORT, 0, 65535, 'PORT');
  const appBaseUrl = parseAppBaseUrl(env.APP_BASE_URL);

  const sqlitePath = env.SQLITE_PATH?.trim() ?? '';
  if (sqlitePath.length === 0) {
    throw new RangeError('SQLITE_PATH is required and must be a file path or :memory:');
  }

  const encryptionMasterKey = env.ENCRYPTION_MASTER_KEY;
  if (encryptionMasterKey === undefined || encryptionMasterKey.length === 0) {
    throw new RangeError('ENCRYPTION_MASTER_KEY is required');
  }
  parseMasterKey(encryptionMasterKey);

  const userInactivityTtlDays = parseIntegerRange(
    env.USER_INACTIVITY_TTL_DAYS,
    DEFAULT_USER_INACTIVITY_TTL_DAYS,
    1,
    Number.MAX_SAFE_INTEGER,
    'USER_INACTIVITY_TTL_DAYS',
  );

  return {
    host,
    port,
    appBaseUrl,
    sqlitePath,
    encryptionMasterKey,
    userInactivityTtlDays,
  };
}

/**
 * Resolves a relative request path against the configured authoritative `APP_BASE_URL`
 * origin, rejecting protocol-relative or cross-origin escapes.
 */
export function resolvePublicUrl(appBaseUrl: string, pathname: string): string {
  const baseOrigin = parseAppBaseUrl(appBaseUrl);

  if (
    !pathname.startsWith('/') ||
    pathname.startsWith('//') ||
    pathname.includes('\\') ||
    // eslint-disable-next-line no-control-regex
    /[\u0000-\u001f\u007f]/.test(pathname)
  ) {
    throw new RangeError('Public URL pathname must be a relative path starting with a single /');
  }

  return new URL(pathname, baseOrigin).toString();
}

/**
 * Formats the host-only `mcphub_session` cookie (explicitly omitting `Domain` to isolate
 * staging and friendly-user production subdomains).
 */
export function formatSessionCookie(value: string, maxAgeSeconds: number): string {
  // eslint-disable-next-line no-control-regex
  if (value.length === 0 || /[\s;,\u0000-\u001f\u007f]/.test(value)) {
    throw new RangeError('Session cookie value must be a non-empty token without delimiters');
  }

  if (!Number.isSafeInteger(maxAgeSeconds) || maxAgeSeconds < 0) {
    throw new RangeError('Session cookie Max-Age must be a non-negative safe integer');
  }

  return `${MCPHUB_SESSION_COOKIE_NAME}=${value}; Path=/; Max-Age=${maxAgeSeconds}; HttpOnly; Secure; SameSite=Lax`;
}
