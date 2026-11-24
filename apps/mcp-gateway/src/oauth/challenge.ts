import { isValidPluginSlug } from '@mcphub/core';
import type { Hono } from 'hono';
import { parseAppBaseUrl, resolvePublicUrl } from '../config.js';

const DEFAULT_PROTECTED_RESOURCE_METADATA_PATH = '/.well-known/oauth-protected-resource';
const BEARER_HEADER_REGEX = /^Bearer\s+([A-Za-z0-9._~+/=-]+)$/i;
// eslint-disable-next-line no-control-regex
const UNSAFE_SCOPE_TOKEN_REGEX = /[\s"\\\u0000-\u001f\u007f]/;
// eslint-disable-next-line no-control-regex
const UNSAFE_QUOTED_TEXT_REGEX = /["\\\u0000-\u001f\u007f]/;

/** RFC 6750 §3.1 Bearer error codes surfaced in `WWW-Authenticate` challenges. */
export type WwwAuthenticateErrorCode = 'invalid_token' | 'insufficient_scope' | 'invalid_request';

/** Options for constructing a canonical RFC 9728 / RFC 6750 `WWW-Authenticate` challenge header. */
export interface WwwAuthenticateChallengeOptions {
  readonly resourceMetadataPath?: string;
  readonly scopes?: readonly string[];
  readonly error?: WwwAuthenticateErrorCode;
  readonly errorDescription?: string;
}

/** Options for registering the `/:slug/mcp` canonical `401` challenge middleware. */
export interface McpChallengeMiddlewareOptions {
  readonly appBaseUrl?: string | undefined;
  readonly scopesSupported?: readonly string[];
}

/**
 * Formats an RFC 9728 §5.1 / RFC 6750 §3 `WWW-Authenticate` Bearer challenge header
 * anchored strictly to `APP_BASE_URL` and validated against header injection.
 */
export function buildWwwAuthenticateHeader(
  appBaseUrl: string,
  options?: WwwAuthenticateChallengeOptions,
): string {
  const resourceMetadataUrl = resolvePublicUrl(
    appBaseUrl,
    options?.resourceMetadataPath ?? DEFAULT_PROTECTED_RESOURCE_METADATA_PATH,
  );
  const parts: string[] = [`resource_metadata="${resourceMetadataUrl}"`];

  if (options?.scopes !== undefined && options.scopes.length > 0) {
    for (const scope of options.scopes) {
      if (scope.length === 0 || UNSAFE_SCOPE_TOKEN_REGEX.test(scope)) {
        throw new RangeError('WWW-Authenticate scope tokens must not contain delimiters or spaces');
      }
    }
    parts.push(`scope="${options.scopes.join(' ')}"`);
  }

  if (options?.error !== undefined) {
    parts.push(`error="${options.error}"`);
  }

  if (options?.errorDescription !== undefined) {
    if (
      options.errorDescription.length === 0 ||
      UNSAFE_QUOTED_TEXT_REGEX.test(options.errorDescription)
    ) {
      throw new RangeError(
        'WWW-Authenticate error_description must be non-empty without quotes or control chars',
      );
    }
    parts.push(`error_description="${options.errorDescription}"`);
  }

  return `Bearer ${parts.join(', ')}`;
}

/**
 * Extracts a syntactically valid RFC 6750 Bearer token from an `Authorization` header,
 * returning `null` when absent, non-Bearer, or malformed.
 */
export function extractBearerToken(authorizationHeader: string | undefined): string | null {
  if (authorizationHeader === undefined) {
    return null;
  }

  const match = BEARER_HEADER_REGEX.exec(authorizationHeader.trim());
  return match?.[1] ?? null;
}

/**
 * Builds an unauthenticated `HTTP 401 Unauthorized` response carrying the canonical
 * `WWW-Authenticate` challenge and `Cache-Control: no-store`.
 */
export function createUnauthorizedResponse(
  appBaseUrl: string,
  options?: WwwAuthenticateChallengeOptions,
): Response {
  const wwwAuthenticate = buildWwwAuthenticateHeader(appBaseUrl, options);

  return new Response(
    JSON.stringify({
      error: options?.error ?? 'unauthorized',
      error_description: options?.errorDescription ?? 'Authentication required',
    }),
    {
      status: 401,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        'www-authenticate': wwwAuthenticate,
      },
    },
  );
}

/**
 * Registers the `/:slug/mcp` canonical `401` challenge middleware on a Hono gateway app,
 * rejecting invalid slugs (`404`), failing closed when `APP_BASE_URL` is missing (`503`),
 * and issuing `WWW-Authenticate` when a Bearer token is absent or malformed (`401`).
 */
export function registerMcpChallengeMiddleware(
  app: Hono,
  options: McpChallengeMiddlewareOptions,
): void {
  const normalizedBaseUrl =
    options.appBaseUrl !== undefined ? parseAppBaseUrl(options.appBaseUrl) : undefined;
  const challengeOptions: WwwAuthenticateChallengeOptions = {
    ...(options.scopesSupported !== undefined ? { scopes: options.scopesSupported } : {}),
  };

  app.use('/:slug/mcp', async (c, next) => {
    const slug = c.req.param('slug');
    if (!isValidPluginSlug(slug)) {
      return c.notFound();
    }

    if (normalizedBaseUrl === undefined) {
      return c.json(
        {
          error: 'server_misconfigured',
          error_description: 'APP_BASE_URL is not configured',
        },
        503,
      );
    }

    const token = extractBearerToken(c.req.header('authorization'));
    if (token === null) {
      return createUnauthorizedResponse(normalizedBaseUrl, challengeOptions);
    }

    await next();
  });
}
