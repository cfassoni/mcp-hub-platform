import { isValidPluginSlug } from '@mcphub/core';
import type { Context, Hono } from 'hono';
import { parseAppBaseUrl, resolvePublicUrl } from '../config.js';

const DISCOVERY_CACHE_CONTROL = 'public, max-age=300';

/** RFC 8414 Authorization Server Metadata document returned at `/.well-known/oauth-authorization-server`. */
export interface AuthorizationServerMetadata {
  readonly issuer: string;
  readonly authorization_endpoint: string;
  readonly token_endpoint: string;
  readonly registration_endpoint: string;
  readonly response_types_supported: readonly ['code'];
  readonly grant_types_supported: readonly ['authorization_code'];
  readonly code_challenge_methods_supported: readonly ['S256'];
  readonly token_endpoint_auth_methods_supported: readonly [
    'none',
    'client_secret_post',
    'client_secret_basic',
  ];
  readonly client_id_metadata_document_supported: true;
  readonly scopes_supported?: readonly string[];
}

/** RFC 9728 Protected Resource Metadata document returned at `/.well-known/oauth-protected-resource`. */
export interface ProtectedResourceMetadata {
  readonly resource: string;
  readonly authorization_servers: readonly [string];
  readonly bearer_methods_supported: readonly ['header'];
  readonly scopes_supported?: readonly string[];
}

/** Shared options for building RFC 8414 / RFC 9728 discovery metadata documents. */
export interface DiscoveryMetadataOptions {
  readonly scopesSupported?: readonly string[];
}

/** Options for building RFC 9728 Protected Resource Metadata for a specific resource path. */
export interface ProtectedResourceMetadataOptions extends DiscoveryMetadataOptions {
  readonly resourcePath?: string;
}

/** Options for registering OAuth 2.1 discovery endpoints on a Hono gateway app. */
export interface DiscoveryRoutesOptions extends DiscoveryMetadataOptions {
  readonly appBaseUrl?: string | undefined;
}

/** Builds RFC 8414 Authorization Server Metadata anchored strictly to `APP_BASE_URL`. */
export function buildAuthorizationServerMetadata(
  appBaseUrl: string,
  options?: DiscoveryMetadataOptions,
): AuthorizationServerMetadata {
  const origin = parseAppBaseUrl(appBaseUrl);
  const scopes = options?.scopesSupported;

  return {
    issuer: origin,
    authorization_endpoint: resolvePublicUrl(origin, '/oauth/authorize'),
    token_endpoint: resolvePublicUrl(origin, '/oauth/token'),
    registration_endpoint: resolvePublicUrl(origin, '/oauth/register'),
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
    client_id_metadata_document_supported: true,
    ...(scopes !== undefined && scopes.length > 0 ? { scopes_supported: [...scopes] } : {}),
  };
}

/** Builds RFC 9728 Protected Resource Metadata anchored strictly to `APP_BASE_URL`. */
export function buildProtectedResourceMetadata(
  appBaseUrl: string,
  options?: ProtectedResourceMetadataOptions,
): ProtectedResourceMetadata {
  const origin = parseAppBaseUrl(appBaseUrl);
  const resource =
    options?.resourcePath !== undefined ? resolvePublicUrl(origin, options.resourcePath) : origin;
  const scopes = options?.scopesSupported;

  return {
    resource,
    authorization_servers: [origin],
    bearer_methods_supported: ['header'],
    ...(scopes !== undefined && scopes.length > 0 ? { scopes_supported: [...scopes] } : {}),
  };
}

function respondDiscoveryJson(
  c: Context,
  normalizedBaseUrl: string | undefined,
  buildMetadata: (origin: string) => AuthorizationServerMetadata | ProtectedResourceMetadata,
): Response {
  if (normalizedBaseUrl === undefined) {
    return c.json(
      {
        error: 'server_misconfigured',
        error_description: 'APP_BASE_URL is not configured',
      },
      503,
    );
  }

  c.header('cache-control', DISCOVERY_CACHE_CONTROL);
  return c.json(buildMetadata(normalizedBaseUrl));
}

/**
 * Registers ratified RFC 8414 and RFC 9728 discovery metadata endpoints on a Hono app,
 * failing closed with `503` when `APP_BASE_URL` is unconfigured.
 */
export function registerDiscoveryRoutes(app: Hono, options: DiscoveryRoutesOptions): void {
  const normalizedBaseUrl =
    options.appBaseUrl !== undefined ? parseAppBaseUrl(options.appBaseUrl) : undefined;
  const metadataOptions: DiscoveryMetadataOptions = {
    ...(options.scopesSupported !== undefined ? { scopesSupported: options.scopesSupported } : {}),
  };

  app.get('/.well-known/oauth-authorization-server', (c) =>
    respondDiscoveryJson(c, normalizedBaseUrl, (origin) =>
      buildAuthorizationServerMetadata(origin, metadataOptions),
    ),
  );

  app.get('/.well-known/oauth-protected-resource', (c) =>
    respondDiscoveryJson(c, normalizedBaseUrl, (origin) =>
      buildProtectedResourceMetadata(origin, metadataOptions),
    ),
  );

  app.get('/.well-known/oauth-protected-resource/:slug/mcp', (c) => {
    const slug = c.req.param('slug');
    if (!isValidPluginSlug(slug)) {
      return c.notFound();
    }

    return respondDiscoveryJson(c, normalizedBaseUrl, (origin) =>
      buildProtectedResourceMetadata(origin, {
        ...metadataOptions,
        resourcePath: `/${slug}/mcp`,
      }),
    );
  });
}
