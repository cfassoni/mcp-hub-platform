import { createHealthPayload, type IStorageDriver } from '@mcphub/core';
import { Hono } from 'hono';
import type { GatewayConfig } from './config.js';
import { registerDiscoveryRoutes } from './oauth/discovery.js';

/** Optional dependencies injected into the isomorphic Hono gateway application. */
export interface GatewayAppOptions {
  readonly config?: GatewayConfig;
  readonly storage?: IStorageDriver;
  readonly appBaseUrl?: string;
  readonly scopesSupported?: readonly string[];
}

/** Creates the isomorphic Hono gateway application. */
export function createApp(options?: GatewayAppOptions): Hono {
  const app = new Hono();

  app.get('/health', (c) => c.json(createHealthPayload()));

  registerDiscoveryRoutes(app, {
    appBaseUrl: options?.appBaseUrl ?? options?.config?.appBaseUrl,
    ...(options?.scopesSupported !== undefined ? { scopesSupported: options.scopesSupported } : {}),
  });

  return app;
}

export default createApp();

export {
  DEFAULT_HOST,
  DEFAULT_PORT,
  DEFAULT_USER_INACTIVITY_TTL_DAYS,
  MCPHUB_SESSION_COOKIE_NAME,
  formatSessionCookie,
  parseAppBaseUrl,
  parseGatewayConfig,
  resolvePublicUrl,
} from './config.js';
export type { GatewayConfig, GatewayEnvInput } from './config.js';

export {
  buildAuthorizationServerMetadata,
  buildProtectedResourceMetadata,
  registerDiscoveryRoutes,
} from './oauth/discovery.js';
export type {
  AuthorizationServerMetadata,
  DiscoveryMetadataOptions,
  DiscoveryRoutesOptions,
  ProtectedResourceMetadata,
  ProtectedResourceMetadataOptions,
} from './oauth/discovery.js';
