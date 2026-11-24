import { createHealthPayload, type IStorageDriver } from '@mcphub/core';
import { Hono } from 'hono';
import type { GatewayConfig } from './config.js';

/** Optional dependencies injected into the isomorphic Hono gateway application. */
export interface GatewayAppOptions {
  readonly config?: GatewayConfig;
  readonly storage?: IStorageDriver;
}

/** Creates the isomorphic Hono gateway application. */
export function createApp(options?: GatewayAppOptions): Hono {
  void options;
  const app = new Hono();

  app.get('/health', (c) => c.json(createHealthPayload()));

  return app;
}

export default createApp();

export {
  DEFAULT_HOST,
  DEFAULT_PORT,
  DEFAULT_USER_INACTIVITY_TTL_DAYS,
  MCPHUB_SESSION_COOKIE_NAME,
  formatSessionCookie,
  parseGatewayConfig,
  resolvePublicUrl,
} from './config.js';
export type { GatewayConfig, GatewayEnvInput } from './config.js';
