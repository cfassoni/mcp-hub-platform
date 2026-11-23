import { Hono } from 'hono';
import { createHealthPayload } from '@mcphub/core';

/** Creates the isomorphic Hono gateway application. */
export function createApp(): Hono {
  const app = new Hono();

  app.get('/health', (c) => c.json(createHealthPayload()));

  return app;
}

export default createApp();
