import { describe, expect, it } from 'vitest';
import { createApp } from '../src/index.js';

describe('gateway health route', () => {
  it('returns 200 OK JSON on GET /health', async () => {
    const app = createApp();
    const response = await app.request('/health');

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      status: 'ok',
      service: 'mcp-hub-platform',
    });
  });

  it('returns 404 on unknown routes', async () => {
    const app = createApp();
    const response = await app.request('/nonexistent');

    expect(response.status).toBe(404);
  });
});
