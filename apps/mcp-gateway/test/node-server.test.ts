/// <reference types="node" />
import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Hono } from 'hono';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { formatSessionCookie } from '../src/config.js';
import {
  createNodeGatewayServer,
  createNodeRequest,
  runGatewayProcess,
  writeNodeResponse,
  type NodeGatewayServerHandle,
  type SignalTarget,
} from '../src/node-server.js';

const SYNTHETIC_KEY_HEX = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

const activeHandles: NodeGatewayServerHandle[] = [];

afterEach(async () => {
  vi.unstubAllEnvs();
  while (activeHandles.length > 0) {
    const handle = activeHandles.pop();
    if (handle) {
      await handle.stop();
    }
  }
});

describe('Node.js 26 HTTP server adapter for @mcphub/gateway', () => {
  it('serves GET and HEAD /health on ephemeral port with file-backed SQLite and idempotent stop', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'mcphub-gw-'));
    const dbPath = join(tempDir, 'gateway.sqlite');

    try {
      const handle = await createNodeGatewayServer({
        env: {
          HOST: '127.0.0.1',
          PORT: '0',
          APP_BASE_URL: 'https://staging.example.com',
          SQLITE_PATH: dbPath,
          ENCRYPTION_MASTER_KEY: SYNTHETIC_KEY_HEX,
        },
      });
      activeHandles.push(handle);

      expect(handle.port).toBeGreaterThan(0);

      const getRes = await fetch(`http://127.0.0.1:${handle.port}/health`);
      expect(getRes.status).toBe(200);
      await expect(getRes.json()).resolves.toEqual({
        status: 'ok',
        service: 'mcp-hub-platform',
      });

      const headRes = await fetch(`http://127.0.0.1:${handle.port}/health`, { method: 'HEAD' });
      expect(headRes.status).toBe(200);
      expect(await headRes.text()).toBe('');

      await handle.stop();
      await handle.stop();
    } finally {
      while (activeHandles.length > 0) {
        const handle = activeHandles.pop();
        if (handle) {
          await handle.stop();
        }
      }
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('derives Request.url strictly from APP_BASE_URL, forwards POST bodies, and preserves multiple Set-Cookie headers', async () => {
    const handle = await createNodeGatewayServer({
      env: {
        HOST: '127.0.0.1',
        PORT: '0',
        APP_BASE_URL: 'https://prod.example.com',
        SQLITE_PATH: ':memory:',
        ENCRYPTION_MASTER_KEY: SYNTHETIC_KEY_HEX,
      },
      createGatewayApp: () => {
        const app = new Hono();
        app.post('/oauth/echo', async (c) => {
          const payload = (await c.req.json()) as { token: string };
          c.header('set-cookie', formatSessionCookie(payload.token, 3600), { append: true });
          c.header('set-cookie', 'csrf_hint=1; Path=/; Secure; SameSite=Lax', { append: true });
          return c.json({
            observedUrl: c.req.url,
            multiHeaderObserved: c.req.header('x-multi'),
            received: payload,
          });
        });
        return app;
      },
    });
    activeHandles.push(handle);

    const response = await fetch(`http://127.0.0.1:${handle.port}/oauth/echo?client_id=chatgpt`, {
      method: 'POST',
      headers: [
        ['content-type', 'application/json'],
        ['x-forwarded-host', 'evil.attacker'],
        ['x-forwarded-proto', 'http'],
        ['x-multi', 'alpha'],
        ['x-multi', 'beta'],
      ],
      body: JSON.stringify({ token: 'tok_abc_123' }),
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      observedUrl: 'https://prod.example.com/oauth/echo?client_id=chatgpt',
      multiHeaderObserved: 'alpha, beta',
      received: { token: 'tok_abc_123' },
    });

    const setCookies = response.headers.getSetCookie();
    expect(setCookies).toHaveLength(2);
    expect(setCookies[0]).toBe(
      'mcphub_session=tok_abc_123; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Lax',
    );
    expect(setCookies[1]).toBe('csrf_hint=1; Path=/; Secure; SameSite=Lax');
  });

  it('handles unhandled app errors safely with 500 JSON and handles null response bodies', async () => {
    const handle = await createNodeGatewayServer({
      env: {
        HOST: '127.0.0.1',
        PORT: '0',
        APP_BASE_URL: 'https://prod.example.com',
        SQLITE_PATH: ':memory:',
        ENCRYPTION_MASTER_KEY: SYNTHETIC_KEY_HEX,
      },
      createGatewayApp: () =>
        ({
          fetch: async (request: Request): Promise<Response> => {
            if (new URL(request.url).pathname === '/boom') {
              throw new Error('Unhandled adapter boom');
            }
            return new Response(null, { status: 204 });
          },
        }) as unknown as Hono,
    });
    activeHandles.push(handle);

    const boomRes = await fetch(`http://127.0.0.1:${handle.port}/boom`);
    expect(boomRes.status).toBe(500);
    await expect(boomRes.json()).resolves.toEqual({ error: 'Internal Server Error' });

    const emptyRes = await fetch(`http://127.0.0.1:${handle.port}/empty`);
    expect(emptyRes.status).toBe(204);
    expect(await emptyRes.text()).toBe('');
  });

  it('closes storage if server binding fails and exercises createNodeRequest/writeNodeResponse edge cases', async () => {
    const occupied = await createNodeGatewayServer({
      env: {
        HOST: '127.0.0.1',
        PORT: '0',
        APP_BASE_URL: 'https://prod.example.com',
        SQLITE_PATH: ':memory:',
        ENCRYPTION_MASTER_KEY: SYNTHETIC_KEY_HEX,
      },
    });
    activeHandles.push(occupied);

    await expect(
      createNodeGatewayServer({
        env: {
          HOST: '127.0.0.1',
          PORT: String(occupied.port),
          APP_BASE_URL: 'https://prod.example.com',
          SQLITE_PATH: ':memory:',
          ENCRYPTION_MASTER_KEY: SYNTHETIC_KEY_HEX,
        },
      }),
    ).rejects.toThrow();

    const syntheticReq = {
      headers: {
        'x-array': ['one', 'two'],
        'x-omit': undefined,
        host: 'spoofed.internal',
      },
    } as unknown as IncomingMessage;

    const built = createNodeRequest(syntheticReq, 'https://staging.example.com');
    expect(built.method).toBe('GET');
    expect(built.url).toBe('https://staging.example.com/');
    expect(built.headers.get('x-array')).toBe('one, two');
    expect(built.headers.get('x-omit')).toBeNull();

    const mockRes = {
      statusCode: 0,
      headers: new Map<string, string | string[]>(),
      chunks: [] as Uint8Array[],
      ended: false,
      setHeader(name: string, val: string | string[]) {
        this.headers.set(name, val);
      },
      write(chunk: Uint8Array) {
        this.chunks.push(chunk);
        return true;
      },
      end() {
        this.ended = true;
      },
    };

    await writeNodeResponse(
      new Response('hello', { status: 200, headers: { 'content-type': 'text/plain' } }),
      mockRes as unknown as ServerResponse,
      'GET',
    );
    expect(mockRes.statusCode).toBe(200);
    expect(mockRes.ended).toBe(true);
    expect(Buffer.concat(mockRes.chunks).toString('utf8')).toBe('hello');
  });

  it('starts via runGatewayProcess and shuts down gracefully on SIGTERM/SIGINT', async () => {
    const emitter = new EventEmitter();
    const signalTarget: SignalTarget = {
      on: (event, listener) => emitter.on(event, listener),
      off: (event, listener) => emitter.off(event, listener),
    };

    const handle = await runGatewayProcess(
      {
        HOST: '127.0.0.1',
        PORT: '0',
        APP_BASE_URL: 'https://staging.example.com',
        SQLITE_PATH: ':memory:',
        ENCRYPTION_MASTER_KEY: SYNTHETIC_KEY_HEX,
      },
      signalTarget,
    );
    activeHandles.push(handle);

    expect(emitter.listenerCount('SIGINT')).toBe(1);
    expect(emitter.listenerCount('SIGTERM')).toBe(1);

    emitter.emit('SIGTERM');
    await new Promise((resolve) => setTimeout(resolve, 25));

    expect(emitter.listenerCount('SIGINT')).toBe(0);
    expect(emitter.listenerCount('SIGTERM')).toBe(0);
    await expect(handle.storage.getUserById('user-1')).rejects.toThrow();
  });

  it('defaults to process.env when createNodeGatewayServer options are omitted', async () => {
    vi.stubEnv('HOST', '127.0.0.1');
    vi.stubEnv('PORT', '0');
    vi.stubEnv('APP_BASE_URL', 'https://staging.example.com');
    vi.stubEnv('SQLITE_PATH', ':memory:');
    vi.stubEnv('ENCRYPTION_MASTER_KEY', SYNTHETIC_KEY_HEX);

    const handle = await createNodeGatewayServer();
    activeHandles.push(handle);

    expect(handle.port).toBeGreaterThan(0);
    expect(handle.config.appBaseUrl).toBe('https://staging.example.com');
  });
});
