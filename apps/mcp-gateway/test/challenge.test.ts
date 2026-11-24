/// <reference types="node" />
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Hono } from 'hono';
import { afterEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/index.js';
import { createNodeGatewayServer, type NodeGatewayServerHandle } from '../src/node-server.js';
import {
  buildWwwAuthenticateHeader,
  createUnauthorizedResponse,
  extractBearerToken,
  registerMcpChallengeMiddleware,
} from '../src/oauth/challenge.js';

const SYNTHETIC_KEY_HEX = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

const activeHandles: NodeGatewayServerHandle[] = [];

afterEach(async () => {
  while (activeHandles.length > 0) {
    const handle = activeHandles.pop();
    if (handle) {
      await handle.stop();
    }
  }
});

describe('RFC 9728 / RFC 6750 WWW-Authenticate challenge & Bearer parser', () => {
  it('builds canonical Bearer WWW-Authenticate headers anchored to APP_BASE_URL', () => {
    expect(buildWwwAuthenticateHeader('https://mcp.example.com/')).toBe(
      'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"',
    );

    expect(
      buildWwwAuthenticateHeader('https://mcp.example.com', {
        resourceMetadataPath: '/.well-known/oauth-protected-resource/fiainvest/mcp',
        scopes: ['portfolio:read', 'orders:simulate'],
        error: 'invalid_token',
        errorDescription: 'Access token expired',
      }),
    ).toBe(
      'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/fiainvest/mcp", scope="portfolio:read orders:simulate", error="invalid_token", error_description="Access token expired"',
    );

    expect(
      buildWwwAuthenticateHeader('https://mcp.example.com', {
        scopes: [],
        error: 'insufficient_scope',
      }),
    ).toBe(
      'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", error="insufficient_scope"',
    );
  });

  it.each([
    ['non-HTTPS origin', 'http://insecure.example.com', {}],
    ['origin escape path', 'https://mcp.example.com', { resourceMetadataPath: '//evil.com/meta' }],
    ['empty scope token', 'https://mcp.example.com', { scopes: [''] }],
    ['scope with whitespace', 'https://mcp.example.com', { scopes: ['bad scope'] }],
    ['scope with quote', 'https://mcp.example.com', { scopes: ['bad"scope'] }],
    ['scope with backslash', 'https://mcp.example.com', { scopes: ['bad\\scope'] }],
    ['scope with CR/LF', 'https://mcp.example.com', { scopes: ['bad\nscope'] }],
    ['empty errorDescription', 'https://mcp.example.com', { errorDescription: '' }],
    ['errorDescription with quote', 'https://mcp.example.com', { errorDescription: 'bad"desc' }],
    [
      'errorDescription with backslash',
      'https://mcp.example.com',
      { errorDescription: 'bad\\desc' },
    ],
    ['errorDescription with CR/LF', 'https://mcp.example.com', { errorDescription: 'bad\rdesc' }],
  ])('rejects unsafe header inputs (%s)', (_label, baseUrl, options) => {
    expect(() => buildWwwAuthenticateHeader(baseUrl, options)).toThrow();
  });

  it('extracts syntactically valid RFC 6750 Bearer tokens and rejects malformed headers', () => {
    expect(extractBearerToken('Bearer abc.def_123-xyz==')).toBe('abc.def_123-xyz==');
    expect(extractBearerToken('bearer token123')).toBe('token123');
    expect(extractBearerToken('BeArEr   trimmed_tok')).toBe('trimmed_tok');

    expect(extractBearerToken(undefined)).toBeNull();
    expect(extractBearerToken('')).toBeNull();
    expect(extractBearerToken('   ')).toBeNull();
    expect(extractBearerToken('Basic dXNlcjpwYXNz')).toBeNull();
    expect(extractBearerToken('Bearer')).toBeNull();
    expect(extractBearerToken('Bearer   ')).toBeNull();
    expect(extractBearerToken('Bearer tok extra')).toBeNull();
    expect(extractBearerToken('Bearer bad\rtok')).toBeNull();
  });

  it('constructs 401 unauthorized responses with WWW-Authenticate and Cache-Control: no-store', async () => {
    const res = createUnauthorizedResponse('https://mcp.example.com', {
      scopes: ['portfolio:read'],
      error: 'invalid_token',
      errorDescription: 'Token is invalid',
    });

    expect(res.status).toBe(401);
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(res.headers.get('www-authenticate')).toBe(
      'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", scope="portfolio:read", error="invalid_token", error_description="Token is invalid"',
    );
    await expect(res.json()).resolves.toEqual({
      error: 'invalid_token',
      error_description: 'Token is invalid',
    });
  });
});

describe('canonical MCP 401 challenge middleware on /:slug/mcp', () => {
  it('returns 401 WWW-Authenticate on unauthenticated GET, POST, and DELETE /:slug/mcp requests', async () => {
    const app = createApp({
      appBaseUrl: 'https://staging.example.com/',
      scopesSupported: ['portfolio:read'],
    });

    const spoofHeaders = {
      host: 'evil.attacker',
      'x-forwarded-host': 'evil.attacker',
      'x-forwarded-proto': 'http',
    };

    for (const method of ['GET', 'POST', 'DELETE'] as const) {
      const res = await app.request('http://127.0.0.1:8787/fiainvest/mcp', {
        method,
        headers: spoofHeaders,
      });

      expect(res.status).toBe(401);
      expect(res.headers.get('cache-control')).toBe('no-store');
      expect(res.headers.get('www-authenticate')).toBe(
        'Bearer resource_metadata="https://staging.example.com/.well-known/oauth-protected-resource", scope="portfolio:read"',
      );
      await expect(res.json()).resolves.toEqual({
        error: 'unauthorized',
        error_description: 'Authentication required',
      });
    }
  });

  it('challenges malformed Authorization headers, returns 404 on invalid slugs, and fails closed 503 when unconfigured', async () => {
    const app = createApp({ appBaseUrl: 'https://prod.example.com' });

    for (const badAuth of ['Basic dXNlcjpwYXNz', 'Bearer ', 'Bearer tok extra']) {
      const res = await app.request('/fiainvest/mcp', {
        method: 'POST',
        headers: { authorization: badAuth },
      });
      expect(res.status).toBe(401);
      expect(res.headers.get('www-authenticate')).toBe(
        'Bearer resource_metadata="https://prod.example.com/.well-known/oauth-protected-resource"',
      );
    }

    const badSlugRes = await app.request('/INVALID_SLUG/mcp', { method: 'POST' });
    expect(badSlugRes.status).toBe(404);
    expect(badSlugRes.headers.get('www-authenticate')).toBeNull();

    const unconfiguredApp = createApp();
    const unconfiguredRes = await unconfiguredApp.request('/fiainvest/mcp', { method: 'POST' });
    expect(unconfiguredRes.status).toBe(503);
    await expect(unconfiguredRes.json()).resolves.toEqual({
      error: 'server_misconfigured',
      error_description: 'APP_BASE_URL is not configured',
    });
  });

  it('forwards requests carrying a syntactically valid Bearer token and keeps /health and discovery public', async () => {
    const customApp = new Hono();
    registerMcpChallengeMiddleware(customApp, {
      appBaseUrl: 'https://prod.example.com',
      scopesSupported: ['portfolio:read'],
    });
    customApp.post('/:slug/mcp', (c) =>
      c.json({
        slug: c.req.param('slug'),
        token: extractBearerToken(c.req.header('authorization')),
      }),
    );

    const authorizedRes = await customApp.request('/fiainvest/mcp', {
      method: 'POST',
      headers: { authorization: 'Bearer synthetic_mcp_token_abc' },
    });
    expect(authorizedRes.status).toBe(200);
    await expect(authorizedRes.json()).resolves.toEqual({
      slug: 'fiainvest',
      token: 'synthetic_mcp_token_abc',
    });

    const defaultApp = createApp({ appBaseUrl: 'https://prod.example.com' });
    expect((await defaultApp.request('/health')).status).toBe(200);
    expect((await defaultApp.request('/.well-known/oauth-authorization-server')).status).toBe(200);
    expect((await defaultApp.request('/.well-known/oauth-protected-resource')).status).toBe(200);
    expect(
      (
        await defaultApp.request('/fiainvest/mcp', {
          method: 'POST',
          headers: { authorization: 'Bearer synthetic_mcp_token_abc' },
        })
      ).status,
    ).toBe(404);
  });

  it('challenges anonymous POST /:slug/mcp over live Node.js 26 HTTP adapter using APP_BASE_URL', async () => {
    const handle = await createNodeGatewayServer({
      env: {
        HOST: '127.0.0.1',
        PORT: '0',
        APP_BASE_URL: 'https://prod-mcp.example.com',
        SQLITE_PATH: ':memory:',
        ENCRYPTION_MASTER_KEY: SYNTHETIC_KEY_HEX,
      },
    });
    activeHandles.push(handle);

    const res = await fetch(`http://127.0.0.1:${handle.port}/fiainvest/mcp`, {
      method: 'POST',
      headers: {
        'x-forwarded-host': 'evil.attacker',
        'x-forwarded-proto': 'http',
      },
    });

    expect(res.status).toBe(401);
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(res.headers.get('www-authenticate')).toBe(
      'Bearer resource_metadata="https://prod-mcp.example.com/.well-known/oauth-protected-resource"',
    );
  });

  it('keeps oauth/challenge.ts free of node:*, process.env, and Buffer', () => {
    const challengePath = fileURLToPath(new URL('../src/oauth/challenge.ts', import.meta.url));
    const source = readFileSync(challengePath, 'utf8');

    expect(source).not.toMatch(/['"]node:[^'"]+['"]/);
    expect(source).not.toMatch(/\bprocess\.env\b/);
    expect(source).not.toMatch(/\bBuffer\b/);
  });
});
