/// <reference types="node" />
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, expectTypeOf, it } from 'vitest';
import { createApp, parseGatewayConfig } from '../src/index.js';
import { createNodeGatewayServer, type NodeGatewayServerHandle } from '../src/node-server.js';
import {
  buildAuthorizationServerMetadata,
  buildProtectedResourceMetadata,
  type AuthorizationServerMetadata,
  type ProtectedResourceMetadata,
} from '../src/oauth/discovery.js';

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

describe('OAuth 2.1 discovery metadata builders (RFC 8414 & RFC 9728)', () => {
  it('builds RFC 8414 Authorization Server Metadata with PKCE S256 and CIMD support', () => {
    const meta = buildAuthorizationServerMetadata('https://staging.example.com/');

    expectTypeOf(meta).toEqualTypeOf<AuthorizationServerMetadata>();
    expect(meta).toEqual({
      issuer: 'https://staging.example.com',
      authorization_endpoint: 'https://staging.example.com/oauth/authorize',
      token_endpoint: 'https://staging.example.com/oauth/token',
      registration_endpoint: 'https://staging.example.com/oauth/register',
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
      client_id_metadata_document_supported: true,
    });
    expect('scopes_supported' in meta).toBe(false);

    const emptyScopes = buildAuthorizationServerMetadata('https://staging.example.com', {
      scopesSupported: [],
    });
    expect('scopes_supported' in emptyScopes).toBe(false);

    const withScopes = buildAuthorizationServerMetadata('https://staging.example.com', {
      scopesSupported: ['portfolio:read', 'orders:simulate'],
    });
    expect(withScopes.scopes_supported).toEqual(['portfolio:read', 'orders:simulate']);

    expect(() => buildAuthorizationServerMetadata('http://insecure.example.com')).toThrow();
  });

  it('builds RFC 9728 Protected Resource Metadata for root and plugin resource paths', () => {
    const rootMeta = buildProtectedResourceMetadata('https://prod.example.com/');

    expectTypeOf(rootMeta).toEqualTypeOf<ProtectedResourceMetadata>();
    expect(rootMeta).toEqual({
      resource: 'https://prod.example.com',
      authorization_servers: ['https://prod.example.com'],
      bearer_methods_supported: ['header'],
    });
    expect('scopes_supported' in rootMeta).toBe(false);

    const pluginMeta = buildProtectedResourceMetadata('https://prod.example.com', {
      resourcePath: '/fiainvest/mcp',
      scopesSupported: ['portfolio:read'],
    });
    expect(pluginMeta).toEqual({
      resource: 'https://prod.example.com/fiainvest/mcp',
      authorization_servers: ['https://prod.example.com'],
      bearer_methods_supported: ['header'],
      scopes_supported: ['portfolio:read'],
    });

    const emptyScopesMeta = buildProtectedResourceMetadata('https://prod.example.com', {
      resourcePath: '/fiainvest/mcp',
      scopesSupported: [],
    });
    expect('scopes_supported' in emptyScopesMeta).toBe(false);

    expect(() => buildProtectedResourceMetadata('http://insecure.example.com')).toThrow();
    expect(() =>
      buildProtectedResourceMetadata('https://prod.example.com', {
        resourcePath: '//evil.com/mcp',
      }),
    ).toThrow();
  });
});

describe('gateway well-known discovery endpoints', () => {
  it('serves RFC 8414 and RFC 9728 metadata derived strictly from APP_BASE_URL', async () => {
    const app = createApp({
      appBaseUrl: 'https://staging.example.com/',
      scopesSupported: ['portfolio:read'],
    });

    const spoofHeaders = {
      host: 'evil.attacker',
      'x-forwarded-host': 'evil.attacker',
      'x-forwarded-proto': 'http',
    };

    const asRes = await app.request(
      'http://127.0.0.1:8787/.well-known/oauth-authorization-server',
      {
        headers: spoofHeaders,
      },
    );
    expect(asRes.status).toBe(200);
    expect(asRes.headers.get('cache-control')).toBe('public, max-age=300');
    await expect(asRes.json()).resolves.toEqual({
      issuer: 'https://staging.example.com',
      authorization_endpoint: 'https://staging.example.com/oauth/authorize',
      token_endpoint: 'https://staging.example.com/oauth/token',
      registration_endpoint: 'https://staging.example.com/oauth/register',
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
      client_id_metadata_document_supported: true,
      scopes_supported: ['portfolio:read'],
    });

    const prmRes = await app.request('http://127.0.0.1:8787/.well-known/oauth-protected-resource', {
      headers: spoofHeaders,
    });
    expect(prmRes.status).toBe(200);
    expect(prmRes.headers.get('cache-control')).toBe('public, max-age=300');
    await expect(prmRes.json()).resolves.toEqual({
      resource: 'https://staging.example.com',
      authorization_servers: ['https://staging.example.com'],
      bearer_methods_supported: ['header'],
      scopes_supported: ['portfolio:read'],
    });

    const pluginPrmRes = await app.request(
      'http://127.0.0.1:8787/.well-known/oauth-protected-resource/fiainvest/mcp',
      { headers: spoofHeaders },
    );
    expect(pluginPrmRes.status).toBe(200);
    expect(pluginPrmRes.headers.get('cache-control')).toBe('public, max-age=300');
    await expect(pluginPrmRes.json()).resolves.toEqual({
      resource: 'https://staging.example.com/fiainvest/mcp',
      authorization_servers: ['https://staging.example.com'],
      bearer_methods_supported: ['header'],
      scopes_supported: ['portfolio:read'],
    });
  });

  it('resolves appBaseUrl from GatewayConfig, rejects invalid plugin slugs, and blocks ad-hoc manifests', async () => {
    const config = parseGatewayConfig({
      APP_BASE_URL: 'https://prod.example.com',
      SQLITE_PATH: ':memory:',
      ENCRYPTION_MASTER_KEY: SYNTHETIC_KEY_HEX,
    });
    const app = createApp({ config });

    const validRes = await app.request('/.well-known/oauth-protected-resource/fia-invest/mcp');
    expect(validRes.status).toBe(200);
    await expect(validRes.json()).resolves.toMatchObject({
      resource: 'https://prod.example.com/fia-invest/mcp',
    });

    const invalidSlugRes = await app.request(
      '/.well-known/oauth-protected-resource/INVALID_SLUG/mcp',
    );
    expect(invalidSlugRes.status).toBe(404);

    const adHocRes = await app.request('/.well-known/mcp-app.json');
    expect(adHocRes.status).toBe(404);

    expect(() => createApp({ appBaseUrl: 'http://insecure.example.com' })).toThrow();
  });

  it('fails closed with 503 on discovery routes when APP_BASE_URL is unconfigured while keeping /health 200', async () => {
    const app = createApp();

    const healthRes = await app.request('/health');
    expect(healthRes.status).toBe(200);

    for (const path of [
      '/.well-known/oauth-authorization-server',
      '/.well-known/oauth-protected-resource',
      '/.well-known/oauth-protected-resource/fiainvest/mcp',
    ]) {
      const res = await app.request(path);
      expect(res.status).toBe(503);
      await expect(res.json()).resolves.toEqual({
        error: 'server_misconfigured',
        error_description: 'APP_BASE_URL is not configured',
      });
    }
  });

  it('serves discovery metadata over live Node.js 26 HTTP adapter using authoritative APP_BASE_URL', async () => {
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

    const headers = {
      'x-forwarded-host': 'evil.attacker',
      'x-forwarded-proto': 'http',
    };

    const asRes = await fetch(
      `http://127.0.0.1:${handle.port}/.well-known/oauth-authorization-server`,
      { headers },
    );
    expect(asRes.status).toBe(200);
    await expect(asRes.json()).resolves.toMatchObject({
      issuer: 'https://prod-mcp.example.com',
      authorization_endpoint: 'https://prod-mcp.example.com/oauth/authorize',
      token_endpoint: 'https://prod-mcp.example.com/oauth/token',
      registration_endpoint: 'https://prod-mcp.example.com/oauth/register',
      code_challenge_methods_supported: ['S256'],
      client_id_metadata_document_supported: true,
    });

    const prmRes = await fetch(
      `http://127.0.0.1:${handle.port}/.well-known/oauth-protected-resource/fiainvest/mcp`,
      { headers },
    );
    expect(prmRes.status).toBe(200);
    await expect(prmRes.json()).resolves.toEqual({
      resource: 'https://prod-mcp.example.com/fiainvest/mcp',
      authorization_servers: ['https://prod-mcp.example.com'],
      bearer_methods_supported: ['header'],
    });
  });

  it('keeps oauth/discovery.ts free of node:*, process.env, and Buffer', () => {
    const discoveryPath = fileURLToPath(new URL('../src/oauth/discovery.ts', import.meta.url));
    const source = readFileSync(discoveryPath, 'utf8');

    expect(source).not.toMatch(/['"]node:[^'"]+['"]/);
    expect(source).not.toMatch(/\bprocess\.env\b/);
    expect(source).not.toMatch(/\bBuffer\b/);
  });
});
