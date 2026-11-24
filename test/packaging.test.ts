import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const rootDir = process.cwd();

describe('OCI/Podman packaging, .env.example, and cloudflared config', () => {
  it('defines a rootless multi-stage node:26-slim Containerfile with /health HEALTHCHECK', () => {
    const containerfilePath = resolve(rootDir, 'Containerfile');
    expect(existsSync(containerfilePath)).toBe(true);

    const content = readFileSync(containerfilePath, 'utf8');
    expect(content).toContain('FROM node:26-slim AS builder');
    expect(content).toContain('FROM node:26-slim AS runtime');
    expect(content).toContain('USER node');
    expect(content).toContain('/data');
    expect(content).toContain('HEALTHCHECK');
    expect(content).toContain('/health');
    expect(content).toContain('CMD ["node", "apps/mcp-gateway/bin/server.mjs"]');
  });

  it('defines .containerignore excluding node_modules, .env, scratch, and .git', () => {
    const ignorePath = resolve(rootDir, '.containerignore');
    expect(existsSync(ignorePath)).toBe(true);

    const content = readFileSync(ignorePath, 'utf8');
    expect(content).toContain('node_modules');
    expect(content).toContain('.env');
    expect(content).toContain('scratch');
    expect(content).toContain('.git');
  });

  it('documents required environment variables in .env.example without real secrets', () => {
    const envExamplePath = resolve(rootDir, '.env.example');
    expect(existsSync(envExamplePath)).toBe(true);

    const content = readFileSync(envExamplePath, 'utf8');
    expect(content).toContain('HOST=');
    expect(content).toContain('PORT=');
    expect(content).toContain('APP_BASE_URL=https://');
    expect(content).toContain('SQLITE_PATH=');
    expect(content).toContain('ENCRYPTION_MASTER_KEY=');
    expect(content).toContain('USER_INACTIVITY_TTL_DAYS=60');
    expect(content).not.toMatch(/ENCRYPTION_MASTER_KEY=[0-9a-fA-F]{64}/);
  });

  it('documents isolated staging and friendly-user production tunnels in deploy/cloudflared.example.yml', () => {
    const cloudflaredPath = resolve(rootDir, 'deploy/cloudflared.example.yml');
    expect(existsSync(cloudflaredPath)).toBe(true);

    const content = readFileSync(cloudflaredPath, 'utf8');
    expect(content).toContain('ingress:');
    expect(content).toContain('staging');
    expect(content).toContain('http://127.0.0.1:');
    expect(content).toContain('http_status:404');
  });
});
