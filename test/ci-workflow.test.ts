import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const workflowPath = resolve(process.cwd(), '.github/workflows/ci.yml');

describe('GitHub Actions CI workflow', () => {
  it('exists at .github/workflows/ci.yml', () => {
    expect(existsSync(workflowPath)).toBe(true);
  });

  it('triggers on pull_request and push to main with least-privilege permissions', () => {
    const content = readFileSync(workflowPath, 'utf8');

    expect(content).toContain('pull_request:');
    expect(content).toContain('push:');
    expect(content).toContain('branches: [main]');
    expect(content).toContain('contents: read');
  });

  it('runs build, quality gate, and dependency audit on Node.js 26', () => {
    const content = readFileSync(workflowPath, 'utf8');

    expect(content).toContain("node-version: '26'");
    expect(content).toContain('npm ci');
    expect(content).toContain('npm run build');
    expect(content).toContain('npm run gate');
    expect(content).toContain('npm audit --audit-level=high');
  });
});
