/// <reference types="node" />
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const CORE_SRC_DIR = fileURLToPath(new URL('../src', import.meta.url));

function collectTypeScriptFiles(dir: string): string[] {
  const entries = readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];

  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectTypeScriptFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.ts')) {
      files.push(fullPath);
    }
  }

  return files;
}

describe('@mcphub/core runtime portability invariants', () => {
  it('contains zero node:* imports, zero process.env references, and zero Buffer references across packages/mcp-core/src', () => {
    const sourceFiles = collectTypeScriptFiles(CORE_SRC_DIR);
    expect(sourceFiles.length).toBeGreaterThan(0);

    const violations: string[] = [];

    for (const filePath of sourceFiles) {
      const content = readFileSync(filePath, 'utf8');
      const relPath = relative(CORE_SRC_DIR, filePath);

      if (/['"]node:[^'"]+['"]/.test(content)) {
        violations.push(`${relPath}: contains forbidden node:* module specifier`);
      }

      if (/\bprocess\.env\b/.test(content)) {
        violations.push(`${relPath}: contains forbidden process.env reference`);
      }

      if (/\bBuffer\b/.test(content)) {
        violations.push(`${relPath}: contains forbidden Buffer reference`);
      }
    }

    expect(violations).toEqual([]);
  });
});
