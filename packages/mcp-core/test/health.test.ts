import { describe, expect, it } from 'vitest';
import { PLATFORM_NAME, createHealthPayload } from '@mcphub/core';

describe('health payload helper', () => {
  it('exposes the canonical platform name', () => {
    expect(PLATFORM_NAME).toBe('mcp-hub-platform');
  });

  it('creates a healthy status payload', () => {
    expect(createHealthPayload()).toEqual({
      status: 'ok',
      service: 'mcp-hub-platform',
    });
  });
});
