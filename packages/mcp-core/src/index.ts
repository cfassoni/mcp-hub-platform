export const PLATFORM_NAME = 'mcp-hub-platform' as const;

export interface HealthPayload {
  readonly status: 'ok';
  readonly service: typeof PLATFORM_NAME;
}

/** Returns the canonical liveness payload shared across platform services. */
export function createHealthPayload(): HealthPayload {
  return {
    status: 'ok',
    service: PLATFORM_NAME,
  };
}
