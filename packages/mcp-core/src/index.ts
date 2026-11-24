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

export type {
  BlobResourceContent,
  IMcpPlugin,
  JsonPrimitive,
  JsonSchema,
  JsonValue,
  PluginAuthRequirements,
  PluginAuthType,
  PluginCategory,
  PluginExecutionContext,
  PluginLoginField,
  PluginLoginFieldType,
  PluginLoginPrompt,
  PluginMetadata,
  PromptArgument,
  PromptDefinition,
  PromptMessage,
  PromptResult,
  PromptRole,
  ResourceContent,
  ResourceDefinition,
  TextResourceContent,
  ToolAnnotations,
  ToolContentBlock,
  ToolDefinition,
  ToolInputSchema,
  ToolResult,
  UpstreamValidationResult,
} from './contracts/plugin.js';

export type {
  EncryptedPayload,
  IStorageDriver,
  IsoUtcTimestamp,
  IssueAccessTokenInput,
  OAuthAuthCodeRecord,
  OAuthClientKind,
  OAuthClientRecord,
  OAuthTokenEndpointAuthMethod,
  OAuthTokenRecord,
  SaveAuthCodeInput,
  UpsertOAuthClientInput,
  UpsertUserCredentialInput,
  UpsertUserInput,
  UserCredentialRecord,
  UserRecord,
  WebSessionRecord,
} from './contracts/storage.js';

export { UpstreamClientError, sanitizeUpstreamText } from './errors/upstream-client-error.js';
export type { UpstreamClientErrorOptions } from './errors/upstream-client-error.js';

export {
  PLUGIN_SLUG_MAX_LENGTH,
  PLUGIN_SLUG_REGEX,
  assertValidPluginSlug,
  isValidPluginSlug,
} from './validation/slug.js';

export {
  AES_GCM_AUTH_TAG_BIT_LENGTH,
  AES_GCM_AUTH_TAG_BYTE_LENGTH,
  AES_GCM_IV_BYTE_LENGTH,
  AES_GCM_KEY_BYTE_LENGTH,
  DEFAULT_ENCRYPTION_KEY_VERSION,
  EncryptionError,
  createAesGcmCipher,
  parseMasterKey,
} from './crypto/aes-gcm.js';
export type {
  AesGcmCipherOptions,
  AesGcmOperationOptions,
  EncryptionErrorCode,
  IAesGcmCipher,
  MasterKeyInput,
} from './crypto/aes-gcm.js';
