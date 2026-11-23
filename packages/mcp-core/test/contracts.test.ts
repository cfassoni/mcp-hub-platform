import { describe, expect, expectTypeOf, it } from 'vitest';
import { PLATFORM_NAME, createHealthPayload } from '@mcphub/core';
import type {
  BlobResourceContent,
  EncryptedPayload,
  HealthPayload,
  IMcpPlugin,
  IStorageDriver,
  IsoUtcTimestamp,
  IssueAccessTokenInput,
  JsonPrimitive,
  JsonSchema,
  JsonValue,
  OAuthAuthCodeRecord,
  OAuthClientKind,
  OAuthClientRecord,
  OAuthTokenEndpointAuthMethod,
  OAuthTokenRecord,
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
  SaveAuthCodeInput,
  TextResourceContent,
  ToolAnnotations,
  ToolContentBlock,
  ToolDefinition,
  ToolInputSchema,
  ToolResult,
  UpsertOAuthClientInput,
  UpsertUserCredentialInput,
  UpsertUserInput,
  UpstreamValidationResult,
  UserCredentialRecord,
  UserRecord,
  WebSessionRecord,
} from '@mcphub/core';

describe('health contract preservation', () => {
  it('preserves PLATFORM_NAME, HealthPayload, and createHealthPayload', () => {
    expectTypeOf<HealthPayload>().toEqualTypeOf<{
      readonly status: 'ok';
      readonly service: typeof PLATFORM_NAME;
    }>();

    const payload: HealthPayload = createHealthPayload();
    expect(PLATFORM_NAME).toBe('mcp-hub-platform');
    expect(payload).toEqual({
      status: 'ok',
      service: 'mcp-hub-platform',
    });
  });
});

describe('plugin contracts', () => {
  it('defines plugin metadata and auth requirement types', () => {
    expectTypeOf<PluginCategory>().toEqualTypeOf<'investments' | 'productivity' | 'utilities'>();
    expectTypeOf<PluginMetadata>().toEqualTypeOf<{
      readonly id: string;
      readonly slug: string;
      readonly name: string;
      readonly description: string;
      readonly category: PluginCategory;
      readonly version: string;
      readonly locale?: string;
    }>();

    expectTypeOf<PluginAuthType>().toEqualTypeOf<'oauth2' | 'credentials' | 'apikey' | 'none'>();
    expectTypeOf<PluginLoginFieldType>().toEqualTypeOf<'text' | 'password' | 'email' | 'url'>();
    expectTypeOf<PluginLoginField>().toEqualTypeOf<{
      readonly name: string;
      readonly label: string;
      readonly type: PluginLoginFieldType;
      readonly required: boolean;
      readonly placeholder?: string;
      readonly helpText?: string;
    }>();
    expectTypeOf<PluginLoginPrompt>().toEqualTypeOf<{
      readonly title: string;
      readonly description?: string;
      readonly fields: readonly PluginLoginField[];
      readonly submitLabel?: string;
    }>();
    expectTypeOf<PluginAuthRequirements>().toEqualTypeOf<{
      readonly authType: PluginAuthType;
      readonly scopes?: readonly string[];
      readonly loginPrompt?: PluginLoginPrompt;
      readonly validateUpstream?: (
        input: Readonly<Record<string, unknown>>,
        signal?: AbortSignal,
      ) => Promise<UpstreamValidationResult>;
      readonly refreshUpstream?: (
        credentials: Readonly<Record<string, unknown>>,
        signal?: AbortSignal,
      ) => Promise<UpstreamValidationResult>;
    }>();
  });

  it('narrows UpstreamValidationResult strictly on valid discriminant', () => {
    type ValidValidation = Extract<UpstreamValidationResult, { readonly valid: true }>;
    type InvalidValidation = Extract<UpstreamValidationResult, { readonly valid: false }>;

    expectTypeOf<ValidValidation>().toEqualTypeOf<{
      readonly valid: true;
      readonly upstreamAccountId: string;
      readonly email?: string;
      readonly credentials: Readonly<Record<string, unknown>>;
      readonly expiresAt?: string;
    }>();
    expectTypeOf<InvalidValidation>().toEqualTypeOf<{
      readonly valid: false;
      readonly error: string;
    }>();

    const extractOutcome = (result: UpstreamValidationResult): string => {
      if (result.valid) {
        expectTypeOf(result).toEqualTypeOf<ValidValidation>();
        expectTypeOf(result).not.toHaveProperty('error');
        return result.upstreamAccountId;
      }
      expectTypeOf(result).toEqualTypeOf<InvalidValidation>();
      expectTypeOf(result).not.toHaveProperty('upstreamAccountId');
      return result.error;
    };

    // Synthetic dummy test fixtures
    const validResult: UpstreamValidationResult = {
      valid: true,
      upstreamAccountId: 'acct-dummy-001',
      email: 'dummy.user@example.test',
      credentials: { token: 'dummy-upstream-token' },
      expiresAt: '2026-12-31T23:59:59.000Z',
    };
    const invalidResult: UpstreamValidationResult = {
      valid: false,
      error: 'Upstream authentication rejected',
    };

    expect(extractOutcome(validResult)).toBe('acct-dummy-001');
    expect(extractOutcome(invalidResult)).toBe('Upstream authentication rejected');
  });

  it('isolates PluginExecutionContext from storage drivers and encryption master keys', () => {
    expectTypeOf<keyof PluginExecutionContext>().toEqualTypeOf<
      'userId' | 'pluginSlug' | 'credentials' | 'updateCredentials' | 'signal'
    >();
    expectTypeOf<PluginExecutionContext>().toEqualTypeOf<{
      readonly userId: string;
      readonly pluginSlug: string;
      readonly credentials: Readonly<Record<string, unknown>> | null;
      updateCredentials(next: Readonly<Record<string, unknown>>): Promise<void>;
      readonly signal?: AbortSignal;
    }>();

    expectTypeOf<PluginExecutionContext>().not.toHaveProperty('storage');
    expectTypeOf<PluginExecutionContext>().not.toHaveProperty('driver');
    expectTypeOf<PluginExecutionContext>().not.toHaveProperty('encryptionMasterKey');
    expectTypeOf<PluginExecutionContext>().not.toHaveProperty('ENCRYPTION_MASTER_KEY');
  });

  it('defines strictly typed JSON schema, MCP primitive, and IMcpPlugin contracts', async () => {
    expectTypeOf<JsonPrimitive>().toEqualTypeOf<string | number | boolean | null>();
    expectTypeOf<JsonValue>().toExtend<
      JsonPrimitive | readonly JsonValue[] | { readonly [key: string]: JsonValue }
    >();
    expectTypeOf<
      JsonPrimitive | readonly JsonValue[] | { readonly [key: string]: JsonValue }
    >().toExtend<JsonValue>();

    expectTypeOf<keyof JsonSchema>().toEqualTypeOf<
      | 'type'
      | 'description'
      | 'enum'
      | 'default'
      | 'properties'
      | 'required'
      | 'items'
      | 'additionalProperties'
      | 'minimum'
      | 'maximum'
      | 'minLength'
      | 'maxLength'
      | 'pattern'
      | 'format'
    >();
    expectTypeOf<JsonSchema['type']>().toEqualTypeOf<
      'object' | 'array' | 'string' | 'number' | 'integer' | 'boolean' | 'null' | undefined
    >();
    expectTypeOf<JsonSchema['description']>().toEqualTypeOf<string | undefined>();
    expectTypeOf<JsonSchema['enum']>().toEqualTypeOf<
      readonly (string | number | boolean)[] | undefined
    >();
    expectTypeOf<JsonSchema['default']>().toEqualTypeOf<JsonValue | undefined>();
    expectTypeOf<JsonSchema['properties']>().toEqualTypeOf<
      Readonly<Record<string, JsonSchema>> | undefined
    >();
    expectTypeOf<JsonSchema['required']>().toEqualTypeOf<readonly string[] | undefined>();
    expectTypeOf<JsonSchema['items']>().toEqualTypeOf<JsonSchema | undefined>();
    expectTypeOf<JsonSchema['additionalProperties']>().toEqualTypeOf<
      boolean | JsonSchema | undefined
    >();
    expectTypeOf<JsonSchema['minimum']>().toEqualTypeOf<number | undefined>();
    expectTypeOf<JsonSchema['maximum']>().toEqualTypeOf<number | undefined>();
    expectTypeOf<JsonSchema['minLength']>().toEqualTypeOf<number | undefined>();
    expectTypeOf<JsonSchema['maxLength']>().toEqualTypeOf<number | undefined>();
    expectTypeOf<JsonSchema['pattern']>().toEqualTypeOf<string | undefined>();
    expectTypeOf<JsonSchema['format']>().toEqualTypeOf<string | undefined>();

    expectTypeOf<ToolInputSchema>().toExtend<JsonSchema>();
    expectTypeOf<ToolInputSchema['type']>().toEqualTypeOf<'object'>();

    expectTypeOf<ToolAnnotations>().toEqualTypeOf<{
      readonly title?: string;
      readonly readOnlyHint?: boolean;
      readonly destructiveHint?: boolean;
      readonly idempotentHint?: boolean;
      readonly openWorldHint?: boolean;
    }>();

    expectTypeOf<TextResourceContent>().toEqualTypeOf<{
      readonly uri: string;
      readonly mimeType?: string;
      readonly text: string;
    }>();
    expectTypeOf<BlobResourceContent>().toEqualTypeOf<{
      readonly uri: string;
      readonly mimeType?: string;
      readonly blob: string;
    }>();
    expectTypeOf<ResourceContent>().toEqualTypeOf<TextResourceContent | BlobResourceContent>();

    const extractResourcePayload = (content: ResourceContent): string => {
      if ('text' in content) {
        expectTypeOf(content).toEqualTypeOf<TextResourceContent>();
        return content.text;
      }
      expectTypeOf(content).toEqualTypeOf<BlobResourceContent>();
      return content.blob;
    };

    expectTypeOf<ResourceDefinition>().toEqualTypeOf<{
      readonly uri: string;
      readonly name: string;
      readonly description?: string;
      readonly mimeType?: string;
      read(uri: string): Promise<readonly ResourceContent[]>;
    }>();

    expectTypeOf<ToolContentBlock>().toEqualTypeOf<
      | { readonly type: 'text'; readonly text: string }
      | { readonly type: 'image'; readonly data: string; readonly mimeType: string }
      | { readonly type: 'resource'; readonly resource: ResourceContent }
    >();
    expectTypeOf<ToolResult>().toEqualTypeOf<{
      readonly content: readonly ToolContentBlock[];
      readonly structuredContent?: Readonly<Record<string, unknown>>;
      readonly isError?: boolean;
    }>();
    expectTypeOf<ToolDefinition>().toEqualTypeOf<{
      readonly name: string;
      readonly title?: string;
      readonly description: string;
      readonly inputSchema: ToolInputSchema;
      readonly annotations?: ToolAnnotations;
      execute(args: Readonly<Record<string, unknown>>): Promise<ToolResult>;
    }>();

    expectTypeOf<PromptArgument>().toEqualTypeOf<{
      readonly name: string;
      readonly description?: string;
      readonly required?: boolean;
    }>();
    expectTypeOf<PromptRole>().toEqualTypeOf<'user' | 'assistant'>();
    expectTypeOf<PromptMessage>().toEqualTypeOf<{
      readonly role: PromptRole;
      readonly content: ToolContentBlock;
    }>();
    expectTypeOf<PromptResult>().toEqualTypeOf<{
      readonly description?: string;
      readonly messages: readonly PromptMessage[];
    }>();
    expectTypeOf<PromptDefinition>().toEqualTypeOf<{
      readonly name: string;
      readonly title?: string;
      readonly description?: string;
      readonly arguments?: readonly PromptArgument[];
      get(args: Readonly<Record<string, string>>): Promise<PromptResult>;
    }>();

    expectTypeOf<IMcpPlugin>().toEqualTypeOf<{
      readonly metadata: PluginMetadata;
      getAuthRequirements(): PluginAuthRequirements;
      registerResources(ctx: PluginExecutionContext): Promise<readonly ResourceDefinition[]>;
      registerTools(ctx: PluginExecutionContext): Promise<readonly ToolDefinition[]>;
      registerPrompts(ctx: PluginExecutionContext): Promise<readonly PromptDefinition[]>;
    }>();

    // Synthetic dummy plugin implementation verifying structural construction
    const samplePlugin: IMcpPlugin = {
      metadata: {
        id: 'plugin-dummy-001',
        slug: 'dummy-connector',
        name: 'Dummy Connector',
        description: 'Synthetic test connector',
        category: 'utilities',
        version: '0.1.0',
        locale: 'en-US',
      },
      getAuthRequirements: () => ({
        authType: 'none',
      }),
      registerResources: async () => [
        {
          uri: 'dummy://resource/1',
          name: 'dummy-resource',
          mimeType: 'text/plain',
          read: async (uri: string) => [{ uri, text: 'dummy text content' }],
        },
      ],
      registerTools: async () => [
        {
          name: 'dummy_tool',
          description: 'Synthetic test tool',
          inputSchema: {
            type: 'object',
            properties: {
              symbol: { type: 'string', minLength: 1 },
            },
            required: ['symbol'],
            additionalProperties: false,
          },
          annotations: {
            readOnlyHint: true,
          },
          execute: async () => ({
            content: [{ type: 'text', text: 'ok' }],
          }),
        },
      ],
      registerPrompts: async () => [
        {
          name: 'dummy_prompt',
          arguments: [{ name: 'topic', required: true }],
          get: async (args: Readonly<Record<string, string>>) => ({
            messages: [
              {
                role: 'user',
                content: { type: 'text', text: args['topic'] ?? 'default' },
              },
            ],
          }),
        },
      ],
    };

    const dummyCtx: PluginExecutionContext = {
      userId: 'user-dummy-001',
      pluginSlug: 'dummy-connector',
      credentials: null,
      updateCredentials: async () => undefined,
    };

    const resources = await samplePlugin.registerResources(dummyCtx);
    const firstResource = resources[0];
    expect(firstResource).toBeDefined();
    if (firstResource) {
      const contents = await firstResource.read(firstResource.uri);
      const firstContent = contents[0];
      expect(firstContent).toBeDefined();
      if (firstContent) {
        expect(extractResourcePayload(firstContent)).toBe('dummy text content');
      }
    }
    expect(extractResourcePayload({ uri: 'dummy://blob/1', blob: 'ZHVtbXk=' })).toBe('ZHVtbXk=');
  });
});

describe('storage and vault contracts', () => {
  it('defines encrypted payload and all seven persistence record schemas', () => {
    expectTypeOf<IsoUtcTimestamp>().toEqualTypeOf<string>();

    expectTypeOf<EncryptedPayload>().toEqualTypeOf<{
      readonly ciphertext: string;
      readonly iv: string;
      readonly authTag: string;
      readonly keyVersion?: number;
    }>();

    expectTypeOf<UserRecord>().toEqualTypeOf<{
      readonly id: string;
      readonly email: string;
      readonly createdAt: IsoUtcTimestamp;
      readonly updatedAt: IsoUtcTimestamp;
      readonly lastActivityAt: IsoUtcTimestamp;
    }>();

    expectTypeOf<UserCredentialRecord>().toEqualTypeOf<{
      readonly userId: string;
      readonly pluginSlug: string;
      readonly encryptedPayload: EncryptedPayload;
      readonly expiresAt?: IsoUtcTimestamp;
      readonly createdAt: IsoUtcTimestamp;
      readonly updatedAt: IsoUtcTimestamp;
    }>();

    expectTypeOf<OAuthClientKind>().toEqualTypeOf<'cimd' | 'dcr' | 'static'>();
    expectTypeOf<OAuthTokenEndpointAuthMethod>().toEqualTypeOf<
      'none' | 'client_secret_post' | 'client_secret_basic'
    >();
    expectTypeOf<OAuthClientRecord>().toEqualTypeOf<{
      readonly clientId: string;
      readonly kind: OAuthClientKind;
      readonly clientName?: string;
      readonly redirectUris: readonly string[];
      readonly scope?: string;
      readonly tokenEndpointAuthMethod?: OAuthTokenEndpointAuthMethod;
      readonly expiresAt?: IsoUtcTimestamp;
      readonly createdAt: IsoUtcTimestamp;
      readonly updatedAt: IsoUtcTimestamp;
    }>();

    expectTypeOf<OAuthAuthCodeRecord['codeChallengeMethod']>().toEqualTypeOf<'S256'>();
    expectTypeOf<OAuthAuthCodeRecord>().toEqualTypeOf<{
      readonly codeHash: string;
      readonly clientId: string;
      readonly userId: string;
      readonly pluginSlug: string;
      readonly redirectUri: string;
      readonly codeChallenge: string;
      readonly codeChallengeMethod: 'S256';
      readonly scope: string;
      readonly expiresAt: IsoUtcTimestamp;
      readonly usedAt?: IsoUtcTimestamp;
      readonly createdAt: IsoUtcTimestamp;
    }>();

    expectTypeOf<OAuthTokenRecord>().toEqualTypeOf<{
      readonly tokenHash: string;
      readonly userId: string;
      readonly clientId: string;
      readonly pluginSlug: string;
      readonly scope: string;
      readonly expiresAt: IsoUtcTimestamp;
      readonly revokedAt?: IsoUtcTimestamp;
      readonly createdAt: IsoUtcTimestamp;
    }>();

    expectTypeOf<WebSessionRecord>().toEqualTypeOf<{
      readonly cookieHash: string;
      readonly userId: string;
      readonly expiresAt: IsoUtcTimestamp;
      readonly createdAt: IsoUtcTimestamp;
    }>();

    // Synthetic dummy record instantiation
    const nowIso: IsoUtcTimestamp = '2026-11-23T00:00:00.000Z';
    const encrypted: EncryptedPayload = {
      ciphertext: 'dummy-ciphertext-b64',
      iv: 'dummy-iv-12b',
      authTag: 'dummy-tag-16b',
      keyVersion: 1,
    };
    const user: UserRecord = {
      id: 'user-dummy-001',
      email: 'dummy@example.test',
      createdAt: nowIso,
      updatedAt: nowIso,
      lastActivityAt: nowIso,
    };
    const cred: UserCredentialRecord = {
      userId: user.id,
      pluginSlug: 'dummy-connector',
      encryptedPayload: encrypted,
      createdAt: nowIso,
      updatedAt: nowIso,
    };
    const client: OAuthClientRecord = {
      clientId: 'https://client.example.test/oauth-metadata.json',
      kind: 'cimd',
      redirectUris: ['https://client.example.test/callback'],
      tokenEndpointAuthMethod: 'none',
      createdAt: nowIso,
      updatedAt: nowIso,
    };
    const authCode: OAuthAuthCodeRecord = {
      codeHash: 'dummy-code-sha256',
      clientId: client.clientId,
      userId: user.id,
      pluginSlug: 'dummy-connector',
      redirectUri: 'https://client.example.test/callback',
      codeChallenge: 'dummy-s256-challenge',
      codeChallengeMethod: 'S256',
      scope: 'mcp:tools',
      expiresAt: '2026-11-23T00:05:00.000Z',
      createdAt: nowIso,
    };
    const token: OAuthTokenRecord = {
      tokenHash: 'dummy-token-sha256',
      userId: user.id,
      clientId: client.clientId,
      pluginSlug: 'dummy-connector',
      scope: 'mcp:tools',
      expiresAt: '2026-11-23T01:00:00.000Z',
      createdAt: nowIso,
    };
    const session: WebSessionRecord = {
      cookieHash: 'dummy-cookie-sha256',
      userId: user.id,
      expiresAt: '2026-12-23T00:00:00.000Z',
      createdAt: nowIso,
    };

    expect(cred.encryptedPayload).toEqual(encrypted);
    expect(authCode.codeChallengeMethod).toBe('S256');
    expect(token.userId).toBe(user.id);
    expect(session.cookieHash).toBe('dummy-cookie-sha256');
  });

  it('defines input DTOs and all 20 async IStorageDriver method signatures', () => {
    expectTypeOf<UpsertUserInput>().toEqualTypeOf<{
      readonly id: string;
      readonly email: string;
      readonly nowIso: IsoUtcTimestamp;
    }>();
    expectTypeOf<UpsertUserCredentialInput>().toEqualTypeOf<{
      readonly userId: string;
      readonly pluginSlug: string;
      readonly encryptedPayload: EncryptedPayload;
      readonly expiresAt?: IsoUtcTimestamp;
      readonly nowIso: IsoUtcTimestamp;
    }>();
    expectTypeOf<UpsertOAuthClientInput>().toEqualTypeOf<{
      readonly clientId: string;
      readonly kind: OAuthClientKind;
      readonly clientName?: string;
      readonly redirectUris: readonly string[];
      readonly scope?: string;
      readonly tokenEndpointAuthMethod?: OAuthTokenEndpointAuthMethod;
      readonly expiresAt?: IsoUtcTimestamp;
      readonly nowIso: IsoUtcTimestamp;
    }>();
    expectTypeOf<SaveAuthCodeInput>().toEqualTypeOf<Omit<OAuthAuthCodeRecord, 'usedAt'>>();
    expectTypeOf<IssueAccessTokenInput>().toEqualTypeOf<Omit<OAuthTokenRecord, 'revokedAt'>>();

    expectTypeOf<keyof IStorageDriver>().toEqualTypeOf<
      | 'migrate'
      | 'close'
      | 'upsertUser'
      | 'getUserById'
      | 'getUserByEmail'
      | 'touchUserActivity'
      | 'purgeInactiveUsers'
      | 'upsertUserCredential'
      | 'getUserCredential'
      | 'deleteUserCredential'
      | 'upsertOAuthClient'
      | 'getOAuthClient'
      | 'saveAuthCode'
      | 'consumeAuthCode'
      | 'issueAccessToken'
      | 'getActiveTokenByHash'
      | 'revokeClientTokens'
      | 'createWebSession'
      | 'getActiveWebSessionByHash'
      | 'deleteWebSessionByHash'
    >();

    expectTypeOf<IStorageDriver['migrate']>().toEqualTypeOf<() => Promise<void>>();
    expectTypeOf<IStorageDriver['close']>().toEqualTypeOf<() => Promise<void>>();
    expectTypeOf<IStorageDriver['upsertUser']>().toEqualTypeOf<
      (input: UpsertUserInput) => Promise<UserRecord>
    >();
    expectTypeOf<IStorageDriver['getUserById']>().toEqualTypeOf<
      (userId: string) => Promise<UserRecord | null>
    >();
    expectTypeOf<IStorageDriver['getUserByEmail']>().toEqualTypeOf<
      (email: string) => Promise<UserRecord | null>
    >();
    expectTypeOf<IStorageDriver['touchUserActivity']>().toEqualTypeOf<
      (userId: string, activityAtIso: IsoUtcTimestamp) => Promise<boolean>
    >();
    expectTypeOf<IStorageDriver['purgeInactiveUsers']>().toEqualTypeOf<
      (cutoffIso: IsoUtcTimestamp) => Promise<number>
    >();
    expectTypeOf<IStorageDriver['upsertUserCredential']>().toEqualTypeOf<
      (input: UpsertUserCredentialInput) => Promise<UserCredentialRecord>
    >();
    expectTypeOf<IStorageDriver['getUserCredential']>().toEqualTypeOf<
      (userId: string, pluginSlug: string) => Promise<UserCredentialRecord | null>
    >();
    expectTypeOf<IStorageDriver['deleteUserCredential']>().toEqualTypeOf<
      (userId: string, pluginSlug: string) => Promise<boolean>
    >();
    expectTypeOf<IStorageDriver['upsertOAuthClient']>().toEqualTypeOf<
      (input: UpsertOAuthClientInput) => Promise<OAuthClientRecord>
    >();
    expectTypeOf<IStorageDriver['getOAuthClient']>().toEqualTypeOf<
      (clientId: string) => Promise<OAuthClientRecord | null>
    >();
    expectTypeOf<IStorageDriver['saveAuthCode']>().toEqualTypeOf<
      (input: SaveAuthCodeInput) => Promise<void>
    >();
    expectTypeOf<IStorageDriver['consumeAuthCode']>().toEqualTypeOf<
      (codeHash: string, nowIso: IsoUtcTimestamp) => Promise<OAuthAuthCodeRecord | null>
    >();
    expectTypeOf<IStorageDriver['issueAccessToken']>().toEqualTypeOf<
      (input: IssueAccessTokenInput) => Promise<OAuthTokenRecord>
    >();
    expectTypeOf<IStorageDriver['getActiveTokenByHash']>().toEqualTypeOf<
      (tokenHash: string, nowIso: IsoUtcTimestamp) => Promise<OAuthTokenRecord | null>
    >();
    expectTypeOf<IStorageDriver['revokeClientTokens']>().toEqualTypeOf<
      (userId: string, clientId: string, revokedAtIso: IsoUtcTimestamp) => Promise<number>
    >();
    expectTypeOf<IStorageDriver['createWebSession']>().toEqualTypeOf<
      (input: WebSessionRecord) => Promise<WebSessionRecord>
    >();
    expectTypeOf<IStorageDriver['getActiveWebSessionByHash']>().toEqualTypeOf<
      (cookieHash: string, nowIso: IsoUtcTimestamp) => Promise<WebSessionRecord | null>
    >();
    expectTypeOf<IStorageDriver['deleteWebSessionByHash']>().toEqualTypeOf<
      (cookieHash: string) => Promise<boolean>
    >();
  });
});
