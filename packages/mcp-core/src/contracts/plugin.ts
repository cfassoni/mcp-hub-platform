/** Supported marketplace classification categories for hub plugins. */
export type PluginCategory = 'investments' | 'productivity' | 'utilities';

/** Descriptive metadata identifying a registered MCP connector plugin. */
export interface PluginMetadata {
  readonly id: string;
  readonly slug: string;
  readonly name: string;
  readonly description: string;
  readonly category: PluginCategory;
  readonly version: string;
  /** Optional BCP-47 locale tag for user-facing MCP/UI copy (defaults to 'en-US'; e.g., 'pt-BR'). */
  readonly locale?: string;
}

/** Authentication mechanism required by an upstream service connector. */
export type PluginAuthType = 'oauth2' | 'credentials' | 'apikey' | 'none';

/** Supported HTML input types rendered in the portal credential onboarding form. */
export type PluginLoginFieldType = 'text' | 'password' | 'email' | 'url';

/** Definition for a single field in a plugin's credential onboarding form. */
export interface PluginLoginField {
  readonly name: string;
  readonly label: string;
  readonly type: PluginLoginFieldType;
  readonly required: boolean;
  readonly placeholder?: string;
  readonly helpText?: string;
}

/** Portal onboarding prompt schema describing fields collected for upstream auth. */
export interface PluginLoginPrompt {
  readonly title: string;
  readonly description?: string;
  readonly fields: readonly PluginLoginField[];
  readonly submitLabel?: string;
}

/** Discriminated outcome of validating or refreshing upstream user credentials. */
export type UpstreamValidationResult =
  | {
      readonly valid: true;
      readonly upstreamAccountId: string;
      readonly email?: string;
      readonly credentials: Readonly<Record<string, unknown>>;
      /** ISO-8601 UTC timestamp when upstream credentials/tokens expire, if bounded. */
      readonly expiresAt?: string;
    }
  | {
      readonly valid: false;
      /** Sanitized, user-safe failure description (never raw secrets/tokens). */
      readonly error: string;
    };

/** Plugin-declared upstream authentication, validation, and refresh hooks. */
export interface PluginAuthRequirements {
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
}

/** Isolated per-request execution context supplied by the gateway to plugin primitives. */
export interface PluginExecutionContext {
  readonly userId: string;
  readonly pluginSlug: string;
  readonly credentials: Readonly<Record<string, unknown>> | null;
  updateCredentials(next: Readonly<Record<string, unknown>>): Promise<void>;
  readonly signal?: AbortSignal;
}

/** Primitive JSON scalar type. */
export type JsonPrimitive = string | number | boolean | null;

/** Recursive readonly JSON value type. */
export type JsonValue =
  JsonPrimitive | readonly JsonValue[] | { readonly [key: string]: JsonValue };

/** Subset of JSON Schema supported for MCP tool input definitions. */
export interface JsonSchema {
  readonly type?: 'object' | 'array' | 'string' | 'number' | 'integer' | 'boolean' | 'null';
  readonly description?: string;
  readonly enum?: readonly (string | number | boolean)[];
  readonly default?: JsonValue;
  readonly properties?: Readonly<Record<string, JsonSchema>>;
  readonly required?: readonly string[];
  readonly items?: JsonSchema;
  readonly additionalProperties?: boolean | JsonSchema;
  readonly minimum?: number;
  readonly maximum?: number;
  readonly minLength?: number;
  readonly maxLength?: number;
  readonly pattern?: string;
  readonly format?: string;
}

/** Root JSON Schema object contract for MCP tool input arguments. */
export interface ToolInputSchema extends JsonSchema {
  readonly type: 'object';
}

/** Optional behavioral hints attached to an MCP tool definition. */
export interface ToolAnnotations {
  readonly title?: string;
  readonly readOnlyHint?: boolean;
  readonly destructiveHint?: boolean;
  readonly idempotentHint?: boolean;
  readonly openWorldHint?: boolean;
}

/** Plain-text payload returned when reading an MCP resource. */
export interface TextResourceContent {
  readonly uri: string;
  readonly mimeType?: string;
  readonly text: string;
}

/** Base64-encoded binary payload returned when reading an MCP resource. */
export interface BlobResourceContent {
  readonly uri: string;
  readonly mimeType?: string;
  readonly blob: string;
}

/** Union of supported MCP resource payload formats. */
export type ResourceContent = TextResourceContent | BlobResourceContent;

/** Declarative MCP resource descriptor and read handler. */
export interface ResourceDefinition {
  readonly uri: string;
  readonly name: string;
  readonly description?: string;
  readonly mimeType?: string;
  read(uri: string): Promise<readonly ResourceContent[]>;
}

/** Discriminated content block returned by MCP tools and prompt messages. */
export type ToolContentBlock =
  | { readonly type: 'text'; readonly text: string }
  | { readonly type: 'image'; readonly data: string; readonly mimeType: string }
  | { readonly type: 'resource'; readonly resource: ResourceContent };

/** Structured response payload returned by an MCP tool invocation. */
export interface ToolResult {
  readonly content: readonly ToolContentBlock[];
  readonly structuredContent?: Readonly<Record<string, unknown>>;
  readonly isError?: boolean;
}

/** Declarative MCP tool descriptor and execution handler. */
export interface ToolDefinition {
  readonly name: string;
  readonly title?: string;
  readonly description: string;
  readonly inputSchema: ToolInputSchema;
  readonly annotations?: ToolAnnotations;
  execute(args: Readonly<Record<string, unknown>>): Promise<ToolResult>;
}

/** Parameter metadata accepted by an MCP prompt template. */
export interface PromptArgument {
  readonly name: string;
  readonly description?: string;
  readonly required?: boolean;
}

/** Conversational participant role for an MCP prompt message. */
export type PromptRole = 'user' | 'assistant';

/** Single message entry rendered inside an MCP prompt result. */
export interface PromptMessage {
  readonly role: PromptRole;
  readonly content: ToolContentBlock;
}

/** Rendered prompt messages returned by an MCP prompt handler. */
export interface PromptResult {
  readonly description?: string;
  readonly messages: readonly PromptMessage[];
}

/** Declarative MCP prompt descriptor and expansion handler. */
export interface PromptDefinition {
  readonly name: string;
  readonly title?: string;
  readonly description?: string;
  readonly arguments?: readonly PromptArgument[];
  get(args: Readonly<Record<string, string>>): Promise<PromptResult>;
}

/** Primary decoupling contract implemented by every hub connector plugin. */
export interface IMcpPlugin {
  readonly metadata: PluginMetadata;
  getAuthRequirements(): PluginAuthRequirements;
  registerResources(ctx: PluginExecutionContext): Promise<readonly ResourceDefinition[]>;
  registerTools(ctx: PluginExecutionContext): Promise<readonly ToolDefinition[]>;
  registerPrompts(ctx: PluginExecutionContext): Promise<readonly PromptDefinition[]>;
}
