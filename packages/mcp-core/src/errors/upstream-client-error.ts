const SENSITIVE_KEY_PATTERN =
  '(?:[a-z0-9_-]*(?:password|token|secret|cookie|(?:api|private|encryption|master|signing|auth|session|access|secret)[_-]?key)|access|refresh|(?:proxy[-_]?)?authorization)';

const SENSITIVE_HEADER_LINE_REGEX =
  /^([ \t]*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)):[^\r\n]*/gim;

const INLINE_AUTH_SCHEME_REGEX = /\b(bearer|basic)[ \t]+[^\s"',;<>()[\]{}\\]+/gi;

const JWT_REGEX = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]*)+/g;

const QUERY_PARAM_SECRET_REGEX = new RegExp(
  `([?&])(${SENSITIVE_KEY_PATTERN})=(?:(?:"(?:[^"&#\\r\\n\\\\]|\\\\[^&#\\r\\n])*"|'(?:[^'&#\\r\\n\\\\]|\\\\[^&#\\r\\n])*'|\\\\"(?:[^"&#\\r\\n\\\\]|\\\\\\\\[^&#\\r\\n])*\\\\")(?=[&#\\s"'<>\\)\\]},;]|$)|(?!["']|\\\\")(?:\\[REDACTED\\]|[^&#\\s"'<>\\\\,;()[\\]{}]*))`,
  'gi',
);

const ESCAPED_DOUBLE_QUOTED_VALUE_REGEX = new RegExp(
  `(?<![a-z0-9_-])\\\\"(${SENSITIVE_KEY_PATTERN})\\\\"([ \\t]*:[ \\t]*)\\\\"(?:[^\\\\"]|\\\\\\\\(?:\\\\\\\\|\\\\"|[^\\\\"])|\\\\(?![\\\\"]))*\\\\"`,
  'gi',
);

const DOUBLE_QUOTED_VALUE_REGEX = new RegExp(
  `(?<![a-z0-9_-])(["']?)(${SENSITIVE_KEY_PATTERN})\\1([ \\t]*[:=][ \\t]*)"(?:[^"\\\\]|\\\\.)*"`,
  'gi',
);

const SINGLE_QUOTED_VALUE_REGEX = new RegExp(
  `(?<![a-z0-9_-])(["']?)(${SENSITIVE_KEY_PATTERN})\\1([ \\t]*[:=][ \\t]*)'(?:[^'\\\\]|\\\\.)*'`,
  'gi',
);

const AUTHORIZATION_SCHEME_KV_REGEX =
  /(?<![a-z0-9_-])(["']?)((?:proxy[-_]?)?authorization)\1([ \t]*[:=][ \t]*)(?:bearer|basic|token|apikey|digest|oauth)[ \t]+(?:\[REDACTED\]|[^\s"',;&<>()[\]{}\\]+)/gi;

const UNQUOTED_VALUE_REGEX = new RegExp(
  `(?<![a-z0-9_-])(["']?)(${SENSITIVE_KEY_PATTERN})\\1([ \\t]*[:=][ \\t]*)(?:(?:bearer|basic)[ \\t]+)?(?:\\[REDACTED\\]|[^\\s"',;&<>()[\\]{}\\\\]+)`,
  'gi',
);

/**
 * Deterministically scrubs sensitive upstream credentials, auth headers, JWTs/JWEs,
 * query parameters, and secret key/value pairs from diagnostic text while keeping
 * ordinary error prose intact.
 */
export function sanitizeUpstreamText(input: string): string {
  return input
    .replace(SENSITIVE_HEADER_LINE_REGEX, '$1: [REDACTED]')
    .replace(INLINE_AUTH_SCHEME_REGEX, '$1 [REDACTED]')
    .replace(JWT_REGEX, '[REDACTED]')
    .replace(QUERY_PARAM_SECRET_REGEX, '$1$2=[REDACTED]')
    .replace(ESCAPED_DOUBLE_QUOTED_VALUE_REGEX, '\\"$1\\"$2\\"[REDACTED]\\"')
    .replace(DOUBLE_QUOTED_VALUE_REGEX, '$1$2$1$3"[REDACTED]"')
    .replace(SINGLE_QUOTED_VALUE_REGEX, "$1$2$1$3'[REDACTED]'")
    .replace(AUTHORIZATION_SCHEME_KV_REGEX, '$1$2$1$3[REDACTED]')
    .replace(UNQUOTED_VALUE_REGEX, '$1$2$1$3[REDACTED]');
}

/** Configuration options for constructing a sanitized {@link UpstreamClientError}. */
export interface UpstreamClientErrorOptions {
  readonly message: string;
  readonly status: number;
  readonly pluginSlug: string;
  readonly upstreamEndpoint: string;
  readonly sanitizedBody?: string;
  readonly retryable?: boolean;
}

/**
 * Sanitized error boundary wrapping upstream HTTP failures without retaining
 * raw credentials or an unsanitized `cause`.
 */
export class UpstreamClientError extends Error {
  override readonly name = 'UpstreamClientError';
  readonly status: number;
  readonly pluginSlug: string;
  readonly upstreamEndpoint: string;
  readonly sanitizedBody?: string;
  readonly retryable: boolean;

  constructor(options: UpstreamClientErrorOptions) {
    super(sanitizeUpstreamText(options.message));
    this.status = options.status;
    this.pluginSlug = options.pluginSlug;
    this.upstreamEndpoint = sanitizeUpstreamText(options.upstreamEndpoint);
    if (options.sanitizedBody !== undefined) {
      this.sanitizedBody = sanitizeUpstreamText(options.sanitizedBody);
    }
    this.retryable =
      options.retryable ??
      (options.status === 408 || options.status === 429 || options.status >= 500);
  }
}
