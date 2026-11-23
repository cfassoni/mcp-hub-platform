import { describe, expect, it } from 'vitest';
import {
  UpstreamClientError,
  sanitizeUpstreamText,
  type UpstreamClientErrorOptions,
} from '@mcphub/core';

// Synthetic dummy test fixtures (never real credentials)
const DUMMY_JWT = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJkdW1teS10ZXN0LXVzZXIifQ.dummySigSegment_01-23';
const DUMMY_JWT_EMPTY_SIG = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJkdW1teS11c2VyIn0.';
const DUMMY_JWE = 'eyJhbGciOiJkaXIifQ..dummy-iv.dummy-cipher.dummy-tag';

describe('sanitizeUpstreamText', () => {
  it('redacts multiline sensitive HTTP header lines case-insensitively while preserving safe lines', () => {
    const rawHttpDump = [
      'HTTP/1.1 401 Unauthorized',
      'Authorization: Bearer dummy-header-bearer-token',
      'proxy-authorization: Basic ZHVtbXk6ZHVtbXk=',
      'Cookie: mcphub_session=dummy-cookie-value; theme=dark',
      'set-cookie: sid=dummy-set-cookie-value; HttpOnly; Secure',
      'X-Api-Key: dummy-x-api-key-value',
      'Content-Type: application/json',
    ].join('\n');

    const sanitized = sanitizeUpstreamText(rawHttpDump);

    expect(sanitized).toContain('HTTP/1.1 401 Unauthorized');
    expect(sanitized).toContain('Content-Type: application/json');
    expect(sanitized).toContain('Authorization: [REDACTED]');
    expect(sanitized).toMatch(/proxy-authorization:\s*\[REDACTED\]/i);
    expect(sanitized).toContain('Cookie: [REDACTED]');
    expect(sanitized).toMatch(/set-cookie:\s*\[REDACTED\]/i);
    expect(sanitized).toContain('X-Api-Key: [REDACTED]');

    expect(sanitized).not.toContain('dummy-header-bearer-token');
    expect(sanitized).not.toContain('ZHVtbXk6ZHVtbXk=');
    expect(sanitized).not.toContain('dummy-cookie-value');
    expect(sanitized).not.toContain('dummy-set-cookie-value');
    expect(sanitized).not.toContain('dummy-x-api-key-value');
  });

  it('redacts inline Bearer and Basic scheme credentials case-insensitively', () => {
    const raw =
      'Rejected upstream call using Bearer dummy-bearer-001 and basic ZHVtbXk6c2VjcmV0 with bearer dummy-bearer-002';

    const sanitized = sanitizeUpstreamText(raw);

    expect(sanitized).toBe(
      'Rejected upstream call using Bearer [REDACTED] and basic [REDACTED] with bearer [REDACTED]',
    );
    expect(sanitized).not.toContain('dummy-bearer-001');
    expect(sanitized).not.toContain('ZHVtbXk6c2VjcmV0');
    expect(sanitized).not.toContain('dummy-bearer-002');
  });

  it('redacts 3-segment JWT and 5-segment JWE tokens', () => {
    const raw = `Upstream rejected token ${DUMMY_JWT}, legacy token ${DUMMY_JWT_EMPTY_SIG}, and encrypted token ${DUMMY_JWE} during sync`;

    const sanitized = sanitizeUpstreamText(raw);

    expect(sanitized).toBe(
      'Upstream rejected token [REDACTED], legacy token [REDACTED], and encrypted token [REDACTED] during sync',
    );
    expect(sanitized).not.toContain('eyJhbGciOiJub25lIn0');
    expect(sanitized).not.toContain('eyJhbGciOiJkaXIifQ');
    expect(sanitized).not.toContain('dummySigSegment_01-23');
    expect(sanitized).not.toContain('dummy-');
  });

  it('redacts indented multiline HTTP headers', () => {
    const rawIndentedHeaders = [
      '  Cookie: theme=dark; sid=dummy-indented-cookie',
      '  X-Api-Key: dummy-part1 dummy-part2',
    ].join('\n');

    const sanitizedHeaders = sanitizeUpstreamText(rawIndentedHeaders);

    expect(sanitizedHeaders).toMatch(/^\s*Cookie:\s*\[REDACTED\]$/m);
    expect(sanitizedHeaders).toMatch(/^\s*X-Api-Key:\s*\[REDACTED\]$/m);
    expect(sanitizedHeaders).not.toContain('dummy-');
  });

  it('redacts non-Bearer/Basic authorization schemes in headers and KV pairs', () => {
    expect(sanitizeUpstreamText('Authorization: Token dummy-tok-auth')).toBe(
      'Authorization: [REDACTED]',
    );
    expect(sanitizeUpstreamText('Authorization: Digest dummy-digest-auth')).toBe(
      'Authorization: [REDACTED]',
    );

    const sanitizedKvAuth = sanitizeUpstreamText('authorization=ApiKey dummy-apikey-auth');
    expect(sanitizedKvAuth).toMatch(/^authorization=(?:ApiKey\s+)?\[REDACTED\]$/i);
    expect(sanitizedKvAuth).not.toContain('dummy-');
  });

  it('redacts quoted URL query parameter values while preserving non-sensitive parameters', () => {
    const rawUrl =
      'https://api.example.test/v1?api_key="dummy-q-quoted"&token=\'dummy-q-single\'&symbol=PETR4';

    const sanitized = sanitizeUpstreamText(rawUrl);

    expect(sanitized).toMatch(
      /^https:\/\/api\.example\.test\/v1\?api_key=(?:"\[REDACTED\]"|\[REDACTED\])&token=(?:'\[REDACTED\]'|"\[REDACTED\]"|\[REDACTED\])&symbol=PETR4$/,
    );
    expect(sanitized).toContain('&symbol=PETR4');
    expect(sanitized).not.toContain('dummy-q-quoted');
    expect(sanitized).not.toContain('dummy-q-single');
    expect(sanitized).not.toContain('dummy-');
  });

  it('redacts quoted URL query parameters embedded in JSON', () => {
    const rawSingleInJson =
      '{"url":"https://api.example.test/v1?api_key=\'dummy-q-in-json\'&symbol=PETR4"}';
    const sanitizedSingleInJson = sanitizeUpstreamText(rawSingleInJson);
    expect(sanitizedSingleInJson).not.toContain('dummy-q-in-json');
    const parsedSingle: unknown = JSON.parse(sanitizedSingleInJson);
    expect(parsedSingle).toEqual({
      url: 'https://api.example.test/v1?api_key=[REDACTED]&symbol=PETR4',
    });
  });

  it('redacts escaped-quote URL query parameters embedded in JSON', () => {
    const rawEscapedInJson = JSON.stringify({
      url: 'https://api.example.test/v1?api_key="dummy-q-escaped"&symbol=PETR4',
    });
    const sanitizedEscapedInJson = sanitizeUpstreamText(rawEscapedInJson);
    expect(sanitizedEscapedInJson).not.toContain('dummy-q-escaped');
    const parsedEscaped: unknown = JSON.parse(sanitizedEscapedInJson);
    const escapedUrl =
      typeof parsedEscaped === 'object' && parsedEscaped !== null && 'url' in parsedEscaped
        ? parsedEscaped.url
        : undefined;
    expect(typeof escapedUrl).toBe('string');
    expect(escapedUrl).toMatch(
      /^https:\/\/api\.example\.test\/v1\?api_key=(?:"\[REDACTED\]"|\[REDACTED\])&symbol=PETR4$/,
    );
  });

  it('redacts quoted URL query parameters while keeping trailing punctuation intact', () => {
    const rawTrailingPunct =
      'See https://api.example.test/v1?api_key="dummy-q-comma", and symbol=PETR4;';
    const sanitizedTrailingPunct = sanitizeUpstreamText(rawTrailingPunct);
    expect(sanitizedTrailingPunct).not.toContain('dummy-q-comma');
    expect(sanitizedTrailingPunct).toMatch(
      /^See https:\/\/api\.example\.test\/v1\?api_key=(?:"\[REDACTED\]"|\[REDACTED\]), and symbol=PETR4;$/,
    );
  });

  it('redacts escaped JSON-inside-JSON payloads without leaking nested credentials', () => {
    const rawNested = JSON.stringify({
      body: JSON.stringify({
        password: 'dummy-nested-pw',
        access_token: 'dummy-nested-at',
        client_secret: 'dummy-nested-cs',
        symbol: 'PETR4',
      }),
    });

    const sanitized = sanitizeUpstreamText(rawNested);

    expect(sanitized).not.toContain('dummy-nested-');
    const parsed: unknown = JSON.parse(sanitized);
    const bodyValue =
      typeof parsed === 'object' && parsed !== null && 'body' in parsed ? parsed.body : undefined;
    expect(typeof bodyValue).toBe('string');

    if (typeof bodyValue === 'string') {
      const nested: unknown = JSON.parse(bodyValue);
      expect(nested).toEqual({
        password: '[REDACTED]',
        access_token: '[REDACTED]',
        client_secret: '[REDACTED]',
        symbol: 'PETR4',
      });
    }
  });

  it('redacts escaped inner quotes and trailing escaped backslashes inside serialized JSON-in-JSON', () => {
    const rawNestedEscaped = JSON.stringify({
      body: JSON.stringify({
        password: 'my "dummy-inner-quote" pass',
        secret: 'trailing-bs\\',
        symbol: 'PETR4',
      }),
    });

    const sanitized = sanitizeUpstreamText(rawNestedEscaped);

    expect(sanitized).not.toContain('dummy-inner-quote');
    expect(sanitized).not.toContain('trailing-bs');
    expect(sanitizeUpstreamText(sanitized)).toBe(sanitized);

    const parsed: unknown = JSON.parse(sanitized);
    const bodyValue =
      typeof parsed === 'object' && parsed !== null && 'body' in parsed ? parsed.body : undefined;
    expect(typeof bodyValue).toBe('string');

    if (typeof bodyValue === 'string') {
      const nested: unknown = JSON.parse(bodyValue);
      expect(nested).toEqual({
        password: '[REDACTED]',
        secret: '[REDACTED]',
        symbol: 'PETR4',
      });
    }
  });

  it('redacts compound secret_key and secretKey names across JSON, query params, and inline KVs', () => {
    const rawJson = JSON.stringify({
      secret_key: 'dummy-json-sk1',
      secretKey: 'dummy-json-sk2',
      client_secret_key: 'dummy-json-sk3',
      jwt_secret_key: 'dummy-json-sk4',
      symbol: 'PETR4',
    });
    const sanitizedJson = sanitizeUpstreamText(rawJson);
    expect(sanitizedJson).not.toContain('dummy-');
    expect(JSON.parse(sanitizedJson)).toEqual({
      secret_key: '[REDACTED]',
      secretKey: '[REDACTED]',
      client_secret_key: '[REDACTED]',
      jwt_secret_key: '[REDACTED]',
      symbol: 'PETR4',
    });

    const rawQuery =
      'https://api.example.test/v1/auth?secret_key=dummy-q-sk1&secretKey=dummy-q-sk2&client_secret_key=dummy-q-sk3&jwt_secret_key=dummy-q-sk4&symbol=PETR4';
    const sanitizedQuery = sanitizeUpstreamText(rawQuery);
    expect(sanitizedQuery).toBe(
      'https://api.example.test/v1/auth?secret_key=[REDACTED]&secretKey=[REDACTED]&client_secret_key=[REDACTED]&jwt_secret_key=[REDACTED]&symbol=PETR4',
    );
    expect(sanitizedQuery).not.toContain('dummy-');

    const rawKv =
      'secret_key=dummy-kv-sk1 secretKey=dummy-kv-sk2 client_secret_key="dummy-kv-sk3" jwt_secret_key: dummy-kv-sk4 symbol=PETR4';
    const sanitizedKv = sanitizeUpstreamText(rawKv);
    expect(sanitizedKv).toContain('secret_key=[REDACTED]');
    expect(sanitizedKv).toContain('secretKey=[REDACTED]');
    expect(sanitizedKv).toContain('client_secret_key="[REDACTED]"');
    expect(sanitizedKv).toMatch(/\bjwt_secret_key:\s*\[REDACTED\]/);
    expect(sanitizedKv).toContain('symbol=PETR4');
    expect(sanitizedKv).not.toContain('dummy-');
  });

  it('redacts sensitive URL query parameters while preserving non-sensitive parameters', () => {
    const rawUrl =
      'https://api.example.test/v1/quote?api_key=dummy-q-ak&symbol=PETR4&refresh_token=dummy-q-rt&access_token=dummy-q-at&token=dummy-q-tok&secret=dummy-q-sec';

    const sanitized = sanitizeUpstreamText(rawUrl);

    expect(sanitized).toBe(
      'https://api.example.test/v1/quote?api_key=[REDACTED]&symbol=PETR4&refresh_token=[REDACTED]&access_token=[REDACTED]&token=[REDACTED]&secret=[REDACTED]',
    );
    expect(sanitized).toContain('&symbol=PETR4&');
  });

  it('redacts all sensitive keys in JSON payloads while keeping non-sensitive fields and valid JSON', () => {
    const rawJson = JSON.stringify({
      password: 'dummy-json-password',
      token: 'dummy-json-token',
      access: 'dummy-json-access',
      refresh: 'dummy-json-refresh',
      secret: 'dummy-json-secret',
      authorization: 'Bearer dummy-json-auth',
      cookie: 'dummy-json-cookie',
      api_key: 'dummy-json-api-key',
      apiKey: 'dummy-json-apiKey',
      access_token: 'dummy-json-access-token',
      accessToken: 'dummy-json-accessToken',
      refresh_token: 'dummy-json-refresh-token',
      refreshToken: 'dummy-json-refreshToken',
      client_secret: 'dummy-json-client-secret',
      'x-api-key': 'dummy-json-x-api-key',
      'set-cookie': 'dummy-json-set-cookie',
      symbol: 'PETR4',
    });

    const sanitized = sanitizeUpstreamText(rawJson);
    const parsed: unknown = JSON.parse(sanitized);

    expect(parsed).toEqual({
      password: '[REDACTED]',
      token: '[REDACTED]',
      access: '[REDACTED]',
      refresh: '[REDACTED]',
      secret: '[REDACTED]',
      authorization: '[REDACTED]',
      cookie: '[REDACTED]',
      api_key: '[REDACTED]',
      apiKey: '[REDACTED]',
      access_token: '[REDACTED]',
      accessToken: '[REDACTED]',
      refresh_token: '[REDACTED]',
      refreshToken: '[REDACTED]',
      client_secret: '[REDACTED]',
      'x-api-key': '[REDACTED]',
      'set-cookie': '[REDACTED]',
      symbol: 'PETR4',
    });
  });

  it('redacts unquoted and quoted inline key=value and key: value pairs case-insensitively', () => {
    const rawInline = [
      'password=dummy-unq-pw',
      'token=dummy-unq-tok',
      'access=dummy-unq-acc',
      'refresh=dummy-unq-ref',
      'secret: dummy-unq-sec',
      'authorization: dummy-unq-auth',
      'cookie: dummy-unq-cookie',
      'api_key=dummy-unq-ak1',
      'apiKey=dummy-unq-ak2',
      'access_token=dummy-unq-at1',
      'accessToken=dummy-unq-at2',
      'refresh_token=dummy-unq-rt1',
      'refreshToken=dummy-unq-rt2',
      'client_secret="dummy-quoted-cs"',
      "x-api-key='dummy-single-xak'",
      'set-cookie=dummy-unq-sc',
      'PASSWORD=dummy-upper-pw',
      'symbol=PETR4',
    ].join(' ');

    const sanitized = sanitizeUpstreamText(rawInline);

    expect(sanitized).toContain('symbol=PETR4');
    expect(sanitized).toContain('password=[REDACTED]');
    expect(sanitized).toContain('token=[REDACTED]');
    expect(sanitized).toContain('access=[REDACTED]');
    expect(sanitized).toContain('refresh=[REDACTED]');
    expect(sanitized).toMatch(/\bsecret:\s*\[REDACTED\]/);
    expect(sanitized).toMatch(/\bauthorization:\s*\[REDACTED\]/);
    expect(sanitized).toMatch(/\bcookie:\s*\[REDACTED\]/);
    expect(sanitized).toContain('api_key=[REDACTED]');
    expect(sanitized).toContain('apiKey=[REDACTED]');
    expect(sanitized).toContain('access_token=[REDACTED]');
    expect(sanitized).toContain('accessToken=[REDACTED]');
    expect(sanitized).toContain('refresh_token=[REDACTED]');
    expect(sanitized).toContain('refreshToken=[REDACTED]');
    expect(sanitized).toContain('client_secret="[REDACTED]"');
    expect(sanitized).toMatch(/x-api-key=['"]\[REDACTED\]['"]/);
    expect(sanitized).toContain('set-cookie=[REDACTED]');
    expect(sanitized).toContain('PASSWORD=[REDACTED]');
    expect(sanitized).not.toContain('dummy-');
  });

  it('is idempotent across all credential patterns', () => {
    const samples = [
      `Authorization: Bearer ${DUMMY_JWT}\nX-Api-Key: dummy-key`,
      `  Cookie: theme=dark; sid=dummy-indented-cookie\n  X-Api-Key: dummy-part1 dummy-part2\nAuthorization: Token dummy-tok-auth`,
      'https://api.example.test/v1/data?api_key=dummy-k&symbol=PETR4&refresh_token=dummy-r',
      'https://api.example.test/v1?api_key="dummy-q-quoted"&token=\'dummy-q-single\'&symbol=PETR4',
      '{"url":"https://api.example.test/v1?api_key=\'dummy-q-in-json\'&symbol=PETR4"}',
      JSON.stringify({
        url: 'https://api.example.test/v1?api_key="dummy-q-escaped"&symbol=PETR4',
      }),
      'See https://api.example.test/v1?api_key="dummy-q-comma", and symbol=PETR4;',
      '{"accessToken":"dummy-at","client_secret":"dummy-cs","secret_key":"dummy-sk","symbol":"PETR4"}',
      JSON.stringify({
        body: JSON.stringify({
          password: 'dummy-nested-pw',
          access_token: 'dummy-nested-at',
          client_secret: 'dummy-nested-cs',
          symbol: 'PETR4',
        }),
      }),
      JSON.stringify({
        body: JSON.stringify({
          password: 'my "dummy-inner-quote" pass',
          secret: 'trailing-bs\\',
          symbol: 'PETR4',
        }),
      }),
      `Failed with Basic ZHVtbXk6ZHVtbXk=, ${DUMMY_JWE}, and secretKey=dummy-sk`,
    ];

    for (const sample of samples) {
      const once = sanitizeUpstreamText(sample);
      const twice = sanitizeUpstreamText(once);
      expect(twice).toBe(once);
    }
  });

  it('preserves ordinary diagnostic prose without over-redacting', () => {
    expect(sanitizeUpstreamText('Invalid token expired')).toBe('Invalid token expired');
    expect(sanitizeUpstreamText('Unauthorized access')).toBe('Unauthorized access');
    expect(sanitizeUpstreamText('Upstream returned 404 for symbol PETR4')).toBe(
      'Upstream returned 404 for symbol PETR4',
    );
  });
});

describe('UpstreamClientError', () => {
  it('constructs an Error subclass named UpstreamClientError and sanitizes text fields', () => {
    const options: UpstreamClientErrorOptions = {
      message: `Upstream failed with Bearer dummy-msg-secret and ${DUMMY_JWT}`,
      status: 502,
      pluginSlug: 'fiainvest',
      upstreamEndpoint:
        'https://api.example.test/v1/portfolio?api_key=dummy-url-key&symbol=PETR4&refresh_token=dummy-url-rt',
      sanitizedBody: '{"access_token":"dummy-body-at","error":"Bad Gateway"}',
    };

    const err = new UpstreamClientError(options);

    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(UpstreamClientError);
    expect(err.name).toBe('UpstreamClientError');
    expect(err.status).toBe(502);
    expect(err.pluginSlug).toBe('fiainvest');
    expect(err.message).toBe('Upstream failed with Bearer [REDACTED] and [REDACTED]');
    expect(err.upstreamEndpoint).toBe(
      'https://api.example.test/v1/portfolio?api_key=[REDACTED]&symbol=PETR4&refresh_token=[REDACTED]',
    );
    expect(err.sanitizedBody).toBe('{"access_token":"[REDACTED]","error":"Bad Gateway"}');
    expect(err.message).not.toContain('dummy-msg-secret');
    expect(err.upstreamEndpoint).not.toContain('dummy-url-key');
    expect(err.sanitizedBody).not.toContain('dummy-body-at');
  });

  it('preserves sanitizedBody as undefined when omitted', () => {
    const err = new UpstreamClientError({
      message: 'Gateway timeout',
      status: 504,
      pluginSlug: 'fiainvest',
      upstreamEndpoint: 'https://api.example.test/v1/quotes',
    });

    expect(err.sanitizedBody).toBeUndefined();
  });

  it.each([
    [408, true],
    [429, true],
    [500, true],
    [503, true],
    [400, false],
    [401, false],
    [404, false],
  ])('for HTTP status %i, computes default retryable=%s', (status, expectedRetryable) => {
    const err = new UpstreamClientError({
      message: 'Upstream response error',
      status,
      pluginSlug: 'fiainvest',
      upstreamEndpoint: 'https://api.example.test/v1/quotes',
    });

    expect(err.retryable).toBe(expectedRetryable);
  });

  it('honors explicit retryable boolean overrides', () => {
    const nonRetryable500 = new UpstreamClientError({
      message: 'Fatal upstream misconfiguration',
      status: 500,
      pluginSlug: 'fiainvest',
      upstreamEndpoint: 'https://api.example.test/v1/quotes',
      retryable: false,
    });
    const retryable400 = new UpstreamClientError({
      message: 'Transient bad request state',
      status: 400,
      pluginSlug: 'fiainvest',
      upstreamEndpoint: 'https://api.example.test/v1/quotes',
      retryable: true,
    });

    expect(nonRetryable500.retryable).toBe(false);
    expect(retryable400.retryable).toBe(true);
  });

  it('does not retain an unsanitized cause property', () => {
    const err = new UpstreamClientError({
      message: 'Upstream rejected request',
      status: 401,
      pluginSlug: 'fiainvest',
      upstreamEndpoint: 'https://api.example.test/v1/auth',
    });

    expect('cause' in err).toBe(false);
    expect(err.cause).toBeUndefined();
  });

  it('does not throw a secondary slug-validation error for empty or unusual pluginSlug values', () => {
    const emptySlugErr = new UpstreamClientError({
      message: 'Upstream error',
      status: 502,
      pluginSlug: '',
      upstreamEndpoint: 'https://api.example.test/v1/health',
    });
    const unusualSlugErr = new UpstreamClientError({
      message: 'Upstream error',
      status: 503,
      pluginSlug: '../Invalid_Slug!',
      upstreamEndpoint: 'https://api.example.test/v1/health',
    });

    expect(emptySlugErr.pluginSlug).toBe('');
    expect(unusualSlugErr.pluginSlug).toBe('../Invalid_Slug!');
  });
});
