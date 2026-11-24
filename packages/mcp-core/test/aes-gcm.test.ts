import { afterEach, describe, expect, expectTypeOf, it, vi } from 'vitest';
import {
  AES_GCM_AUTH_TAG_BIT_LENGTH,
  AES_GCM_AUTH_TAG_BYTE_LENGTH,
  AES_GCM_IV_BYTE_LENGTH,
  AES_GCM_KEY_BYTE_LENGTH,
  DEFAULT_ENCRYPTION_KEY_VERSION,
  EncryptionError,
  createAesGcmCipher,
  parseMasterKey,
} from '@mcphub/core';
import type {
  AesGcmCipherOptions,
  AesGcmOperationOptions,
  EncryptedPayload,
  EncryptionErrorCode,
  IAesGcmCipher,
  MasterKeyInput,
} from '@mcphub/core';

// Synthetic 32-byte test key material (contains bytes yielding +, /, -, _ in Base64/Base64url).
// Never a real secret.
const SYNTHETIC_KEY_BYTES = new Uint8Array([
  0xfb, 0xef, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76,
  0x54, 0x32, 0x10, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xfc,
]);
const SYNTHETIC_KEY_HEX_LOWER = 'fbefff0123456789abcdeffedcba98765432100f1e2d3c4b5a69788796a5b4fc';
const SYNTHETIC_KEY_HEX_UPPER = 'FBEFFF0123456789ABCDEFFEDCBA98765432100F1E2D3C4B5A69788796A5B4FC';
const SYNTHETIC_KEY_HEX_MIXED = 'FbEfFf0123456789aBcDeFfEdCbA98765432100f1E2d3C4b5A69788796a5B4fC';
const SYNTHETIC_KEY_BASE64URL = '--__ASNFZ4mrze_-3LqYdlQyEA8eLTxLWml4h5altPw';
const SYNTHETIC_KEY_BASE64_STD = '++//ASNFZ4mrze/+3LqYdlQyEA8eLTxLWml4h5altPw=';

const ALTERNATIVE_KEY_BYTES = new Uint8Array([
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
  0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
]);

const BASE64URL_REGEX = /^[A-Za-z0-9_-]*$/;

const SYNTHETIC_KEY_FORBIDDEN_STRINGS = [
  SYNTHETIC_KEY_HEX_LOWER,
  SYNTHETIC_KEY_HEX_UPPER,
  SYNTHETIC_KEY_HEX_MIXED,
  SYNTHETIC_KEY_BASE64URL,
  SYNTHETIC_KEY_BASE64_STD,
];

function encodeBase64UrlForTest(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    const byte = bytes[i];
    if (byte !== undefined) {
      binary += String.fromCharCode(byte);
    }
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}

function decodeBase64UrlForTest(encoded: string): Uint8Array {
  const paddedLength = encoded.length + ((4 - (encoded.length % 4)) % 4);
  const base64 = encoded.replace(/-/g, '+').replace(/_/g, '/').padEnd(paddedLength, '=');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function flipSingleBitInBase64Url(encoded: string, byteIndex = 0): string {
  const bytes = decodeBase64UrlForTest(encoded);
  const target = bytes[byteIndex];
  if (target === undefined) {
    throw new Error(`Expected byte at index ${byteIndex} in decoded test token`);
  }
  bytes[byteIndex] = target ^ 0x01;
  return encodeBase64UrlForTest(bytes);
}

async function captureThrownError(fn: () => unknown): Promise<unknown> {
  try {
    await fn();
  } catch (error: unknown) {
    return error;
  }
  throw new Error('Expected function to throw an error, but it succeeded');
}

function assertSafeEncryptionError(
  error: unknown,
  expectedCode: EncryptionErrorCode,
  forbiddenValues: readonly string[] = [],
): EncryptionError {
  expect(error).toBeInstanceOf(Error);
  expect(error).toBeInstanceOf(EncryptionError);

  if (!(error instanceof EncryptionError)) {
    throw new Error('Expected EncryptionError instance');
  }

  expect(error.name).toBe('EncryptionError');
  expect(error.code).toBe(expectedCode);
  expect('cause' in error).toBe(false);
  expect(error.cause).toBeUndefined();
  expect(error.message.length).toBeGreaterThan(0);

  const serialized = JSON.stringify(error);
  const lowerMessage = error.message.toLowerCase();
  const lowerSerialized = serialized.toLowerCase();

  for (const forbidden of [...SYNTHETIC_KEY_FORBIDDEN_STRINGS, ...forbiddenValues]) {
    if (forbidden.length === 0) {
      continue;
    }
    expect(error.message).not.toContain(forbidden);
    expect(serialized).not.toContain(forbidden);
    if (forbidden.length >= 8) {
      expect(lowerMessage).not.toContain(forbidden.toLowerCase());
      expect(lowerSerialized).not.toContain(forbidden.toLowerCase());
    }
  }

  return error;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('AES-256-GCM public constants, exports, and TypeScript contracts', () => {
  it('exports the canonical cryptographic constants', () => {
    expect(AES_GCM_KEY_BYTE_LENGTH).toBe(32);
    expect(AES_GCM_IV_BYTE_LENGTH).toBe(12);
    expect(AES_GCM_AUTH_TAG_BYTE_LENGTH).toBe(16);
    expect(AES_GCM_AUTH_TAG_BIT_LENGTH).toBe(128);
    expect(DEFAULT_ENCRYPTION_KEY_VERSION).toBe(1);
  });

  it('preserves exact public TypeScript types and function signatures', () => {
    expectTypeOf<MasterKeyInput>().toEqualTypeOf<string | Uint8Array>();
    expectTypeOf<EncryptionErrorCode>().toEqualTypeOf<
      | 'INVALID_MASTER_KEY'
      | 'INVALID_KEY_VERSION'
      | 'INVALID_PAYLOAD'
      | 'UNSUPPORTED_KEY_VERSION'
      | 'DECRYPTION_FAILED'
    >();
    expectTypeOf<AesGcmCipherOptions>().toEqualTypeOf<{
      readonly masterKey: MasterKeyInput;
      readonly keyVersion?: number;
    }>();
    expectTypeOf<AesGcmOperationOptions>().toEqualTypeOf<{
      readonly aad?: string;
    }>();
    expectTypeOf<EncryptedPayload>().toEqualTypeOf<{
      readonly ciphertext: string;
      readonly iv: string;
      readonly authTag: string;
      readonly keyVersion?: number;
    }>();
    expectTypeOf<IAesGcmCipher>().toEqualTypeOf<{
      readonly keyVersion: number;
      encrypt(plaintext: string, options?: AesGcmOperationOptions): Promise<EncryptedPayload>;
      decrypt(payload: EncryptedPayload, options?: AesGcmOperationOptions): Promise<string>;
      encryptJson(value: unknown, options?: AesGcmOperationOptions): Promise<EncryptedPayload>;
      decryptJson(payload: EncryptedPayload, options?: AesGcmOperationOptions): Promise<unknown>;
    }>();
    expectTypeOf<typeof parseMasterKey>().toEqualTypeOf<
      (input: MasterKeyInput) => Uint8Array<ArrayBuffer>
    >();
    expectTypeOf<typeof createAesGcmCipher>().toEqualTypeOf<
      (options: AesGcmCipherOptions) => Promise<IAesGcmCipher>
    >();
    expectTypeOf<EncryptionError>().toExtend<Error>();
    expectTypeOf<EncryptionError['code']>().toEqualTypeOf<EncryptionErrorCode>();
  });

  it('constructs EncryptionError without retaining a cause property', () => {
    const err = new EncryptionError('DECRYPTION_FAILED', 'Sanitized failure message');
    assertSafeEncryptionError(err, 'DECRYPTION_FAILED');
    expect(err.message).toBe('Sanitized failure message');
  });
});

describe('parseMasterKey & master key format contract', () => {
  it.each<[string, MasterKeyInput]>([
    ['raw 32-byte Uint8Array', SYNTHETIC_KEY_BYTES.slice()],
    ['64-char lowercase hex', SYNTHETIC_KEY_HEX_LOWER],
    ['64-char uppercase hex', SYNTHETIC_KEY_HEX_UPPER],
    ['64-char mixed-case hex', SYNTHETIC_KEY_HEX_MIXED],
    ['43-char unpadded Base64url', SYNTHETIC_KEY_BASE64URL],
    ['44-char padded standard Base64', SYNTHETIC_KEY_BASE64_STD],
  ])('accepts %s and decodes identical 32-byte ArrayBuffer-backed Uint8Array', (_label, input) => {
    const parsed = parseMasterKey(input);

    expect(parsed).toBeInstanceOf(Uint8Array);
    expect(parsed.buffer).toBeInstanceOf(ArrayBuffer);
    expect(parsed.byteLength).toBe(32);
    expect(parsed).toEqual(SYNTHETIC_KEY_BYTES);
  });

  it('reads exact 32-byte subarray slice when Uint8Array has non-zero byteOffset', () => {
    const backing = new Uint8Array(64).fill(0xaa);
    backing.set(SYNTHETIC_KEY_BYTES, 16);
    const subKey = backing.subarray(16, 48);

    const parsed = parseMasterKey(subKey);

    expect(parsed).toEqual(SYNTHETIC_KEY_BYTES);
    expect(parsed.buffer).not.toBe(backing.buffer);
    parsed.fill(0);
    expect(subKey).toEqual(SYNTHETIC_KEY_BYTES);
  });

  it('copies caller-supplied Uint8Array and never mutates it across parsing or cipher usage', async () => {
    const callerKey = SYNTHETIC_KEY_BYTES.slice();
    const parsed = parseMasterKey(callerKey);

    expect(parsed).not.toBe(callerKey);
    expect(parsed.buffer).not.toBe(callerKey.buffer);
    parsed.fill(0);
    expect(callerKey).toEqual(SYNTHETIC_KEY_BYTES);

    const cipher = await createAesGcmCipher({ masterKey: callerKey });
    expect(callerKey).toEqual(SYNTHETIC_KEY_BYTES);

    const sealed = await cipher.encrypt('synthetic-secret-value', { aad: 'user-1:fiainvest' });
    const opened = await cipher.decrypt(sealed, { aad: 'user-1:fiainvest' });
    expect(opened).toBe('synthetic-secret-value');
    expect(callerKey).toEqual(SYNTHETIC_KEY_BYTES);
  });

  it('cross-decrypts payloads across ciphers initialized from all valid master key formats', async () => {
    const ciphers = await Promise.all([
      createAesGcmCipher({ masterKey: SYNTHETIC_KEY_BYTES.slice() }),
      createAesGcmCipher({ masterKey: SYNTHETIC_KEY_HEX_LOWER }),
      createAesGcmCipher({ masterKey: SYNTHETIC_KEY_HEX_UPPER }),
      createAesGcmCipher({ masterKey: SYNTHETIC_KEY_BASE64URL }),
      createAesGcmCipher({ masterKey: SYNTHETIC_KEY_BASE64_STD }),
    ]);

    const secret = 'synthetic-cross-format-secret';
    const aad = 'user-42:fiainvest';

    for (const writer of ciphers) {
      const encrypted = await writer.encrypt(secret, { aad });
      for (const reader of ciphers) {
        await expect(reader.decrypt(encrypted, { aad })).resolves.toBe(secret);
      }
    }
  });

  it.each<[string, unknown]>([
    ['empty string', ''],
    ['empty Uint8Array', new Uint8Array(0)],
    ['leading space before hex', ` ${SYNTHETIC_KEY_HEX_LOWER}`],
    ['trailing space after hex', `${SYNTHETIC_KEY_HEX_LOWER} `],
    ['trailing newline after hex', `${SYNTHETIC_KEY_HEX_LOWER}\n`],
    ['leading tab before Base64url', `\t${SYNTHETIC_KEY_BASE64URL}`],
    ['trailing CRLF after Base64url', `${SYNTHETIC_KEY_BASE64URL}\r\n`],
    ['leading space before standard Base64', ` ${SYNTHETIC_KEY_BASE64_STD}`],
    [
      'embedded whitespace in 64-char string',
      `${SYNTHETIC_KEY_HEX_LOWER.slice(0, 31)} ${SYNTHETIC_KEY_HEX_LOWER.slice(32)}`,
    ],
    ['arbitrary short passphrase', 'correct-horse-battery-staple'],
    ['32-char ASCII passphrase', 'synthetic-ascii-passphrase-32b!!'],
    ['43-char non-encoding passphrase', 'synthetic-passphrase-with-43-chars-invalid!'],
    [
      '44-char non-encoding passphrase without equals',
      'synthetic-passphrase-with-44-chars-no-equals',
    ],
    [
      '64-char non-hex passphrase',
      'synthetic-passphrase-that-is-exactly-64-characters-long-non-hex!',
    ],
    ['31-byte Uint8Array', new Uint8Array(31).fill(0x11)],
    ['33-byte Uint8Array', new Uint8Array(33).fill(0x11)],
    ['62-char hex', SYNTHETIC_KEY_HEX_LOWER.slice(0, 62)],
    ['63-char hex', SYNTHETIC_KEY_HEX_LOWER.slice(0, 63)],
    ['65-char hex', `${SYNTHETIC_KEY_HEX_LOWER}0`],
    ['42-char unpadded Base64url', SYNTHETIC_KEY_BASE64URL.slice(0, 42)],
    ['44-char unpadded Base64url', `${SYNTHETIC_KEY_BASE64URL}A`],
    ['43-char standard Base64 missing =', SYNTHETIC_KEY_BASE64_STD.slice(0, 43)],
    ['44-char standard Base64 with ==', `${SYNTHETIC_KEY_BASE64_STD.slice(0, 42)}==`],
    ['+ inside 43-char string', `+${SYNTHETIC_KEY_BASE64URL.slice(1)}`],
    ['/ inside 43-char string', `/${SYNTHETIC_KEY_BASE64URL.slice(1)}`],
    ['= inside 43-char string', `${SYNTHETIC_KEY_BASE64URL.slice(0, 42)}=`],
    ['- inside 44-char =-padded string', `-${SYNTHETIC_KEY_BASE64_STD.slice(1)}`],
    ['_ inside 44-char =-padded string', `_${SYNTHETIC_KEY_BASE64_STD.slice(1)}`],
    ['non-hex lowercase letter in 64-char string', `g${SYNTHETIC_KEY_HEX_LOWER.slice(1)}`],
    ['non-hex uppercase letter in 64-char string', `Z${SYNTHETIC_KEY_HEX_UPPER.slice(1)}`],
    [
      'non-zero trailing bits (0b01) in 43-char Base64url',
      `${SYNTHETIC_KEY_BASE64URL.slice(0, 42)}x`,
    ],
    [
      'non-zero trailing bits (0b10) in 43-char Base64url',
      `${SYNTHETIC_KEY_BASE64URL.slice(0, 42)}y`,
    ],
    [
      'non-zero trailing bits (0b11) in 43-char Base64url',
      `${SYNTHETIC_KEY_BASE64URL.slice(0, 42)}z`,
    ],
    [
      'non-zero trailing bits (0b01) in 44-char Base64',
      `${SYNTHETIC_KEY_BASE64_STD.slice(0, 42)}x=`,
    ],
    [
      'non-zero trailing bits (0b10) in 44-char Base64',
      `${SYNTHETIC_KEY_BASE64_STD.slice(0, 42)}y=`,
    ],
    [
      'non-zero trailing bits (0b11) in 44-char Base64',
      `${SYNTHETIC_KEY_BASE64_STD.slice(0, 42)}z=`,
    ],
    ['all-zero 32-byte Uint8Array', new Uint8Array(32)],
    ['all-zero 64-char hex', '0'.repeat(64)],
    ['all-zero 43-char Base64url', 'A'.repeat(43)],
    ['all-zero 44-char padded Base64', `${'A'.repeat(43)}=`],
    ['null', null],
    ['undefined', undefined],
    ['number', 123456],
    ['boolean', true],
    ['plain object', { key: SYNTHETIC_KEY_HEX_LOWER }],
    ['number array', Array.from(SYNTHETIC_KEY_BYTES)],
    ['raw ArrayBuffer', SYNTHETIC_KEY_BYTES.slice().buffer],
    ['Uint16Array', new Uint16Array(16).fill(0x1234)],
    ['Int8Array', new Int8Array(32).fill(1)],
    ['DataView', new DataView(new ArrayBuffer(32))],
  ])('rejects invalid master key (%s) with non-leaking INVALID_MASTER_KEY', async (_label, bad) => {
    const forbidden = typeof bad === 'string' && bad.length >= 8 ? [bad] : [];

    const syncError = await captureThrownError(() => parseMasterKey(bad as MasterKeyInput));
    assertSafeEncryptionError(syncError, 'INVALID_MASTER_KEY', forbidden);

    const asyncError = await captureThrownError(() =>
      createAesGcmCipher({ masterKey: bad as MasterKeyInput }),
    );
    assertSafeEncryptionError(asyncError, 'INVALID_MASTER_KEY', forbidden);
  });
});

describe('createAesGcmCipher options, immutability, and key-wiping hygiene', () => {
  it('freezes the returned cipher instance and defaults keyVersion to 1', async () => {
    const cipher = await createAesGcmCipher({ masterKey: SYNTHETIC_KEY_HEX_LOWER });
    expect(Object.isFrozen(cipher)).toBe(true);
    expect(cipher.keyVersion).toBe(1);

    const cipherWithUndefinedVersion = await createAesGcmCipher({
      masterKey: SYNTHETIC_KEY_HEX_LOWER,
      keyVersion: undefined,
    });
    expect(cipherWithUndefinedVersion.keyVersion).toBe(1);
  });

  it.each<[string, unknown]>([
    ['0', 0],
    ['negative integer', -1],
    ['fractional number', 1.5],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
    ['unsafe integer above MAX_SAFE_INTEGER', Number.MAX_SAFE_INTEGER + 1],
    ['numeric string', '1'],
    ['null', null],
  ])(
    'rejects invalid keyVersion (%s) with INVALID_KEY_VERSION before parsing masterKey',
    async (_label, badKeyVersion) => {
      const invalidMasterKeySentinel = 'unparsed-invalid-master-key-sentinel';
      const err = await captureThrownError(() =>
        createAesGcmCipher({
          masterKey: invalidMasterKeySentinel,
          keyVersion: badKeyVersion as number,
        }),
      );

      assertSafeEncryptionError(err, 'INVALID_KEY_VERSION', [invalidMasterKeySentinel]);
    },
  );

  it('imports non-extractable CryptoKey and zero-fills transient keyBytes in finally on success', async () => {
    const callerKey = SYNTHETIC_KEY_BYTES.slice();
    const importKeySpy = vi.spyOn(crypto.subtle, 'importKey');

    try {
      const cipher = await createAesGcmCipher({ masterKey: callerKey });

      expect(importKeySpy).toHaveBeenCalledTimes(1);
      const callArgs = importKeySpy.mock.calls[0];
      expect(callArgs).toBeDefined();
      if (callArgs) {
        const [format, keyData, algorithm, extractable, keyUsages] = callArgs;
        expect(format).toBe('raw');
        expect(algorithm).toEqual({ name: 'AES-GCM', length: 256 });
        expect(extractable).toBe(false);
        expect(keyUsages).toEqual(['encrypt', 'decrypt']);
        expect(keyData).toBeInstanceOf(Uint8Array);
        if (keyData instanceof Uint8Array) {
          expect(keyData).not.toBe(callerKey);
          expect(keyData.buffer).not.toBe(callerKey.buffer);
          expect(keyData.byteLength).toBe(32);
          expect(keyData.every((byte) => byte === 0)).toBe(true);
        }
      }

      expect(callerKey).toEqual(SYNTHETIC_KEY_BYTES);
      const sealed = await cipher.encrypt('synthetic-hygiene-check');
      await expect(cipher.decrypt(sealed)).resolves.toBe('synthetic-hygiene-check');
    } finally {
      importKeySpy.mockRestore();
    }
  });

  it('zero-fills transient keyBytes in finally even when crypto.subtle.importKey rejects', async () => {
    const callerKey = SYNTHETIC_KEY_BYTES.slice();
    const importKeySpy = vi
      .spyOn(crypto.subtle, 'importKey')
      .mockRejectedValueOnce(new Error('Simulated Web Crypto importKey rejection'));

    try {
      await expect(createAesGcmCipher({ masterKey: callerKey })).rejects.toThrow(
        'Simulated Web Crypto importKey rejection',
      );

      expect(importKeySpy).toHaveBeenCalledTimes(1);
      const passedKeyData = importKeySpy.mock.calls[0]?.[1];
      expect(passedKeyData).toBeInstanceOf(Uint8Array);
      if (passedKeyData instanceof Uint8Array) {
        expect(passedKeyData).not.toBe(callerKey);
        expect(passedKeyData.buffer).not.toBe(callerKey.buffer);
        expect(passedKeyData.byteLength).toBe(32);
        expect(passedKeyData.every((byte) => byte === 0)).toBe(true);
      }

      expect(callerKey).toEqual(SYNTHETIC_KEY_BYTES);
    } finally {
      importKeySpy.mockRestore();
    }
  });
});

describe('encryption/decryption round-trips & Base64url wire format', () => {
  it('round-trips empty string with empty ciphertext, 16-char IV, and 22-char authTag', async () => {
    const cipher = await createAesGcmCipher({ masterKey: SYNTHETIC_KEY_HEX_LOWER });
    const payload = await cipher.encrypt('');

    expect(payload.ciphertext).toBe('');
    expect(payload.iv).toMatch(/^[A-Za-z0-9_-]{16}$/);
    expect(payload.authTag).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(payload.keyVersion).toBe(1);
    expect(decodeBase64UrlForTest(payload.iv).byteLength).toBe(12);
    expect(decodeBase64UrlForTest(payload.authTag).byteLength).toBe(16);

    await expect(cipher.decrypt(payload)).resolves.toBe('');
  });

  it.each<[string, string]>([
    ['1-byte plaintext', 'a'],
    ['2-byte plaintext', 'ab'],
    ['3-byte plaintext', 'abc'],
    ['ASCII plaintext', 'synthetic-api-token-value-12345'],
    ['multi-byte Unicode and emoji', 'Hello 🚀 café — π/Ω'],
    ['large >64 KB plaintext (128 KB)', 'abcd1234'.repeat(16 * 1024)],
  ])('round-trips %s with strict unpadded Base64url wire encoding', async (_label, plaintext) => {
    const cipher = await createAesGcmCipher({ masterKey: SYNTHETIC_KEY_BASE64URL });
    const payload = await cipher.encrypt(plaintext);

    expect(payload.ciphertext).toMatch(BASE64URL_REGEX);
    expect(payload.iv).toMatch(BASE64URL_REGEX);
    expect(payload.authTag).toMatch(BASE64URL_REGEX);
    expect(payload.ciphertext.includes('=')).toBe(false);
    expect(payload.iv.includes('=')).toBe(false);
    expect(payload.authTag.includes('=')).toBe(false);
    expect(decodeBase64UrlForTest(payload.iv).byteLength).toBe(12);
    expect(decodeBase64UrlForTest(payload.authTag).byteLength).toBe(16);
    expect(payload.keyVersion).toBe(1);

    await expect(cipher.decrypt(payload)).resolves.toBe(plaintext);
  });

  it('produces distinct random IVs and ciphertexts across repeated encryptions of identical inputs', async () => {
    const cipher = await createAesGcmCipher({ masterKey: SYNTHETIC_KEY_BYTES.slice() });
    const plaintext = 'synthetic-repeated-plaintext';
    const aad = 'user-1:fiainvest';

    const payloads: readonly EncryptedPayload[] = await Promise.all([
      cipher.encrypt(plaintext, { aad }),
      cipher.encrypt(plaintext, { aad }),
      cipher.encrypt(plaintext, { aad }),
      cipher.encrypt(plaintext, { aad }),
    ]);

    const uniqueIvs = new Set(payloads.map((item) => item.iv));
    const uniqueCiphertexts = new Set(payloads.map((item) => item.ciphertext));
    const uniqueTags = new Set(payloads.map((item) => item.authTag));

    expect(uniqueIvs.size).toBe(payloads.length);
    expect(uniqueCiphertexts.size).toBe(payloads.length);
    expect(uniqueTags.size).toBe(payloads.length);
  });

  it('rejects non-string plaintext and non-string options.aad at runtime with INVALID_PAYLOAD', async () => {
    const cipher = await createAesGcmCipher({ masterKey: SYNTHETIC_KEY_HEX_LOWER });
    const validPayload = await cipher.encrypt('synthetic-valid-plaintext');

    for (const badPlaintext of [null, undefined, 42, {}, new Uint8Array([1, 2, 3])]) {
      const err = await captureThrownError(() => cipher.encrypt(badPlaintext as unknown as string));
      assertSafeEncryptionError(err, 'INVALID_PAYLOAD');
    }

    for (const badAad of [123, null, {}, true]) {
      const encErr = await captureThrownError(() =>
        cipher.encrypt('synthetic-secret', { aad: badAad as unknown as string }),
      );
      assertSafeEncryptionError(encErr, 'INVALID_PAYLOAD', ['synthetic-secret']);

      const decErr = await captureThrownError(() =>
        cipher.decrypt(validPayload, { aad: badAad as unknown as string }),
      );
      assertSafeEncryptionError(decErr, 'INVALID_PAYLOAD', [
        validPayload.ciphertext,
        validPayload.iv,
        validPayload.authTag,
      ]);

      const encJsonErr = await captureThrownError(() =>
        cipher.encryptJson(
          { token: 'synthetic-json-secret' },
          { aad: badAad as unknown as string },
        ),
      );
      assertSafeEncryptionError(encJsonErr, 'INVALID_PAYLOAD', ['synthetic-json-secret']);

      const decJsonErr = await captureThrownError(() =>
        cipher.decryptJson(validPayload, { aad: badAad as unknown as string }),
      );
      assertSafeEncryptionError(decJsonErr, 'INVALID_PAYLOAD', [
        validPayload.ciphertext,
        validPayload.iv,
        validPayload.authTag,
      ]);
    }

    const explicitUndefinedAadPayload = await cipher.encrypt('synthetic-undefined-aad', {
      aad: undefined,
    });
    await expect(cipher.decrypt(explicitUndefinedAadPayload, { aad: undefined })).resolves.toBe(
      'synthetic-undefined-aad',
    );
  });
});

describe('AAD binding & NIST SP 800-38D empty AAD equivalence', () => {
  it('binds ciphertext to AAD and rejects mismatched, missing, or unexpected AAD', async () => {
    const cipher = await createAesGcmCipher({ masterKey: SYNTHETIC_KEY_HEX_LOWER });
    const secret = 'synthetic-tenant-credential-secret';
    const expectedAad = 'user-1:fiainvest';

    const sealedWithAad = await cipher.encrypt(secret, { aad: expectedAad });
    await expect(cipher.decrypt(sealedWithAad, { aad: expectedAad })).resolves.toBe(secret);

    for (const wrongAad of [undefined, 'user-2:fiainvest', 'user-1:other-plugin']) {
      const err = await captureThrownError(() =>
        cipher.decrypt(sealedWithAad, wrongAad === undefined ? undefined : { aad: wrongAad }),
      );
      assertSafeEncryptionError(err, 'DECRYPTION_FAILED', [
        secret,
        expectedAad,
        wrongAad ?? '',
        sealedWithAad.ciphertext,
        sealedWithAad.iv,
        sealedWithAad.authTag,
      ]);
    }

    const sealedWithoutAad = await cipher.encrypt(secret);
    const unexpectedAadErr = await captureThrownError(() =>
      cipher.decrypt(sealedWithoutAad, { aad: expectedAad }),
    );
    assertSafeEncryptionError(unexpectedAadErr, 'DECRYPTION_FAILED', [
      secret,
      expectedAad,
      sealedWithoutAad.ciphertext,
      sealedWithoutAad.iv,
      sealedWithoutAad.authTag,
    ]);
  });

  it('treats empty string AAD and undefined AAD identically per NIST SP 800-38D', async () => {
    const cipher = await createAesGcmCipher({ masterKey: SYNTHETIC_KEY_BASE64_STD });
    const secret = 'synthetic-empty-aad-equivalence-secret';

    const sealedWithEmptyAad = await cipher.encrypt(secret, { aad: '' });
    await expect(cipher.decrypt(sealedWithEmptyAad)).resolves.toBe(secret);
    await expect(cipher.decrypt(sealedWithEmptyAad, { aad: undefined })).resolves.toBe(secret);

    const sealedWithOmittedAad = await cipher.encrypt(secret);
    await expect(cipher.decrypt(sealedWithOmittedAad, { aad: '' })).resolves.toBe(secret);

    const sealedWithUndefinedAad = await cipher.encrypt(secret, { aad: undefined });
    await expect(cipher.decrypt(sealedWithUndefinedAad, { aad: '' })).resolves.toBe(secret);
  });
});

describe('tampering, wrong key, malformed Base64url, and payload envelope validation', () => {
  it('fails with non-leaking DECRYPTION_FAILED when ciphertext, iv, or authTag is bit-flipped', async () => {
    const cipher = await createAesGcmCipher({ masterKey: SYNTHETIC_KEY_HEX_LOWER });
    const secret = 'synthetic-tamper-check-secret';
    const aad = 'user-9:fiainvest';
    const valid = await cipher.encrypt(secret, { aad });

    const tamperedVariants: EncryptedPayload[] = [
      { ...valid, ciphertext: flipSingleBitInBase64Url(valid.ciphertext, 0) },
      { ...valid, iv: flipSingleBitInBase64Url(valid.iv, 0) },
      { ...valid, authTag: flipSingleBitInBase64Url(valid.authTag, 0) },
      { ...valid, authTag: flipSingleBitInBase64Url(valid.authTag, 15) },
    ];

    for (const tampered of tamperedVariants) {
      const err = await captureThrownError(() => cipher.decrypt(tampered, { aad }));
      assertSafeEncryptionError(err, 'DECRYPTION_FAILED', [
        secret,
        aad,
        valid.ciphertext,
        valid.iv,
        valid.authTag,
        tampered.ciphertext,
        tampered.iv,
        tampered.authTag,
      ]);
    }

    const emptyPayload = await cipher.encrypt('', { aad });
    const emptyTamperedTag: EncryptedPayload = {
      ...emptyPayload,
      authTag: flipSingleBitInBase64Url(emptyPayload.authTag, 0),
    };
    const emptyErr = await captureThrownError(() => cipher.decrypt(emptyTamperedTag, { aad }));
    assertSafeEncryptionError(emptyErr, 'DECRYPTION_FAILED', [
      aad,
      emptyTamperedTag.iv,
      emptyTamperedTag.authTag,
    ]);
  });

  it('fails with non-leaking DECRYPTION_FAILED when decrypted with a different master key', async () => {
    const writer = await createAesGcmCipher({ masterKey: SYNTHETIC_KEY_BYTES.slice() });
    const wrongReader = await createAesGcmCipher({ masterKey: ALTERNATIVE_KEY_BYTES.slice() });
    const secret = 'synthetic-wrong-key-secret';
    const payload = await writer.encrypt(secret);

    const err = await captureThrownError(() => wrongReader.decrypt(payload));
    assertSafeEncryptionError(err, 'DECRYPTION_FAILED', [
      secret,
      payload.ciphertext,
      payload.iv,
      payload.authTag,
    ]);
  });

  it('rejects malformed Base64url characters, impossible lengths, and non-zero trailing bits in ciphertext, iv, and authTag', async () => {
    const cipher = await createAesGcmCipher({ masterKey: SYNTHETIC_KEY_HEX_LOWER });
    const valid = await cipher.encrypt('synthetic-base64url-validation');

    const malformedIvCases = [
      `+${valid.iv.slice(1)}`,
      `/${valid.iv.slice(1)}`,
      `${valid.iv.slice(0, 15)}=`,
      ` ${valid.iv.slice(1)}`,
      `${valid.iv.slice(0, 15)}\n`,
      `é${valid.iv.slice(1)}`,
      'A'.repeat(17), // length % 4 === 1
      `${'A'.repeat(13)}B`, // length % 4 === 2 with non-zero trailing bits (0x01 & 0x0f !== 0)
      `${'A'.repeat(14)}B`, // length % 4 === 3 with non-zero trailing bits (0x01 & 0x03 !== 0)
    ];

    const malformedAuthTagCases = [
      `+${valid.authTag.slice(1)}`,
      `/${valid.authTag.slice(1)}`,
      `${valid.authTag.slice(0, 21)}=`,
      `\t${valid.authTag.slice(1)}`,
      `🚀${valid.authTag.slice(2)}`,
      'A'.repeat(21), // length % 4 === 1
      `${'A'.repeat(21)}B`, // exact 22-char length % 4 === 2 with non-zero trailing bits
      `${'A'.repeat(22)}B`, // length % 4 === 3 with non-zero trailing bits
    ];

    const malformedCiphertextCases = [
      '+AAA',
      '/AAA',
      'AAA=',
      'AA A',
      'AA\nA',
      'éAAA',
      'A', // length % 4 === 1
      'AAAAA', // length % 4 === 1
      'AB', // length % 4 === 2 with non-zero trailing bits (s1 = 1, 1 & 0x0f !== 0)
      'AAB', // length % 4 === 3 with non-zero trailing bits (s2 = 1, 1 & 0x03 !== 0)
    ];

    for (const badIv of malformedIvCases) {
      const err = await captureThrownError(() => cipher.decrypt({ ...valid, iv: badIv }));
      assertSafeEncryptionError(err, 'INVALID_PAYLOAD', [badIv, valid.ciphertext, valid.authTag]);
    }

    for (const badTag of malformedAuthTagCases) {
      const err = await captureThrownError(() => cipher.decrypt({ ...valid, authTag: badTag }));
      assertSafeEncryptionError(err, 'INVALID_PAYLOAD', [badTag, valid.ciphertext, valid.iv]);
    }

    for (const badCiphertext of malformedCiphertextCases) {
      const err = await captureThrownError(() =>
        cipher.decrypt({ ...valid, ciphertext: badCiphertext }),
      );
      const forbidden =
        badCiphertext.length >= 8
          ? [badCiphertext, valid.iv, valid.authTag]
          : [valid.iv, valid.authTag];
      assertSafeEncryptionError(err, 'INVALID_PAYLOAD', forbidden);
    }
  });

  it('rejects valid Base64url with wrong decoded byte lengths for iv or authTag', async () => {
    const cipher = await createAesGcmCipher({ masterKey: SYNTHETIC_KEY_HEX_LOWER });
    const valid = await cipher.encrypt('synthetic-length-check');

    const elevenByteIv = encodeBase64UrlForTest(new Uint8Array(11));
    const thirteenByteIv = encodeBase64UrlForTest(new Uint8Array(13));
    const fifteenByteTag = encodeBase64UrlForTest(new Uint8Array(15));
    const seventeenByteTag = encodeBase64UrlForTest(new Uint8Array(17));

    for (const invalidEnvelope of [
      { ...valid, iv: '' },
      { ...valid, iv: elevenByteIv },
      { ...valid, iv: thirteenByteIv },
      { ...valid, authTag: '' },
      { ...valid, authTag: fifteenByteTag },
      { ...valid, authTag: seventeenByteTag },
    ]) {
      const err = await captureThrownError(() => cipher.decrypt(invalidEnvelope));
      assertSafeEncryptionError(err, 'INVALID_PAYLOAD', [
        invalidEnvelope.ciphertext,
        invalidEnvelope.iv,
        invalidEnvelope.authTag,
      ]);
    }
  });

  it('rejects non-object, null, array, missing, or non-string envelope fields with INVALID_PAYLOAD', async () => {
    const cipher = await createAesGcmCipher({ masterKey: SYNTHETIC_KEY_HEX_LOWER });
    const valid = await cipher.encrypt('synthetic-shape-check');

    const malformedEnvelopes: unknown[] = [
      null,
      undefined,
      'serialized-envelope-string',
      42,
      [],
      { iv: valid.iv, authTag: valid.authTag },
      { ciphertext: valid.ciphertext, authTag: valid.authTag },
      { ciphertext: valid.ciphertext, iv: valid.iv },
      { ...valid, ciphertext: 123 },
      { ...valid, iv: null },
      { ...valid, authTag: {} },
    ];

    for (const badEnvelope of malformedEnvelopes) {
      const err = await captureThrownError(() => cipher.decrypt(badEnvelope as EncryptedPayload));
      assertSafeEncryptionError(err, 'INVALID_PAYLOAD');
    }
  });

  it('rejects valid AES-GCM ciphertext containing invalid UTF-8 byte sequences via fatal decoding', async () => {
    const cipher = await createAesGcmCipher({ masterKey: SYNTHETIC_KEY_BYTES.slice() });
    const iv = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    const invalidUtf8Plaintext = new Uint8Array([0xff, 0xfe, 0x80, 0xc3, 0x28]);

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      SYNTHETIC_KEY_BYTES,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt'],
    );
    const sealedBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      cryptoKey,
      invalidUtf8Plaintext,
    );
    const sealedBytes = new Uint8Array(sealedBuffer);
    const ciphertextBytes = sealedBytes.subarray(0, sealedBytes.byteLength - 16);
    const authTagBytes = sealedBytes.subarray(sealedBytes.byteLength - 16);

    const payload: EncryptedPayload = {
      ciphertext: encodeBase64UrlForTest(ciphertextBytes),
      iv: encodeBase64UrlForTest(iv),
      authTag: encodeBase64UrlForTest(authTagBytes),
      keyVersion: 1,
    };

    const err = await captureThrownError(() => cipher.decrypt(payload));
    assertSafeEncryptionError(err, 'DECRYPTION_FAILED', [
      payload.ciphertext,
      payload.iv,
      payload.authTag,
    ]);
  });
});

describe('keyVersion lifecycle handling', () => {
  it('stamps custom keyVersion and supports omitting keyVersion on decrypt', async () => {
    const cipherV2 = await createAesGcmCipher({
      masterKey: SYNTHETIC_KEY_HEX_LOWER,
      keyVersion: 2,
    });
    expect(cipherV2.keyVersion).toBe(2);

    const secret = 'synthetic-versioned-secret';
    const payload = await cipherV2.encrypt(secret);
    expect(payload.keyVersion).toBe(2);
    await expect(cipherV2.decrypt(payload)).resolves.toBe(secret);

    const unversionedPayload: EncryptedPayload = {
      ciphertext: payload.ciphertext,
      iv: payload.iv,
      authTag: payload.authTag,
    };
    await expect(cipherV2.decrypt(unversionedPayload)).resolves.toBe(secret);
    await expect(cipherV2.decrypt({ ...unversionedPayload, keyVersion: undefined })).resolves.toBe(
      secret,
    );

    const cipherV1 = await createAesGcmCipher({ masterKey: SYNTHETIC_KEY_HEX_LOWER });
    const v1Payload = await cipherV1.encrypt(secret);
    await expect(
      cipherV1.decrypt({
        ciphertext: v1Payload.ciphertext,
        iv: v1Payload.iv,
        authTag: v1Payload.authTag,
      }),
    ).resolves.toBe(secret);
  });

  it.each<unknown>([
    0,
    -1,
    1.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    Number.MAX_SAFE_INTEGER + 1,
    '1',
    null,
  ])('rejects malformed payload.keyVersion (%j) with INVALID_PAYLOAD', async (badVersion) => {
    const cipher = await createAesGcmCipher({ masterKey: SYNTHETIC_KEY_HEX_LOWER });
    const valid = await cipher.encrypt('synthetic-payload-version-check');
    const malformed: EncryptedPayload = {
      ...valid,
      keyVersion: badVersion as number,
    };

    const err = await captureThrownError(() => cipher.decrypt(malformed));
    assertSafeEncryptionError(err, 'INVALID_PAYLOAD', [valid.ciphertext, valid.iv, valid.authTag]);
  });

  it('rejects mismatched payload.keyVersion with UNSUPPORTED_KEY_VERSION', async () => {
    const cipherV1 = await createAesGcmCipher({
      masterKey: SYNTHETIC_KEY_HEX_LOWER,
      keyVersion: 1,
    });
    const cipherV2 = await createAesGcmCipher({
      masterKey: SYNTHETIC_KEY_HEX_LOWER,
      keyVersion: 2,
    });

    const payloadV2 = await cipherV2.encrypt('synthetic-v2-secret');
    const errOnV1 = await captureThrownError(() => cipherV1.decrypt(payloadV2));
    assertSafeEncryptionError(errOnV1, 'UNSUPPORTED_KEY_VERSION', [
      'synthetic-v2-secret',
      payloadV2.ciphertext,
      payloadV2.iv,
      payloadV2.authTag,
    ]);

    const payloadV1 = await cipherV1.encrypt('synthetic-v1-secret');
    const errOnV2 = await captureThrownError(() => cipherV2.decrypt(payloadV1));
    assertSafeEncryptionError(errOnV2, 'UNSUPPORTED_KEY_VERSION', [
      'synthetic-v1-secret',
      payloadV1.ciphertext,
      payloadV1.iv,
      payloadV1.authTag,
    ]);
  });
});

describe('encryptJson & decryptJson helpers', () => {
  it.each<[string, unknown]>([
    [
      'plain object',
      { accessToken: 'synthetic-oauth-token', expiresIn: 3600, nested: { enabled: true } },
    ],
    ['nested arrays', [1, ['two', { three: null, four: false }]]],
    ['string', 'synthetic-json-string'],
    ['number', 123.45],
    ['zero', 0],
    ['boolean true', true],
    ['boolean false', false],
    ['null', null],
  ])('round-trips JSON value (%s)', async (_label, value) => {
    const cipher = await createAesGcmCipher({
      masterKey: SYNTHETIC_KEY_BASE64URL,
      keyVersion: 3,
    });
    const aad = 'user-1:fiainvest';

    const payload = await cipher.encryptJson(value, { aad });
    expect(payload.keyVersion).toBe(3);

    const decrypted = await cipher.decryptJson(payload, { aad });
    expect(decrypted).toEqual(value);
  });

  it('rejects non-JSON-serializable values with INVALID_PAYLOAD without leaking values', async () => {
    const cipher = await createAesGcmCipher({ masterKey: SYNTHETIC_KEY_HEX_LOWER });
    const circular: Record<string, unknown> = { label: 'synthetic-circular-secret' };
    circular['self'] = circular;

    const nonSerializableValues: unknown[] = [
      undefined,
      () => 'synthetic-function-secret',
      Symbol('synthetic-symbol-secret'),
      BigInt('9007199254740993'),
      circular,
    ];

    for (const badValue of nonSerializableValues) {
      const err = await captureThrownError(() => cipher.encryptJson(badValue));
      const safeErr = assertSafeEncryptionError(err, 'INVALID_PAYLOAD', [
        'synthetic-circular-secret',
        'synthetic-function-secret',
        'synthetic-symbol-secret',
      ]);
      expect(safeErr.message).toBe('Value is not JSON-serializable');
    }
  });

  it('wraps JSON.parse failures on decrypted non-JSON plaintext without leaking plaintext snippets', async () => {
    const cipher = await createAesGcmCipher({ masterKey: SYNTHETIC_KEY_HEX_LOWER });
    const sentinel = 'not-valid-json-sentinel-secret-9f8e7d';
    const payload = await cipher.encrypt(sentinel, { aad: 'user-7:fiainvest' });

    const err = await captureThrownError(() =>
      cipher.decryptJson(payload, { aad: 'user-7:fiainvest' }),
    );
    const safeErr = assertSafeEncryptionError(err, 'INVALID_PAYLOAD', [
      sentinel,
      'sentinel',
      '9f8e7d',
      payload.ciphertext,
      payload.iv,
      payload.authTag,
      'user-7:fiainvest',
    ]);
    expect(safeErr.message).toBe('Decrypted payload is not valid JSON');
  });

  it('propagates DECRYPTION_FAILED from decryptJson when authentication fails', async () => {
    const cipher = await createAesGcmCipher({ masterKey: SYNTHETIC_KEY_HEX_LOWER });
    const payload = await cipher.encryptJson(
      { secret: 'synthetic-json-aad-secret' },
      { aad: 'user-1:fiainvest' },
    );

    const err = await captureThrownError(() =>
      cipher.decryptJson(payload, { aad: 'user-2:fiainvest' }),
    );
    assertSafeEncryptionError(err, 'DECRYPTION_FAILED', [
      'synthetic-json-aad-secret',
      'user-1:fiainvest',
      'user-2:fiainvest',
      payload.ciphertext,
      payload.iv,
      payload.authTag,
    ]);
  });
});
