import type { EncryptedPayload } from '../contracts/storage.js';
import { decodeBase64Url, encodeBase64Url } from './base64url.js';

/** Required AES-256 key byte length (256 bits). */
export const AES_GCM_KEY_BYTE_LENGTH = 32;

/** Required AES-GCM initialization vector byte length (96 bits). */
export const AES_GCM_IV_BYTE_LENGTH = 12;

/** Required AES-GCM authentication tag byte length (128 bits). */
export const AES_GCM_AUTH_TAG_BYTE_LENGTH = 16;

/** Required AES-GCM authentication tag bit length passed to Web Crypto. */
export const AES_GCM_AUTH_TAG_BIT_LENGTH = 128;

/** Default active key version stamped on newly encrypted payloads. */
export const DEFAULT_ENCRYPTION_KEY_VERSION = 1;

/** Accepted master key input representations (raw 32-byte Uint8Array or encoded string). */
export type MasterKeyInput = string | Uint8Array;

/** Discriminated machine-readable failure codes emitted by {@link EncryptionError}. */
export type EncryptionErrorCode =
  | 'INVALID_MASTER_KEY'
  | 'INVALID_KEY_VERSION'
  | 'INVALID_PAYLOAD'
  | 'UNSUPPORTED_KEY_VERSION'
  | 'DECRYPTION_FAILED';

/** Configuration options for instantiating an AES-256-GCM cipher via {@link createAesGcmCipher}. */
export interface AesGcmCipherOptions {
  readonly masterKey: MasterKeyInput;
  readonly keyVersion?: number;
}

/** Optional per-operation cryptographic context parameters. */
export interface AesGcmOperationOptions {
  readonly aad?: string;
}

/** Immutable Web Crypto AES-256-GCM sealing and opening cipher instance. */
export interface IAesGcmCipher {
  readonly keyVersion: number;
  encrypt(plaintext: string, options?: AesGcmOperationOptions): Promise<EncryptedPayload>;
  decrypt(payload: EncryptedPayload, options?: AesGcmOperationOptions): Promise<string>;
  encryptJson(value: unknown, options?: AesGcmOperationOptions): Promise<EncryptedPayload>;
  decryptJson(payload: EncryptedPayload, options?: AesGcmOperationOptions): Promise<unknown>;
}

/**
 * Zero-leakage error boundary for key parsing, payload validation, and AES-256-GCM failures.
 * Never retains a `cause` property and never echoes keys, plaintext, ciphertext, IV, tag, or AAD.
 */
export class EncryptionError extends Error {
  override readonly name = 'EncryptionError';
  readonly code: EncryptionErrorCode;

  constructor(code: EncryptionErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

const HEX_MASTER_KEY_REGEX = /^[0-9a-fA-F]{64}$/;
const BASE64URL_MASTER_KEY_REGEX = /^[A-Za-z0-9_-]{43}$/;
const STANDARD_BASE64_MASTER_KEY_REGEX = /^[A-Za-z0-9+/]{43}=$/;

const INVALID_MASTER_KEY_MESSAGE =
  'Master key must be a non-zero 32-byte Uint8Array, 64-char hex, 43-char Base64url, or 44-char Base64 key';

const textEncoder = new TextEncoder();
const fatalUtf8Decoder = new TextDecoder('utf-8', { fatal: true });

function isValidKeyVersion(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1;
}

function decodeMasterKeyString(input: string): Uint8Array<ArrayBuffer> {
  if (HEX_MASTER_KEY_REGEX.test(input)) {
    const keyBytes = new Uint8Array(AES_GCM_KEY_BYTE_LENGTH);
    for (let i = 0; i < AES_GCM_KEY_BYTE_LENGTH; i += 1) {
      keyBytes[i] = Number.parseInt(input.slice(i * 2, i * 2 + 2), 16);
    }
    return keyBytes;
  }

  let base64urlCandidate: string | null = null;
  if (BASE64URL_MASTER_KEY_REGEX.test(input)) {
    base64urlCandidate = input;
  } else if (STANDARD_BASE64_MASTER_KEY_REGEX.test(input)) {
    base64urlCandidate = input.slice(0, 43).replace(/\+/g, '-').replace(/\//g, '_');
  }

  if (base64urlCandidate !== null) {
    const decoded = decodeBase64Url(base64urlCandidate);
    if (decoded !== null) {
      return decoded;
    }
  }

  throw new EncryptionError('INVALID_MASTER_KEY', INVALID_MASTER_KEY_MESSAGE);
}

/**
 * Validates and decodes a 256-bit master key from raw 32-byte `Uint8Array`,
 * 64-char hex, 43-char unpadded Base64url, or 44-char padded Base64,
 * rejecting all-zero keys and copying binary input into an isolated `ArrayBuffer`.
 */
export function parseMasterKey(input: MasterKeyInput): Uint8Array<ArrayBuffer> {
  let keyBytes: Uint8Array<ArrayBuffer>;

  if (input instanceof Uint8Array) {
    if (input.byteLength !== AES_GCM_KEY_BYTE_LENGTH) {
      throw new EncryptionError('INVALID_MASTER_KEY', INVALID_MASTER_KEY_MESSAGE);
    }
    keyBytes = new Uint8Array(AES_GCM_KEY_BYTE_LENGTH);
    keyBytes.set(input);
  } else if (typeof input === 'string') {
    keyBytes = decodeMasterKeyString(input);
  } else {
    throw new EncryptionError('INVALID_MASTER_KEY', INVALID_MASTER_KEY_MESSAGE);
  }

  let nonZeroMask = 0;
  for (const byte of keyBytes) {
    nonZeroMask |= byte;
  }
  if (nonZeroMask === 0) {
    throw new EncryptionError('INVALID_MASTER_KEY', INVALID_MASTER_KEY_MESSAGE);
  }

  return keyBytes;
}

function resolveAdditionalData(
  options?: AesGcmOperationOptions,
): Uint8Array<ArrayBuffer> | undefined {
  const aad = options?.aad;
  if (aad === undefined) {
    return undefined;
  }
  if (typeof aad !== 'string') {
    throw new EncryptionError('INVALID_PAYLOAD', 'Additional authenticated data must be a string');
  }
  if (aad.length === 0) {
    return undefined;
  }
  return textEncoder.encode(aad);
}

function buildAesGcmParams(
  iv: Uint8Array<ArrayBuffer>,
  additionalData: Uint8Array<ArrayBuffer> | undefined,
): AesGcmParams {
  if (additionalData === undefined) {
    return {
      name: 'AES-GCM',
      iv,
      tagLength: AES_GCM_AUTH_TAG_BIT_LENGTH,
    };
  }
  return {
    name: 'AES-GCM',
    iv,
    tagLength: AES_GCM_AUTH_TAG_BIT_LENGTH,
    additionalData,
  };
}

/**
 * Creates an immutable Web Crypto AES-256-GCM cipher backed by a non-extractable
 * `CryptoKey`, wiping transient decoded key bytes in a `finally` block.
 */
export async function createAesGcmCipher(options: AesGcmCipherOptions): Promise<IAesGcmCipher> {
  const keyVersion =
    options.keyVersion === undefined ? DEFAULT_ENCRYPTION_KEY_VERSION : options.keyVersion;
  if (!isValidKeyVersion(keyVersion)) {
    throw new EncryptionError(
      'INVALID_KEY_VERSION',
      'Encryption keyVersion must be a positive safe integer',
    );
  }

  const keyBytes = parseMasterKey(options.masterKey);
  let cryptoKey: CryptoKey;
  try {
    cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  } finally {
    keyBytes.fill(0);
  }

  async function encrypt(
    plaintext: string,
    operationOptions?: AesGcmOperationOptions,
  ): Promise<EncryptedPayload> {
    if (typeof plaintext !== 'string') {
      throw new EncryptionError('INVALID_PAYLOAD', 'Plaintext must be a string');
    }

    const additionalData = resolveAdditionalData(operationOptions);
    const plaintextBytes = textEncoder.encode(plaintext);
    const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTE_LENGTH));
    const params = buildAesGcmParams(iv, additionalData);

    const sealed = new Uint8Array(await crypto.subtle.encrypt(params, cryptoKey, plaintextBytes));
    const splitIndex = sealed.byteLength - AES_GCM_AUTH_TAG_BYTE_LENGTH;
    const ciphertextBytes = sealed.subarray(0, splitIndex);
    const authTagBytes = sealed.subarray(splitIndex);

    return {
      ciphertext: encodeBase64Url(ciphertextBytes),
      iv: encodeBase64Url(iv),
      authTag: encodeBase64Url(authTagBytes),
      keyVersion,
    };
  }

  async function decrypt(
    payload: EncryptedPayload,
    operationOptions?: AesGcmOperationOptions,
  ): Promise<string> {
    if (
      typeof payload !== 'object' ||
      payload === null ||
      Array.isArray(payload) ||
      typeof payload.ciphertext !== 'string' ||
      typeof payload.iv !== 'string' ||
      typeof payload.authTag !== 'string'
    ) {
      throw new EncryptionError('INVALID_PAYLOAD', 'Encrypted payload is malformed');
    }

    if (payload.keyVersion !== undefined) {
      if (!isValidKeyVersion(payload.keyVersion)) {
        throw new EncryptionError(
          'INVALID_PAYLOAD',
          'Encrypted payload keyVersion must be a positive safe integer',
        );
      }
      if (payload.keyVersion !== keyVersion) {
        throw new EncryptionError(
          'UNSUPPORTED_KEY_VERSION',
          'Encrypted payload keyVersion is not supported by this cipher',
        );
      }
    }

    const additionalData = resolveAdditionalData(operationOptions);
    const ivBytes = decodeBase64Url(payload.iv);
    const authTagBytes = decodeBase64Url(payload.authTag);
    const ciphertextBytes = decodeBase64Url(payload.ciphertext);

    if (
      ivBytes === null ||
      authTagBytes === null ||
      ciphertextBytes === null ||
      ivBytes.byteLength !== AES_GCM_IV_BYTE_LENGTH ||
      authTagBytes.byteLength !== AES_GCM_AUTH_TAG_BYTE_LENGTH
    ) {
      throw new EncryptionError(
        'INVALID_PAYLOAD',
        'Encrypted payload encoding or field length is invalid',
      );
    }

    const combined = new Uint8Array(ciphertextBytes.byteLength + authTagBytes.byteLength);
    combined.set(ciphertextBytes, 0);
    combined.set(authTagBytes, ciphertextBytes.byteLength);

    const params = buildAesGcmParams(ivBytes, additionalData);

    try {
      const decrypted = await crypto.subtle.decrypt(params, cryptoKey, combined);
      return fatalUtf8Decoder.decode(decrypted);
    } catch {
      throw new EncryptionError(
        'DECRYPTION_FAILED',
        'AES-256-GCM authentication or decryption failed',
      );
    }
  }

  async function encryptJson(
    value: unknown,
    operationOptions?: AesGcmOperationOptions,
  ): Promise<EncryptedPayload> {
    let serialized: string | undefined;
    try {
      serialized = JSON.stringify(value);
    } catch {
      throw new EncryptionError('INVALID_PAYLOAD', 'Value is not JSON-serializable');
    }

    if (typeof serialized !== 'string') {
      throw new EncryptionError('INVALID_PAYLOAD', 'Value is not JSON-serializable');
    }

    return encrypt(serialized, operationOptions);
  }

  async function decryptJson(
    payload: EncryptedPayload,
    operationOptions?: AesGcmOperationOptions,
  ): Promise<unknown> {
    const plaintext = await decrypt(payload, operationOptions);
    try {
      return JSON.parse(plaintext) as unknown;
    } catch {
      throw new EncryptionError('INVALID_PAYLOAD', 'Decrypted payload is not valid JSON');
    }
  }

  return Object.freeze({
    keyVersion,
    encrypt,
    decrypt,
    encryptJson,
    decryptJson,
  });
}
