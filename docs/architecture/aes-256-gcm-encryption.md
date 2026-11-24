# Architecture & Security Specification: AES-256-GCM Encryption Engine (`TSK-01.3` / #4)

- **Task:** `TSK-01.3` (GitHub Issue `#4`)
- **Tier:** Complex (`AGENTS.md §0`)
- **Status:** Accepted (Approved by PO on 2026-11-24)
- **Target Workspace:** `packages/mcp-core` (`@mcphub/core`)
- **Canonical Standards & References:**
  - `AGENTS.md` (Decision Benchmark, Isomorphic Runtime Portability, Security & Error Handling)
  - `docs/rules/core-invariants.md` §§3, 4, 6
  - `docs/architecture/mcp-core-contracts.md` (`EncryptedPayload`, `UserCredentialRecord`, `PluginExecutionContext`)
  - `tsconfig.base.json` (`strict`, `noUncheckedIndexedAccess`, `noImplicitOverride`, `isolatedModules`, `verbatimModuleSyntax`, `NodeNext` ESM)
  - `eslint.config.js` (`typescript-eslint` recommended — zero `any`, zero `{}` empty object types)
  - [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) (Galois/Counter Mode (GCM) and GMAC)
  - [RFC 4648 §5](https://datatracker.ietf.org/doc/html/rfc4648#section-5) (Base 64 Encoding with URL and Filename Safe Alphabet)

---

## 1. Scope & Explicit Non-Scope

### 1.1 Scope

Defines the canonical Web Crypto AES-256-GCM authenticated encryption engine, master key parser, strict Base64url wire codec, and zero-leakage error contract exported by `@mcphub/core` (`packages/mcp-core`):

1. **Web Crypto AES-256-GCM Sealing/Opening Engine:** `createAesGcmCipher` and `IAesGcmCipher` backed strictly by `crypto.subtle` (`AES-GCM`, 256-bit key, random 96-bit IV per encryption, 128-bit authentication tag, optional AAD tenant binding).
2. **Strict `ENCRYPTION_MASTER_KEY` Parser (`parseMasterKey`):** Validates and decodes 256-bit master keys from raw 32-byte `Uint8Array`, 64-character hex, 43-character unpadded Base64url, or 44-character padded standard Base64 while rejecting weak/zero keys and ambiguous encodings.
3. **Strict Unpadded Base64url Codec:** Pure O(n) byte-level RFC 4648 §5 encoder/decoder free of `Buffer` and `String.fromCharCode(...bytes)` spread limits, enforcing canonical zero trailing bits.
4. **Typed Zero-Leakage Error Boundary:** `EncryptionError` and `EncryptionErrorCode` ensuring cryptographic, parsing, and JSON failures never expose key material, plaintext, ciphertext, IV, authTag, AAD, or raw `cause` properties.
5. **JSON Convenience Helpers:** `encryptJson` and `decryptJson` on `IAesGcmCipher` with strict JSON serializability and safe parse-failure wrapping.
6. **Barrel Re-Exports (`packages/mcp-core/src/index.ts`):** Exports all public constants, types, `EncryptionError`, `parseMasterKey`, and `createAesGcmCipher` from `@mcphub/core`.

### 1.2 Explicit Non-Scope

- SQLite storage driver (`TSK-01.4` / `#5`) and Cloudflare D1 storage driver (`TSK-01.5` / `#6`).
- Gateway authentication middleware and decrypted session injection (`TSK-03.3`).
- Multi-key rotation ring (`previousKeys` / `legacyKeys`), deferred as a backwards-compatible future extension to `AesGcmCipherOptions`.
- Password-based key derivation functions (PBKDF2, scrypt, Argon2); `ENCRYPTION_MASTER_KEY` MUST already be a full-entropy 256-bit key rather than a human passphrase.
- Reading `process.env` inside `@mcphub/core`; runtime entrypoints (e.g., `apps/mcp-gateway`) read `ENCRYPTION_MASTER_KEY` from the host environment and pass it to `createAesGcmCipher`.
- Streaming encryption, non-GCM block cipher modes, or third-party cryptographic/encoding libraries.

---

## 2. Cryptographic Parameters & Wire Format (`EncryptedPayload`)

### 2.1 Existing Envelope Contract (`packages/mcp-core/src/contracts/storage.ts`)

The engine consumes and produces the frozen `EncryptedPayload` contract already defined in `packages/mcp-core/src/contracts/storage.ts`:

```ts
export interface EncryptedPayload {
  readonly ciphertext: string;
  readonly iv: string;
  readonly authTag: string;
  readonly keyVersion?: number;
}
```

### 2.2 Cipher Algorithm, Nonce, and Authentication Tag

| Parameter | Value | Invariant |
| :--- | :--- | :--- |
| **Algorithm** | `AES-GCM` (`crypto.subtle`) | 256-bit key (`length: 256`, `32` bytes). |
| **Initialization Vector (`iv`)** | `96` bits (`12` bytes) | Generated fresh on every `encrypt` / `encryptJson` call via `crypto.getRandomValues(new Uint8Array(12))`. Never reused or counter-derived across stateless workers. |
| **Authentication Tag (`authTag`)** | `128` bits (`16` bytes) | `tagLength: 128` passed explicitly in `AesGcmParams` on both `encrypt` and `decrypt`. |
| **Web Crypto Split / Join** | `ciphertext \|\| authTag` | `crypto.subtle.encrypt` returns `ciphertext \|\| authTag`. Sealing splits the trailing `16` bytes as `authTag` and leading `n - 16` bytes as `ciphertext`. Opening re-concatenates `ciphertext \|\| authTag` before calling `crypto.subtle.decrypt`. |

### 2.3 Strict Unpadded Base64url Wire Encoding (RFC 4648 §5)

`ciphertext`, `iv`, and `authTag` in `EncryptedPayload` are encoded exclusively as **strict unpadded Base64url** using the RFC 4648 §5 alphabet `[A-Za-z0-9-_]` with zero `=` padding:

- **Encoder Invariants:**
  - Implemented as a pure `O(n)` byte-group loop over `Uint8Array` (emitting ASCII output via a byte buffer + `TextDecoder` or bounded string chunks).
  - MUST NOT use Node's `Buffer` (`@mcphub/core` Web Standards invariant).
  - MUST NOT use `String.fromCharCode(...bytes)` argument spreading, which throws `RangeError: Maximum call stack size exceeded` in V8 on payloads larger than ~64 KB.
- **Strict Decoder Invariants:**
  - Implemented as a pure `O(n)` lookup loop over UTF-16 code units (`<= 127` ASCII table check).
  - MUST reject with `EncryptionError('INVALID_PAYLOAD', ...)` if any encoded field (`iv`, `authTag`, `ciphertext`):
    1. Contains characters outside `[A-Za-z0-9-_]` (including `+`, `/`, `=`, spaces, tabs, `\r`, `\n`, or non-ASCII characters).
    2. Has `encoded.length % 4 === 1` (impossible Base64url length).
    3. Contains non-zero canonical trailing padding bits per RFC 4648 §3.5:
       - When `encoded.length % 4 === 2`: the lowest `4` bits of the 2nd sextet (`s1 & 0x0f`) MUST equal `0`.
       - When `encoded.length % 4 === 3`: the lowest `2` bits of the 3rd sextet (`s2 & 0x03`) MUST equal `0`.
  - Returns `Uint8Array<ArrayBuffer>` for zero-cast `BufferSource` compatibility under TypeScript 6.0.
- **Empty Plaintext Edge Case:**
  - Encrypting `""` (`0` UTF-8 bytes) MUST succeed and produce `ciphertext: ""`, a fresh `12`-byte Base64url-encoded `iv` (`16` characters), and a valid `16`-byte Base64url-encoded `authTag` (`22` characters) authenticating the zero-length ciphertext and any AAD.
  - Decrypting `ciphertext: ""` with its matching `iv`, `authTag`, and `aad` MUST return `""`.

### 2.4 Payload Validation & `keyVersion` Semantics

- **On `encrypt` / `encryptJson`:**
  - Stamps `keyVersion: cipher.keyVersion` (default `1`) onto every produced `EncryptedPayload`.
  - Validates `typeof plaintext === 'string'` (and `typeof options.aad === 'string'` when `options?.aad !== undefined`); rejects runtime type violations with `EncryptionError('INVALID_PAYLOAD', ...)`.
- **On `decrypt` / `decryptJson`:**
  1. Validates `payload` is a non-null object whose `ciphertext`, `iv`, and `authTag` properties are all strings; otherwise throws `EncryptionError('INVALID_PAYLOAD', ...)`.
  2. Evaluates `payload.keyVersion`:
     - If `payload.keyVersion !== undefined` and (`!Number.isSafeInteger(payload.keyVersion)` or `payload.keyVersion < 1`), throws `EncryptionError('INVALID_PAYLOAD', 'Encrypted payload keyVersion must be a positive safe integer')`.
     - If `payload.keyVersion !== undefined` and `payload.keyVersion !== cipher.keyVersion`, throws `EncryptionError('UNSUPPORTED_KEY_VERSION', 'Encrypted payload keyVersion is not supported by this cipher')`.
     - If `payload.keyVersion === undefined`, accepts the envelope and decrypts using the cipher's active key (supporting compact or legacy unversioned payloads).
  3. Validates `options?.aad` is a string when defined (`!== undefined`); otherwise throws `EncryptionError('INVALID_PAYLOAD', ...)`.
  4. Decodes `iv`, `authTag`, and `ciphertext` with the strict Base64url decoder (`INVALID_PAYLOAD` on failure).
  5. Asserts exact decoded byte lengths: `ivBytes.byteLength === 12` and `authTagBytes.byteLength === 16`; otherwise throws `EncryptionError('INVALID_PAYLOAD', ...)`.
  6. Re-concatenates `ciphertext || authTag`, runs `crypto.subtle.decrypt`, and decodes UTF-8 via `new TextDecoder('utf-8', { fatal: true })`. Any Web Crypto authentication failure or invalid UTF-8 byte sequence throws `EncryptionError('DECRYPTION_FAILED', 'AES-256-GCM authentication or decryption failed')`.

### 2.5 Additional Authenticated Data (`aad`) & Cross-Tenant Swap Protection

- `options?.aad?: string` allows callers to bind ciphertext and authentication tag to immutable context without storing the AAD inside `EncryptedPayload`.
- **Tenant Binding Pattern (`docs/rules/core-invariants.md §3`):** Gateway/vault code MUST pass tenant-scoped AAD when sealing and opening `UserCredentialRecord.encryptedPayload` (e.g., `aad: \`${userId}:${pluginSlug}\``). Because `pluginSlug` matches `PLUGIN_SLUG_REGEX` (`^[a-z0-9]+(?:-[a-z0-9]+)*$`, containing no `:`), `${userId}:${pluginSlug}` is unambiguous and prevents an attacker or storage bug from swapping ciphertext rows across users or plugins.
- **NIST SP 800-38D Empty AAD Equivalence:** Per NIST SP 800-38D, an empty AAD (`aad: ''`) and an omitted AAD (`aad: undefined`) produce identical GHASH inputs (the empty bit string). To guarantee uniform cross-runtime behavior across Node.js 26 Web Crypto and Cloudflare Workers without zero-length `BufferSource` quirks, `AesGcmParams.additionalData` is populated (`textEncoder.encode(options.aad)`) only when `options?.aad !== undefined && options.aad.length > 0`, and omitted when `aad` is `undefined` or `""`. Consequently, sealing with `aad: ''` and opening with `aad: undefined` (and vice versa) MUST succeed deterministically.

---

## 3. Master Key Contract (`ENCRYPTION_MASTER_KEY` & `parseMasterKey`)

### 3.1 Accepted `MasterKeyInput` Formats

```ts
export type MasterKeyInput = string | Uint8Array;
```

`parseMasterKey(input: MasterKeyInput): Uint8Array<ArrayBuffer>` accepts **four strictly disjoint input formats**, guaranteeing zero parsing ambiguity across environment injections and programmatic callers:

| # | Format | Validation Rule | Decoding & Isolation Behavior |
| :--- | :--- | :--- | :--- |
| **1** | **Raw Binary (`Uint8Array`)** | `input instanceof Uint8Array` and `input.byteLength === 32` | Copied into a newly allocated `Uint8Array<ArrayBuffer>(32)` so caller memory is never mutated when wiped and never backed by `SharedArrayBuffer`. |
| **2** | **`64`-Char Hex String** | `typeof input === 'string'` matching `/^[0-9a-fA-F]{64}$/` | Decoded case-insensitively pair-by-pair into `32` raw bytes. |
| **3** | **`43`-Char Unpadded Base64url** | `typeof input === 'string'` matching `/^[A-Za-z0-9_-]{43}$/` | Decoded via strict Base64url into `32` bytes (`43 % 4 === 3`, enforcing `(lastSextet & 0x03) === 0` zero canonical trailing bits). |
| **4** | **`44`-Char Padded Standard Base64** | `typeof input === 'string'` matching `/^[A-Za-z0-9+/]{43}=$/` | Decoded via strict standard Base64 into `32` bytes (enforcing `(lastSextet & 0x03) === 0` zero canonical trailing bits). |

### 3.2 Mandatory Rejections (`INVALID_MASTER_KEY`)

All invalid inputs MUST throw `EncryptionError('INVALID_MASTER_KEY', ...)` without echoing any portion of the input:

- Empty string (`""`) or empty `Uint8Array`.
- Untrimmed leading, trailing, or embedded whitespace (e.g., `" <64hex>"`, `"<64hex>\n"`).
- Arbitrary passphrases or raw UTF-8 strings (including 32-character ASCII strings or non-encoding 43/44/64-character words).
- Incorrect byte or string lengths (`31`- or `33`-byte `Uint8Array`, `62`/`63`/`65`-char hex, `42`/`44`-char unpadded Base64url, `43`-char standard Base64 missing `=`, `44`-char Base64 with `==`).
- Invalid alphabet characters (e.g., `+`/`/`/`=` inside a 43-char string, `-`/`_` inside a 44-char `=`-padded string, non-hex letters).
- Non-zero canonical trailing bits in the 43rd character of Base64url or Base64 (`(lastSextet & 0x03) !== 0`).
- **All-zero 32-byte key** (`0x00` across all 32 bytes in any of the four formats), preventing misconfigured zero-filled placeholders or blank buffers from operating in production or dev.
- Non-string and non-`Uint8Array` runtime values.

### 3.3 Key Import & Memory Hygiene

Inside `createAesGcmCipher(options)`:

1. Parse key bytes via `const keyBytes = parseMasterKey(options.masterKey);`.
2. Import into Web Crypto inside a `try / finally` guard:
   ```ts
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
   ```
3. `extractable: false` guarantees `crypto.subtle.exportKey` cannot extract raw key bytes out of the runtime `CryptoKey` handle.
4. `keyBytes.fill(0)` in `finally` guarantees transient raw key material inside the parsed `Uint8Array<ArrayBuffer>` is wiped immediately whether `importKey` succeeds or fails, without ever mutating an external caller-owned `Uint8Array`.

---

## 4. Public TypeScript API (`packages/mcp-core/src/crypto/aes-gcm.ts` & Barrel `index.ts`)

All public symbols below live in `packages/mcp-core/src/crypto/aes-gcm.ts` and MUST be re-exported from `packages/mcp-core/src/index.ts`.

### 4.1 Constants

```ts
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
```

### 4.2 Types & Interfaces

```ts
/** Accepted master key input representations (raw 32-byte buffer or encoded string). */
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
```

### 4.3 `EncryptionError` Class

```ts
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
```

**Error Hygiene Rules (`4.3`):**
- `this.name` MUST equal `'EncryptionError'`; `err instanceof EncryptionError` and `err instanceof Error` MUST both be `true`.
- Constructor MUST NOT accept or pass `{ cause }` to `super(...)`, ensuring `'cause' in err === false` and `err.cause === undefined` so raw `DOMException`, `SyntaxError`, or caller inputs are never retained on the error object.
- Every `EncryptionError` message MUST be a fixed, sanitized diagnostic string containing zero key material, plaintext, ciphertext, IV, authTag, or AAD.

### 4.4 Public Functions & Cipher Method Contracts

```ts
export function parseMasterKey(input: MasterKeyInput): Uint8Array<ArrayBuffer>;
export function createAesGcmCipher(options: AesGcmCipherOptions): Promise<IAesGcmCipher>;
```

| Symbol / Method | Exact Contract & Failure Modes |
| :--- | :--- |
| **`parseMasterKey(input)`** | Validates all 4 disjoint formats (§3.1), rejects all invalid/zero inputs with `EncryptionError('INVALID_MASTER_KEY', ...)` (§3.2), and returns a freshly allocated 32-byte `Uint8Array<ArrayBuffer>`. |
| **`createAesGcmCipher(options)`** | Resolves `keyVersion = options.keyVersion ?? DEFAULT_ENCRYPTION_KEY_VERSION`; if `!Number.isSafeInteger(keyVersion) \|\| keyVersion < 1`, throws `EncryptionError('INVALID_KEY_VERSION', ...)` before key parsing. Parses and imports key via `crypto.subtle.importKey(..., false, ['encrypt', 'decrypt'])` with `keyBytes.fill(0)` in `finally`. Returns `Object.freeze({ keyVersion, encrypt, decrypt, encryptJson, decryptJson })`. |
| **`cipher.encrypt(plaintext, options?)`** | Validates `plaintext` (and `options?.aad` when defined) are strings (`INVALID_PAYLOAD`). Encodes UTF-8 plaintext, generates fresh 12-byte random IV, encrypts via AES-256-GCM (`tagLength: 128`, optional UTF-8 `additionalData` when `aad` is non-empty), splits `ciphertext \|\| authTag`, and returns `{ ciphertext, iv, authTag, keyVersion }` encoded in strict unpadded Base64url. |
| **`cipher.decrypt(payload, options?)`** | Validates envelope shape (`INVALID_PAYLOAD`), checks `payload.keyVersion` (`INVALID_PAYLOAD` if malformed, `UNSUPPORTED_KEY_VERSION` if `!== cipher.keyVersion`, accepted if `undefined`), strictly Base64url-decodes and length-checks `iv` (`12`) and `authTag` (`16`) (`INVALID_PAYLOAD`), decrypts `ciphertext \|\| authTag` via `crypto.subtle.decrypt`, and decodes UTF-8 via `new TextDecoder('utf-8', { fatal: true })`. Wraps any Web Crypto or UTF-8 decode error uniformly as `EncryptionError('DECRYPTION_FAILED', 'AES-256-GCM authentication or decryption failed')`. |
| **`cipher.encryptJson(value, options?)`** | Serializes `value` via `JSON.stringify(value)`. Rejects unserializable values — `undefined`, functions, symbols (`JSON.stringify` returning `undefined`), `BigInt`, and circular references (`JSON.stringify` throwing `TypeError`) — with `EncryptionError('INVALID_PAYLOAD', 'Value is not JSON-serializable')`. Delegates serialized JSON string to `encrypt(serialized, options)`. |
| **`cipher.decryptJson(payload, options?)`** | Delegates to `decrypt(payload, options)`. Parses resulting plaintext with `JSON.parse(plaintext) as unknown`. Wraps any `SyntaxError` as `EncryptionError('INVALID_PAYLOAD', 'Decrypted payload is not valid JSON')` without attaching `cause` or leaking decrypted plaintext (V8 `SyntaxError` messages can embed input snippets and MUST be suppressed). |

---

## 5. Module Layout, Portability & Traceability Matrix

### 5.1 Canonical Module Layout & Import Rules

```text
packages/mcp-core/src/
├── contracts/
│   ├── plugin.ts
│   └── storage.ts                     # Existing EncryptedPayload interface consumed by crypto/aes-gcm.ts
├── crypto/
│   ├── aes-gcm.ts                     # Constants, types, EncryptionError, parseMasterKey, createAesGcmCipher
│   └── base64url.ts                   # Optional internal O(n) strict RFC 4648 §4/§5 codec (not re-exported)
├── errors/
│   └── upstream-client-error.ts
├── validation/
│   └── slug.ts
└── index.ts                           # Re-exports all public crypto constants, types, class, and functions
```

**Portability & Compiler Invariants (`5.1`):**
- **Zero Node-Only APIs:** `packages/mcp-core/src/` MUST contain **zero** `node:*` imports, **zero** `process.env` reads, **zero** `Buffer` references, and **zero** third-party runtime dependencies. All crypto and text codecs use pure Web Standards (`crypto.subtle`, `crypto.getRandomValues`, `TextEncoder`, `TextDecoder`, `Uint8Array`).
- **NodeNext ESM & `verbatimModuleSyntax`:** All internal relative imports/re-exports MUST use explicit `.js` specifiers (e.g., `'./crypto/aes-gcm.js'`), and type-only re-exports MUST use `export type`.
- **TypeScript 6.0 Strict Typing:** Zero `any`, zero `{}` empty object types, clean indexing under `noUncheckedIndexedAccess: true`, explicit `override` on `EncryptionError.name`, and explicit `Uint8Array<ArrayBuffer>` return types on `parseMasterKey` and Base64url decoders so `BufferSource` calls compile without unsafe casts.
- **Preserved Exports:** `packages/mcp-core/src/index.ts` MUST preserve all existing exports (`PLATFORM_NAME`, `HealthPayload`, `createHealthPayload`, contract types, `UpstreamClientError`, `sanitizeUpstreamText`, and slug validators).

### 5.2 Traceability Matrix (`docs/rules/core-invariants.md`)

| `core-invariants.md` Section | Spec Mapping (`aes-256-gcm-encryption.md`) |
| :--- | :--- |
| **§3 Multi-Tenant Vault, Cryptography & Zero-Trust Privacy** | §2.1–2.4 (`crypto.subtle` AES-256-GCM, fresh random 12-byte IV per write, 16-byte GCM authentication tag verification, `EncryptedPayload` envelope), §2.5 (optional AAD binding e.g. `${userId}:${pluginSlug}` preventing cross-tenant ciphertext swaps), §3.1–3.3 (strict `ENCRYPTION_MASTER_KEY` parsing, all-zero rejection, non-extractable `CryptoKey`, `finally` key zero-fill). |
| **§4 Secrets, Logging & Memory Hygiene** | §3.3 (`extractable: false` + `keyBytes.fill(0)`), §4.3 (`EncryptionError` omits `cause` and never echoes keys, plaintext, ciphertext, IV, tag, or AAD), §4.4 (`decryptJson` suppresses V8 `SyntaxError` plaintext snippets; `decrypt` normalizes crypto/UTF-8 errors into fixed `DECRYPTION_FAILED` message). |
| **§6 Isomorphic Portability & Plugin Decoupling** | §1.2 (zero `process.env` reads inside `@mcphub/core`), §2.3 (pure `O(n)` Base64url loop with zero `Buffer` and zero `String.fromCharCode(...bytes)` stack overflow), §5.1 (100% Web Standards `crypto.subtle` / `TextEncoder` / `TextDecoder` / `Uint8Array<ArrayBuffer>` portable across Node.js 26 and Cloudflare Workers). |

---

## 6. Verification Criteria (QA Red-Test & Coder Gates)

### 6.1 Pre-Implementation Red Tests (`Step 2`)

Before implementing `packages/mcp-core/src/crypto/aes-gcm.ts`, QA creates `packages/mcp-core/test/aes-gcm.test.ts` importing all new constants, types, `EncryptionError`, `parseMasterKey`, and `createAesGcmCipher` from `@mcphub/core` and verifying reproducible red-test failure against the missing module.

### 6.2 Executable Runtime & Security Test Matrix (`packages/mcp-core/test/aes-gcm.test.ts`)

1. **Master Key Parsing (`parseMasterKey` & `createAesGcmCipher`):**
   - Accepts all 4 valid formats representing the same 32-byte key: raw `Uint8Array(32)`, 64-char hex (lowercase and uppercase), 43-char unpadded Base64url, and 44-char `=`-padded standard Base64; verifies cross-format key equivalence by decrypting across ciphers constructed from each format.
   - Verifies caller-supplied `Uint8Array(32)` is copied and **never mutated** (`keyBytes.fill(0)` inside `createAesGcmCipher` leaves caller array intact).
   - Rejects with `EncryptionError('INVALID_MASTER_KEY', ...)`: empty string, empty `Uint8Array`, untrimmed whitespace (`" ..."`, `"...\n"`), arbitrary passphrases, wrong lengths (31/33-byte `Uint8Array`, 62/63/65-char hex, 42/44-char unpadded Base64url, 43-char standard Base64 without `=`, 44-char Base64 with `==`), invalid characters, non-zero canonical trailing bits in 43-char Base64url / 44-char Base64, all-zero 32-byte keys (in all 4 formats), and non-string/non-`Uint8Array` runtime inputs.
   - Verifies `createAesGcmCipher` rejects invalid `keyVersion` (`0`, `-1`, `1.5`, `NaN`, `Infinity`, `Number.MAX_SAFE_INTEGER + 1`) with `EncryptionError('INVALID_KEY_VERSION', ...)` and freezes returned cipher (`Object.isFrozen(cipher) === true`).
2. **Encryption / Decryption Round-Trips & Wire Format:**
   - Round-trips empty string `""` (asserting `ciphertext === ''`, 16-char Base64url `iv`, 22-char Base64url `authTag`), ASCII, multi-byte Unicode/emoji (`"Hello 🚀 café — π/Ω"`), and a large payload `> 64 KB` (e.g., `128 KB`) proving `O(n)` Base64url encoding/decoding suffers zero `String.fromCharCode` stack overflow.
   - Verifies unpadded Base64url alphabet (`^[A-Za-z0-9_-]*$`, zero `=`) and exact `12`-byte decoded IV / `16`-byte decoded authTag.
   - Verifies encrypting identical plaintext and AAD multiple times produces distinct random 12-byte IVs and distinct ciphertexts.
   - Verifies runtime `typeof plaintext !== 'string'` / `typeof options.aad !== 'string'` throws `EncryptionError('INVALID_PAYLOAD', ...)`.
3. **AAD Binding & NIST SP 800-38D Empty Equivalence:**
   - Encrypting with `aad: 'user-1:fiainvest'` decrypts cleanly with matching AAD and throws `EncryptionError('DECRYPTION_FAILED', ...)` when decrypted with mismatched AAD (`'user-2:fiainvest'`, `'user-1:other-plugin'`, or omitted AAD).
   - Encrypting without AAD fails decryption when non-empty AAD is supplied.
   - Verifies NIST SP 800-38D equivalence: encrypting with `aad: ''` decrypts with `aad: undefined`, and encrypting with `aad: undefined` decrypts with `aad: ''`.
4. **Tampering, Malformed Base64url & Payload Validation:**
   - Single-byte/bit flip in `ciphertext`, `iv`, or `authTag` (preserving valid Base64url lengths) throws `EncryptionError('DECRYPTION_FAILED', ...)`.
   - Wrong-key cipher throws `EncryptionError('DECRYPTION_FAILED', ...)`.
   - Malformed Base64url in `ciphertext`, `iv`, or `authTag` (`+`, `/`, `=`, whitespace, non-ASCII, `length % 4 === 1`, non-zero canonical trailing bits at `length % 4 === 2` and `length % 4 === 3`) throws `EncryptionError('INVALID_PAYLOAD', ...)`.
   - Wrong decoded lengths (`11`- or `13`-byte `iv`; `15`- or `17`-byte `authTag`) and non-object / non-string envelope fields throw `EncryptionError('INVALID_PAYLOAD', ...)`.
   - Decryption of valid AES-GCM ciphertext containing invalid UTF-8 byte sequences (sealed directly via `crypto.subtle` for test setup) throws `EncryptionError('DECRYPTION_FAILED', ...)` via `{ fatal: true }`.
5. **`keyVersion` Lifecycle Handling:**
   - Default cipher stamps `keyVersion: 1`; custom cipher (`keyVersion: 2`) stamps `keyVersion: 2` and round-trips successfully.
   - Payload with invalid `keyVersion` (`0`, `-1`, `1.5`, `'1' as unknown as number`) throws `EncryptionError('INVALID_PAYLOAD', ...)`.
   - Payload with mismatched `keyVersion` (e.g., `2` decrypted by cipher `1`) throws `EncryptionError('UNSUPPORTED_KEY_VERSION', ...)`.
   - Payload with `keyVersion: undefined` is accepted and decrypted by the active cipher.
6. **JSON Convenience Helpers (`encryptJson` / `decryptJson`):**
   - Round-trips plain objects, nested arrays, strings, numbers, booleans, and `null`.
   - `encryptJson` rejects `undefined`, functions, symbols, `BigInt`, and circular object references with `EncryptionError('INVALID_PAYLOAD', 'Value is not JSON-serializable')`.
   - `decryptJson` on valid encrypted non-JSON text (e.g., `await cipher.encrypt('not-valid-json-secret')`) throws `EncryptionError('INVALID_PAYLOAD', 'Decrypted payload is not valid JSON')` without leaking any part of `'not-valid-json-secret'`.
7. **Zero-Leakage Error Hygiene:**
   - Every thrown `EncryptionError` asserts `err instanceof Error`, `err instanceof EncryptionError`, `err.name === 'EncryptionError'`, `'cause' in err === false`, `err.cause === undefined`, and `err.message` + `JSON.stringify(err)` contain zero occurrences of test keys, plaintext secrets, ciphertext, IV, authTag, or AAD.
8. **Portability & Final Quality Gate:**
   - `packages/mcp-core/test/portability.test.ts` passes (zero `node:*` imports, zero `process.env` across `packages/mcp-core/src`, plus verification of zero `Buffer` usage in `packages/mcp-core/src/crypto/`).
   - `npm run build && npm run gate` passes with zero ESLint errors, zero Prettier diffs, clean `tsc --noEmit`, clean `.js`/`.d.ts` build emission, and **100% V8 statement coverage** across `packages/mcp-core/src/**`.
