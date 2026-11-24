const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const textDecoder = new TextDecoder();

function decodeBase64UrlSextet(code: number): number {
  if (code >= 65 && code <= 90) {
    return code - 65;
  }
  if (code >= 97 && code <= 122) {
    return code - 71;
  }
  if (code >= 48 && code <= 57) {
    return code + 4;
  }
  if (code === 45) {
    return 62;
  }
  if (code === 95) {
    return 63;
  }
  return -1;
}

/**
 * Encodes arbitrary bytes into strict unpadded Base64url (RFC 4648 section 5)
 * using an O(n) pre-sized Uint8Array and TextDecoder.
 */
export function encodeBase64Url(bytes: Uint8Array): string {
  const len = bytes.length;
  if (len === 0) {
    return '';
  }

  const rem = len % 3;
  const fullLimit = len - rem;
  const outLength = (fullLimit / 3) * 4 + (rem === 0 ? 0 : rem + 1);
  const out = new Uint8Array(outLength);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  let inIndex = 0;
  let outIndex = 0;

  while (inIndex < fullLimit) {
    const triplet =
      (view.getUint8(inIndex) << 16) |
      (view.getUint8(inIndex + 1) << 8) |
      view.getUint8(inIndex + 2);
    out[outIndex] = BASE64URL_ALPHABET.charCodeAt((triplet >>> 18) & 0x3f);
    out[outIndex + 1] = BASE64URL_ALPHABET.charCodeAt((triplet >>> 12) & 0x3f);
    out[outIndex + 2] = BASE64URL_ALPHABET.charCodeAt((triplet >>> 6) & 0x3f);
    out[outIndex + 3] = BASE64URL_ALPHABET.charCodeAt(triplet & 0x3f);
    inIndex += 3;
    outIndex += 4;
  }

  if (rem === 1) {
    const b0 = view.getUint8(inIndex);
    out[outIndex] = BASE64URL_ALPHABET.charCodeAt(b0 >>> 2);
    out[outIndex + 1] = BASE64URL_ALPHABET.charCodeAt((b0 & 0x03) << 4);
  } else if (rem === 2) {
    const b0 = view.getUint8(inIndex);
    const b1 = view.getUint8(inIndex + 1);
    out[outIndex] = BASE64URL_ALPHABET.charCodeAt(b0 >>> 2);
    out[outIndex + 1] = BASE64URL_ALPHABET.charCodeAt(((b0 & 0x03) << 4) | (b1 >>> 4));
    out[outIndex + 2] = BASE64URL_ALPHABET.charCodeAt((b1 & 0x0f) << 2);
  }

  return textDecoder.decode(out);
}

/**
 * Strictly decodes unpadded Base64url (RFC 4648 section 5), returning `null` if
 * non-alphabet characters, invalid length (`length % 4 === 1`), or non-zero
 * canonical trailing bits are present.
 */
export function decodeBase64Url(encoded: string): Uint8Array<ArrayBuffer> | null {
  const len = encoded.length;
  if (len === 0) {
    return new Uint8Array(0);
  }

  const rem = len % 4;
  if (rem === 1) {
    return null;
  }

  const fullGroups = (len - rem) / 4;
  const extraBytes = rem === 0 ? 0 : rem - 1;
  const out = new Uint8Array(fullGroups * 3 + extraBytes);

  let inIndex = 0;
  let outIndex = 0;

  for (let g = 0; g < fullGroups; g += 1) {
    const s0 = decodeBase64UrlSextet(encoded.charCodeAt(inIndex));
    const s1 = decodeBase64UrlSextet(encoded.charCodeAt(inIndex + 1));
    const s2 = decodeBase64UrlSextet(encoded.charCodeAt(inIndex + 2));
    const s3 = decodeBase64UrlSextet(encoded.charCodeAt(inIndex + 3));
    if (s0 < 0 || s1 < 0 || s2 < 0 || s3 < 0) {
      return null;
    }

    const triplet = (s0 << 18) | (s1 << 12) | (s2 << 6) | s3;
    out[outIndex] = (triplet >>> 16) & 0xff;
    out[outIndex + 1] = (triplet >>> 8) & 0xff;
    out[outIndex + 2] = triplet & 0xff;
    inIndex += 4;
    outIndex += 3;
  }

  if (rem === 2) {
    const s0 = decodeBase64UrlSextet(encoded.charCodeAt(inIndex));
    const s1 = decodeBase64UrlSextet(encoded.charCodeAt(inIndex + 1));
    if (s0 < 0 || s1 < 0 || (s1 & 0x0f) !== 0) {
      return null;
    }
    out[outIndex] = (s0 << 2) | (s1 >>> 4);
  } else if (rem === 3) {
    const s0 = decodeBase64UrlSextet(encoded.charCodeAt(inIndex));
    const s1 = decodeBase64UrlSextet(encoded.charCodeAt(inIndex + 1));
    const s2 = decodeBase64UrlSextet(encoded.charCodeAt(inIndex + 2));
    if (s0 < 0 || s1 < 0 || s2 < 0 || (s2 & 0x03) !== 0) {
      return null;
    }
    out[outIndex] = (s0 << 2) | (s1 >>> 4);
    out[outIndex + 1] = ((s1 & 0x0f) << 4) | (s2 >>> 2);
  }

  return out;
}
