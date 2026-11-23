import { describe, expect, it } from 'vitest';
import {
  PLUGIN_SLUG_MAX_LENGTH,
  PLUGIN_SLUG_REGEX,
  assertValidPluginSlug,
  isValidPluginSlug,
} from '@mcphub/core';

const EXPECTED_SLUG_ERROR_MESSAGE =
  'Invalid plugin slug: must be 1..64 lowercase alphanumeric characters separated by single hyphens';

const MAX_LENGTH_PLAIN_SLUG = 'a'.repeat(64);
const MAX_LENGTH_HYPHENATED_SLUG = `${'a1-'.repeat(21)}a`;
const TOO_LONG_SLUG = 'a'.repeat(65);

describe('plugin slug validation constants', () => {
  it('defines the canonical max length and regex', () => {
    expect(PLUGIN_SLUG_MAX_LENGTH).toBe(64);
    expect(PLUGIN_SLUG_REGEX).toBeInstanceOf(RegExp);
  });
});

describe('isValidPluginSlug', () => {
  it.each([
    ['single character', 'a'],
    ['single digit', '1'],
    ['lowercase connector name', 'fiainvest'],
    ['hyphenated alphanumeric slug', 'fia-invest-1'],
    ['exact 64-character plain slug', MAX_LENGTH_PLAIN_SLUG],
    ['exact 64-character hyphenated slug', MAX_LENGTH_HYPHENATED_SLUG],
  ])('accepts valid slug (%s)', (_label, slug) => {
    expect(slug.length).toBeLessThanOrEqual(64);
    expect(isValidPluginSlug(slug)).toBe(true);
  });

  it.each([
    ['empty string', ''],
    ['65-character string exceeding max length', TOO_LONG_SLUG],
    ['uppercase characters', 'FiaInvest'],
    ['underscore separator', 'fia_invest'],
    ['whitespace character', 'fia invest'],
    ['dot-dot path traversal', '../admin'],
    ['forward slash', 'a/b'],
    ['backslash', 'a\\b'],
    ['leading hyphen', '-fia'],
    ['trailing hyphen', 'fia-'],
    ['consecutive hyphens', 'fia--invest'],
    ['dot separator', 'fia.invest'],
  ])('rejects invalid slug (%s)', (_label, slug) => {
    expect(isValidPluginSlug(slug)).toBe(false);
  });
});

describe('assertValidPluginSlug', () => {
  it('returns valid slugs unchanged', () => {
    expect(assertValidPluginSlug('fiainvest')).toBe('fiainvest');
    expect(assertValidPluginSlug('fia-invest-1')).toBe('fia-invest-1');
    expect(assertValidPluginSlug(MAX_LENGTH_HYPHENATED_SLUG)).toBe(MAX_LENGTH_HYPHENATED_SLUG);
  });

  it.each([
    '',
    TOO_LONG_SLUG,
    'FiaInvest',
    'fia_invest',
    'fia invest',
    '../admin',
    'a/b',
    'a\\b',
    '-fia',
    'fia-',
    'fia--invest',
    'UNTRUSTED_RAW_INPUT_LEAK_CHECK',
  ])('throws fixed non-echoing Error for invalid slug %j', (invalidSlug) => {
    let caughtError: unknown;
    try {
      assertValidPluginSlug(invalidSlug);
    } catch (error: unknown) {
      caughtError = error;
    }

    expect(caughtError).toBeInstanceOf(Error);
    if (caughtError instanceof Error) {
      expect(caughtError.message).toBe(EXPECTED_SLUG_ERROR_MESSAGE);
      if (invalidSlug.length > 0) {
        expect(caughtError.message).not.toContain(invalidSlug);
      }
    }
  });
});
