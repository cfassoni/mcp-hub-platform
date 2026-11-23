/** Maximum allowed length (inclusive) for a canonical plugin slug. */
export const PLUGIN_SLUG_MAX_LENGTH = 64;

/** Canonical plugin slug pattern: lowercase alphanumeric segments separated by single hyphens. */
export const PLUGIN_SLUG_REGEX = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

const INVALID_PLUGIN_SLUG_MESSAGE =
  'Invalid plugin slug: must be 1..64 lowercase alphanumeric characters separated by single hyphens';

/** Returns `true` when `slug` satisfies length (`1..64`) and canonical hyphenated lowercase alphanumeric rules. */
export function isValidPluginSlug(slug: string): boolean {
  return slug.length >= 1 && slug.length <= PLUGIN_SLUG_MAX_LENGTH && PLUGIN_SLUG_REGEX.test(slug);
}

/** Returns `slug` unchanged when valid, or throws a fixed-format `Error` without echoing untrusted input. */
export function assertValidPluginSlug(slug: string): string {
  if (!isValidPluginSlug(slug)) {
    throw new Error(INVALID_PLUGIN_SLUG_MESSAGE);
  }
  return slug;
}
