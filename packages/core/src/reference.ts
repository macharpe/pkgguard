/**
 * A short code tying together what a blocked developer sees, the Chat alert and the detection row, so
 * "I got PG-7Q2K4M" is enough to find the event.
 *
 * Crockford base32 without I, L, O and U, so it survives being read aloud or retyped. 256 is a multiple of 32,
 * so masking a random byte to five bits has no modulo bias. Six characters is 2^30 values: plenty to tell
 * events apart, and not a secret.
 */
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const LENGTH = 6;

export const REFERENCE_PATTERN = /^PG-[0-9A-HJKMNP-TV-Z]{6}$/;

export type RandomFill = (bytes: Uint8Array<ArrayBuffer>) => Uint8Array;

/** The source of randomness is injected so this package needs no platform APIs: pass `(b) => crypto.getRandomValues(b)`. */
export function newReference(random: RandomFill): string {
  const bytes = random(new Uint8Array(new ArrayBuffer(LENGTH)));
  let out = "PG-";
  for (let i = 0; i < LENGTH; i++) out += ALPHABET[(bytes[i] ?? 0) & 31];
  return out;
}

export const isReference = (value: unknown): value is string => typeof value === "string" && REFERENCE_PATTERN.test(value);
