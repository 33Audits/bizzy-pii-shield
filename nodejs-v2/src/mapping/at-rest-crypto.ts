/**
 * At-rest encryption for placeholder↔PII mappings.
 *
 * Bizzy hardening (33audits): the upstream mapping store persisted the
 * placeholder→PII map as PLAINTEXT JSON, so anyone with filesystem access could
 * recover every real identity. This module encrypts the mapping blob with
 * AES-256-GCM before it touches disk. Same primitives as session-archive.ts
 * (scrypt KDF + AES-256-GCM), self-contained so the mapping store has no new
 * cross-module coupling.
 *
 * Key source, in priority order:
 *   1. BIZZY_PII_MASTER_KEY env var — 32 bytes as base64 or hex. PREFERRED for
 *      production: inject from a secret manager / 1Password so the key is never
 *      on the same disk as the ciphertext.
 *   2. A local keyfile (0600) auto-generated on first use. Adds a real barrier
 *      over plaintext, but the key sits on the same host — use the env key for
 *      client/HR data.
 *
 * File format (matches session-archive):
 *   magic(4) | version(1)+reserved(3) | salt(16) | nonce(12) | ctlen(4) | ct | authTag(16)
 */
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

const MAGIC = Buffer.from("BZPS", "utf-8"); // Bizzy Pii Shield
const VERSION = 0x01;
const SALT_LEN = 16;
const NONCE_LEN = 12;
const KEY_LEN = 32;
const AUTH_TAG_LEN = 16;
const SCRYPT_OPTS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

let _masterKeyCache: Buffer | null = null;

function decodeEnvKey(raw: string): Buffer {
  const s = raw.trim();
  // hex (64 chars) or base64
  const buf = /^[0-9a-fA-F]{64}$/.test(s)
    ? Buffer.from(s, "hex")
    : Buffer.from(s, "base64");
  if (buf.length !== KEY_LEN) {
    throw new Error(
      `BIZZY_PII_MASTER_KEY must decode to ${KEY_LEN} bytes (got ${buf.length}). Provide 32 random bytes as hex or base64.`,
    );
  }
  return buf;
}

/**
 * Resolve the master key. `keyfilePath` is where the fallback keyfile lives
 * (created 0600 if the env key is absent).
 */
export function getMasterKey(keyfilePath: string): Buffer {
  if (_masterKeyCache) return _masterKeyCache;

  const envKey = process.env.BIZZY_PII_MASTER_KEY;
  if (envKey) {
    _masterKeyCache = decodeEnvKey(envKey);
    return _masterKeyCache;
  }

  // Keyfile fallback — generate on first use, lock to 0600.
  try {
    const existing = fs.readFileSync(keyfilePath);
    if (existing.length === KEY_LEN) {
      _masterKeyCache = existing;
      return _masterKeyCache;
    }
  } catch {
    // not present yet — create below
  }
  const key = crypto.randomBytes(KEY_LEN);
  fs.mkdirSync(path.dirname(keyfilePath), { recursive: true, mode: 0o700 });
  // wx = fail if it appeared concurrently; 0600 owner-only.
  try {
    fs.writeFileSync(keyfilePath, key, { mode: 0o600, flag: "wx" });
    _masterKeyCache = key;
  } catch {
    // lost a race — read whoever won
    _masterKeyCache = fs.readFileSync(keyfilePath);
  }
  try {
    fs.chmodSync(keyfilePath, 0o600);
  } catch {
    /* best effort */
  }
  return _masterKeyCache;
}

/** Encrypt a UTF-8 plaintext blob (the mapping JSON) into the on-disk format. */
export function encrypt(plaintext: string, masterKey: Buffer): Buffer {
  const salt = crypto.randomBytes(SALT_LEN);
  const nonce = crypto.randomBytes(NONCE_LEN);
  const key = crypto.scryptSync(masterKey, salt, KEY_LEN, SCRYPT_OPTS);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  const ct = Buffer.concat([
    cipher.update(Buffer.from(plaintext, "utf-8")),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  const header = Buffer.alloc(4 + 4);
  MAGIC.copy(header, 0);
  header.writeUInt8(VERSION, 4); // bytes 5-7 reserved (zero)
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(ct.length, 0);
  return Buffer.concat([header, salt, nonce, lenBuf, ct, authTag]);
}

/** True if a buffer is our encrypted format (vs a legacy plaintext JSON file). */
export function isEncrypted(buf: Buffer): boolean {
  return buf.length >= 4 && buf.subarray(0, 4).equals(MAGIC);
}

/** Decrypt an on-disk blob back to the mapping JSON string. Throws on tamper. */
export function decrypt(buf: Buffer, masterKey: Buffer): string {
  if (!isEncrypted(buf)) {
    throw new Error("Not a Bizzy PII Shield encrypted mapping (bad magic).");
  }
  let off = 4;
  const version = buf.readUInt8(off);
  off = 8; // skip reserved
  if (version !== VERSION) {
    throw new Error(`Unsupported mapping format version ${version}.`);
  }
  const salt = buf.subarray(off, off + SALT_LEN);
  off += SALT_LEN;
  const nonce = buf.subarray(off, off + NONCE_LEN);
  off += NONCE_LEN;
  const ctLen = buf.readUInt32BE(off);
  off += 4;
  const ct = buf.subarray(off, off + ctLen);
  off += ctLen;
  const authTag = buf.subarray(off, off + AUTH_TAG_LEN);

  const key = crypto.scryptSync(masterKey, salt, KEY_LEN, SCRYPT_OPTS);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(authTag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt.toString("utf-8");
}

/** Test-only: reset the cached key (so tests can swap env keys). */
export function _resetKeyCacheForTests(): void {
  _masterKeyCache = null;
}
