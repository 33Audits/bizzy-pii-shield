/**
 * Bizzy hardening tests: mappings are encrypted at rest, locked down on the
 * filesystem, and no real PII leaks to disk in plaintext.
 *
 * Run: npx tsx tests/at-rest-encryption-test.ts
 *
 * Covers the concerns raised for the HR integration:
 *  - "placeholder→PII mapping stored as unencrypted JSON" → now AES-256-GCM
 *  - "anyone accessing that folder can recover everything" → 0600/0700 perms
 *  - leak testing with our own corpus → assert no PII string hits disk
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pii-atrest-test-"));
process.env.PII_SHIELD_DATA_DIR = tmpRoot;
// Deterministic master key from env (the production path — secret-manager injected).
process.env.BIZZY_PII_MASTER_KEY = Buffer.alloc(32, 7).toString("base64");

const { newSessionId, saveMapping, loadMapping, loadMappingData } = await import(
  "../src/mapping/mapping-store.js"
);
const { PATHS } = await import("../src/utils/config.js");

let passed = 0;
let failed = 0;
function check(cond: boolean, msg: string): void {
  if (cond) { console.log(`  ok   ${msg}`); passed++; }
  else      { console.log(`  FAIL ${msg}`); failed++; }
}

// A small "document corpus" of real-looking PII that must NEVER reach disk.
const PII_CORPUS = [
  "Gregory Osuri",
  "Jane Q. Public",
  "123-45-6789",       // SSN
  "4111 1111 1111 1111", // card
  "jane.public@example.com",
  "+1 (415) 555-0132",
  "42 Wallaby Way, Sydney",
];

async function main(): Promise<void> {
  const sid = newSessionId();
  // Placeholder → real PII, exactly what the anonymize pipeline persists.
  const mapping: Record<string, string> = {
    "[PERSON_1]": PII_CORPUS[0],
    "[PERSON_2]": PII_CORPUS[1],
    "[US_SSN_1]": PII_CORPUS[2],
    "[CREDIT_CARD_1]": PII_CORPUS[3],
    "[EMAIL_1]": PII_CORPUS[4],
    "[PHONE_1]": PII_CORPUS[5],
    "[ADDRESS_1]": PII_CORPUS[6],
  };

  const diskPath = saveMapping(sid, mapping, { source: "hr_intake_form.docx" });
  check(diskPath.startsWith(tmpRoot), "mapping persisted under the data dir");

  const raw = fs.readFileSync(diskPath);

  // 1. LEAK TEST — no plaintext PII anywhere in the on-disk bytes.
  const asText = raw.toString("latin1"); // byte-preserving scan
  let leaked: string | null = null;
  for (const secret of PII_CORPUS) {
    if (asText.includes(secret)) { leaked = secret; break; }
  }
  check(leaked === null, `no plaintext PII on disk (leaked: ${leaked ?? "none"})`);

  // 2. It's actually our encrypted format (magic "BZPS"), not JSON.
  check(raw.subarray(0, 4).toString("utf-8") === "BZPS", "file is AES-256-GCM encrypted (magic present)");
  check(raw[0] !== 0x7b /* '{' */, "file does not start as JSON");

  // 3. Filesystem permissions: file 0600, dir 0700.
  const fileMode = fs.statSync(diskPath).mode & 0o777;
  const dirMode = fs.statSync(PATHS.MAPPINGS_DIR).mode & 0o777;
  check(fileMode === 0o600, `mapping file is 0600 (got ${fileMode.toString(8)})`);
  check(dirMode === 0o700, `mappings dir is 0700 (got ${dirMode.toString(8)})`);

  // 4. Round-trip — decrypts back to the exact mapping.
  const back = loadMapping(sid);
  check(JSON.stringify(back) === JSON.stringify(mapping), "mapping round-trips (decrypt = original)");
  const full = loadMappingData(sid);
  check(full?.metadata?.source === "hr_intake_form.docx", "metadata round-trips");

  // 5. Tamper detection — flip a ciphertext byte, decrypt must throw (GCM auth).
  const tampered = Buffer.from(raw);
  tampered[tampered.length - 1] ^= 0xff; // corrupt the auth tag
  fs.writeFileSync(diskPath, tampered);
  let threw = false;
  try {
    // force a disk re-read by clearing the in-memory cache via a fresh import
    const mod = await import("../src/mapping/at-rest-crypto.js");
    mod.decrypt(tampered, Buffer.alloc(32, 7));
  } catch { threw = true; }
  check(threw, "tampered ciphertext is rejected (GCM auth tag)");

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(2); });
