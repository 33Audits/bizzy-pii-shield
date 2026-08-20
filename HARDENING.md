# Bizzy PII Shield — Hardening Status

Fork of `gregmos/PII-Shield`, hardened as a **privacy preprocessing layer** for
Bizzy's HR integration (and contract/audit/healthcare/finance docs). The upstream
product pattern is good — local GLiNER detection → placeholders → LLM → restore.
This fork fixes the implementation gaps that block trusting it with real PII.

**It is NOT a PII guarantee.** Detection can miss entities (upstream has an open
issue on missed person names). Mandatory human review stays in the workflow.

## Threat model

Protects real identities against: filesystem access to the mappings folder,
backups/snapshots of that folder, and casual disk inspection. Does NOT protect
against: a compromised host with the live key in memory, or a user attaching the
*original* file to the LLM before running the shield (workflow discipline).

## Done (this fork)

| Concern (from review) | Fix | Verified |
|---|---|---|
| Mapping stored as **plaintext JSON** — anyone with the folder recovers everything | `mapping/at-rest-crypto.ts`: AES-256-GCM + scrypt on write/read | `tests/at-rest-encryption-test.ts` |
| **Loose filesystem perms** | mappings dir `0700`, mapping + key files `0600` | same test |
| **No leak testing** | Leak test scans on-disk bytes for a PII corpus, asserts none present | same test (9/9 pass) |
| Key handling | `BIZZY_PII_MASTER_KEY` env (secret-manager path, preferred) or auto `0600` keyfile fallback | — |
| Tamper | GCM auth tag; decrypt rejects modified ciphertext | same test |

Legacy plaintext mapping files remain readable and are re-encrypted on next save
(smooth migration).

### Key management

- **Production / HR / client data:** inject `BIZZY_PII_MASTER_KEY` (32 bytes, hex
  or base64) from a secret manager / 1Password so the key never shares the disk
  with the ciphertext.
- **Fallback:** a `0600` keyfile beside the mappings dir, generated on first use.
  Adds a real barrier over plaintext, but same-host — use the env key for clients.

## Remaining before client/HR use (tracked)

1. **Network isolation** — assert the anonymize path makes zero outbound calls
   after the model is cached (guard + a test that fails on any socket during
   anonymize). Model download is a one-time, explicit, online step.
2. **Leak corpus** — expand `PII_CORPUS` with our own HR/contract documents and
   run detection end-to-end (not just the store), catching missed entities.
3. **Mandatory human review** — make the review gate non-skippable in the Bizzy
   workflow (upstream `start_review`/`apply_review_overrides` exist; enforce).
4. **Log redaction** — audit its error logger (`mcp_audit.log`, exception
   messages) so it never records sensitive fragments.
5. **Orphaned-process / unbounded-log** upstream issues — verify fixed or fix.

## Run the tests

```
cd nodejs-v2
npm install --ignore-scripts
npx tsx tests/at-rest-encryption-test.ts   # leak + encryption + perms
npm run tsc:check                          # type check
```
