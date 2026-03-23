# Keyva Transit — Plan

**Status:** Pre-build

Transit encryption API. The server manages encryption keys and performs encrypt/decrypt operations — plaintext data never touches disk. Applications send data in, get ciphertext back, store it wherever they want. When they need the plaintext, they send the ciphertext back.

This is Vault's transit secrets engine pattern, built on Keyva's foundation.

---

## Relationship to Keyva

Keyva Transit is a **sister product**, not a feature of Keyva. It shares the foundation (crypto, storage, key management, config, auth) but has its own command surface and domain types.

### Shared (zero/minimal changes)

| Layer | Reuse | Notes |
|-------|-------|-------|
| `keyva-crypto` | 100% | AES-256-GCM, HKDF, HMAC, SecretBytes, JWK — all stateless |
| `keyva-storage` WAL/snapshots/recovery | 95% | Add new OpType variants, content-agnostic otherwise |
| `KeyManager` + master key sources | 100% | Same HKDF derivation, same env/file chain |
| Auth system | 100% | Same token → policy → keyring-scoped ACLs |
| Config system | 95% | Same TOML + env vars, swap keyspace → keyring definitions |
| RESP3 codec | 100% | Same wire protocol, different verbs |
| Connection handler | 100% | Same accept loop, same TLS, same shutdown |
| Metrics + tracing | 100% | Same Prometheus + structured logging |
| Background schedulers | 90% | Rotation scheduler reused, revocation/refresh reapers not needed |

### New (~2-3K lines)

| Layer | What's new |
|-------|-----------|
| `transit-core` | Keyring type, key version, ciphertext envelope format, convergent encryption config |
| `transit-protocol` | Command enum (9 verbs), handlers, dispatcher |
| `transit-rest` | REST routes for all operations |
| Config | Keyring definitions instead of keyspace definitions |
| CLI | `keyva-transit-cli` (reuse keyva-cli architecture) |

---

## Repository Structure

**Separate repo: `keyva-io/keyva-transit`**

Option A from the analysis — extract shared foundation over time. For v1, the pragmatic approach:

```
keyva-transit/
  Cargo.toml
  src/
    main.rs           — CLI, config, server startup (mirrors keyva/src/main.rs)
    config.rs         — Keyring config from TOML
    server.rs         — TCP listener (reuse pattern from keyva)
    connection.rs     — Per-connection handler (reuse pattern)
  transit-core/
    src/
      lib.rs
      keyring.rs      — Keyring type (name, algorithm, versions, rotation policy)
      key_version.rs  — KeyVersion with state machine (Staged → Active → Draining → Retired)
      ciphertext.rs   — Ciphertext envelope format (version prefix + encrypted data)
      policy.rs       — Keyring policies (allowed operations, convergent encryption flag)
  transit-protocol/
    src/
      lib.rs
      command.rs      — Command enum (9 verbs)
      dispatch.rs     — Dispatcher
      handlers/
        encrypt.rs
        decrypt.rs
        rewrap.rs
        generate_data_key.rs
        sign.rs
        verify_signature.rs
        hash.rs
        rotate.rs
        key_info.rs
      resp3/          — Copy keyva-protocol/src/resp3 (same codec, different parse_command)
  transit-rest/
    src/
      lib.rs          — axum router
      routes.rs       — REST endpoints
```

Dependencies: `keyva-crypto` and `keyva-storage` from the main repo via git.

---

## Command Surface

### ENCRYPT

```
ENCRYPT <keyring> <plaintext> [CONTEXT <aad>] [KEY_VERSION <version>]
```

Encrypt plaintext with the active key version. Returns ciphertext that embeds the key version used.

- `plaintext` — base64-encoded data to encrypt
- `CONTEXT` — additional authenticated data (AAD). Must be provided again on decrypt. Use for binding ciphertext to a context (e.g., user ID, table name).
- `KEY_VERSION` — encrypt with a specific version instead of active (for testing/migration)

**Response:**
```
{status: OK, ciphertext: "v1:aGVsbG8...", key_version: 3}
```

The ciphertext format: `v{version}:{base64(nonce + encrypted + tag)}`. The version prefix lets DECRYPT find the right key without the caller tracking it.

### DECRYPT

```
DECRYPT <keyring> <ciphertext> [CONTEXT <aad>]
```

Decrypt ciphertext. Extracts the key version from the ciphertext prefix, finds the corresponding key (Active or Draining), decrypts.

- If the key version is Retired, return an error suggesting REWRAP first.
- If the key version is unknown, return NOTFOUND.
- Context (AAD) must match what was used during encryption.

**Response:**
```
{status: OK, plaintext: "aGVsbG8..."}
```

### REWRAP

```
REWRAP <keyring> <ciphertext> [CONTEXT <aad>]
```

Decrypt with the old key version, re-encrypt with the current active version. The caller's stored ciphertext gets updated without the plaintext ever leaving the server.

Use case: after key rotation, batch-REWRAP all stored ciphertext to use the new key version. This is optional — old versions in Draining state still decrypt — but it's good hygiene.

**Response:**
```
{status: OK, ciphertext: "v4:bmV3...", key_version: 4}
```

### GENERATE_DATA_KEY

```
GENERATE_DATA_KEY <keyring> [BITS <256|512>]
```

Envelope encryption pattern. Returns a fresh random data encryption key (DEK) in two forms:
1. `plaintext_key` — the raw DEK (base64). Use this to encrypt data locally.
2. `wrapped_key` — the DEK encrypted with the keyring's active key. Store this alongside your ciphertext.

To decrypt later: send `wrapped_key` to DECRYPT → get `plaintext_key` → decrypt locally.

Why: reduces round-trips for large data. Encrypt a 10GB file locally with the DEK, store the 32-byte wrapped key. Only the unwrap needs a Keyva Transit call.

**Response:**
```
{status: OK, plaintext_key: "...", wrapped_key: "v3:...", key_version: 3}
```

### SIGN

```
SIGN <keyring> <data> [ALGORITHM <algo>]
```

Create a detached signature over the data using the active key.

Algorithms: HMAC-SHA256 (symmetric), ECDSA-P256, Ed25519 (asymmetric — if keyring is configured for signing).

**Response:**
```
{status: OK, signature: "...", key_version: 3, algorithm: "hmac-sha256"}
```

### VERIFY_SIGNATURE

```
VERIFY_SIGNATURE <keyring> <data> <signature>
```

Verify a detached signature. Tries the key version embedded in the signature (or all Active + Draining versions if not embedded).

**Response:**
```
{status: OK, valid: true, key_version: 3}
```

### HASH

```
HASH <algorithm> <data>
```

One-way hash. Stateless — doesn't use a keyring.

Algorithms: `sha256`, `sha384`, `sha512`.

**Response:**
```
{status: OK, hash: "e3b0c442...", algorithm: "sha256"}
```

### ROTATE

```
ROTATE <keyring> [FORCE] [DRYRUN]
```

Same lifecycle as Keyva: Staged → Active → Draining → Retired.

After rotation, existing ciphertext still decrypts (Draining keys are still usable for decrypt). New encryptions use the new Active key. REWRAP migrates old ciphertext.

### KEY_INFO

```
KEY_INFO <keyring>
```

Returns all key versions with their state, creation time, algorithm.

**Response:**
```
{status: OK, keyring: "payments", algorithm: "aes-256-gcm", versions: [
  {version: 3, state: "active", created_at: 1711234567},
  {version: 2, state: "draining", created_at: 1708642567},
  {version: 1, state: "retired", created_at: 1706050567}
]}
```

---

## Keyring Configuration

```toml
[server]
bind = "0.0.0.0:6499"

[keyrings.payments]
algorithm = "aes-256-gcm"
rotation_days = 90
drain_days = 30

[keyrings.pii]
algorithm = "aes-256-gcm"
rotation_days = 30
drain_days = 14
convergent = true  # same plaintext + context → same ciphertext (deterministic)

[keyrings.signing]
algorithm = "ed25519"  # asymmetric keyring for SIGN/VERIFY
rotation_days = 365
```

**Convergent encryption:** When `convergent = true`, the nonce is derived from HMAC(key, plaintext + context) instead of random. Same input → same output. This enables encrypted search/deduplication at the cost of leaking equality (attacker can tell if two ciphertexts encrypt the same value). Useful for tokenization (SSN, email) where you need to look up by encrypted value.

---

## Ciphertext Envelope Format

```
v{version}:{base64url(nonce[12] || ciphertext || tag[16])}
```

- `version` — decimal key version number
- Separator `:` — splits version from payload
- Payload — base64url-encoded AES-256-GCM output (same format as keyva-crypto's aes_gcm_encrypt)

The version prefix is plaintext (not encrypted) so the server can route to the correct key without trial decryption.

---

## WAL Integration

Same WAL as Keyva with new OpType variants:

```rust
pub enum OpType {
    // Keyring lifecycle
    KeyringCreated    = 60,
    KeyVersionCreated = 61,
    KeyVersionRotated = 62,
    KeyringDisabled   = 63,
    KeyringEnabled    = 64,
}
```

The WAL stores keyring operations (creation, rotation, state changes). It does NOT store encrypted/decrypted data — transit operations are stateless from the WAL's perspective. Only key material mutations are durable.

---

## REST API

| Method | Path | Command |
|--------|------|---------|
| POST | `/v1/{keyring}/encrypt` | ENCRYPT |
| POST | `/v1/{keyring}/decrypt` | DECRYPT |
| POST | `/v1/{keyring}/rewrap` | REWRAP |
| POST | `/v1/{keyring}/generate-data-key` | GENERATE_DATA_KEY |
| POST | `/v1/{keyring}/sign` | SIGN |
| POST | `/v1/{keyring}/verify` | VERIFY_SIGNATURE |
| POST | `/v1/hash/{algorithm}` | HASH |
| POST | `/v1/{keyring}/rotate` | ROTATE |
| GET | `/v1/{keyring}/info` | KEY_INFO |
| GET | `/v1/health` | HEALTH |
| GET | `/metrics` | Prometheus |

---

## Default Port

`6499` — distinct from Keyva's `6399`. Both can run on the same host.

URI scheme: `keyva-transit://host:port` or `kvt://host:port`.

---

## Security Model

- **Plaintext never touches disk.** Encrypt/decrypt operations happen in memory. The WAL only stores key material (encrypted with the master key).
- **Key material is double-encrypted.** Same pattern as Keyva: master key → HKDF → per-keyring key → per-version encryption.
- **Context binding (AAD).** ENCRYPT with CONTEXT binds the ciphertext to that context. Decrypting with a different context fails. Use for: encrypting a credit card number with the user ID as context — prevents moving the ciphertext to a different user.
- **Convergent encryption is opt-in and documented.** It leaks equality. The config flag makes this an explicit operator decision.

---

## What Keyva Transit is NOT

- **Not a secrets manager.** It doesn't store your secrets — it encrypts/decrypts data you send it. If you want to store a secret, use Keyva (API key keyspace with metadata).
- **Not a certificate authority.** It doesn't issue X.509 certificates.
- **Not a key escrow.** Key material cannot be exported. The keys exist only inside Transit.

---

## Build Order

1. **transit-core** — Keyring, KeyVersion, ciphertext format, convergent encryption
2. **transit-protocol** — Command enum + handlers (ENCRYPT/DECRYPT first, then REWRAP, GENERATE_DATA_KEY, SIGN/VERIFY, HASH, ROTATE, KEY_INFO)
3. **Storage integration** — WAL OpTypes for keyring operations, snapshot support
4. **Server binary** — config, TCP listener, REST proxy
5. **CLI** — `keyva-transit-cli` for interactive use
6. **Client libraries** — extend existing SDKs with transit methods, or separate packages

---

## Relationship to Keyva Session

Transit and Session are independent products that both build on Keyva:

```
                    ┌─────────────────┐
                    │   Application   │
                    └──┬──────────┬───┘
                       │          │
              ┌────────▼──┐  ┌───▼──────────┐
              │  Session   │  │   Transit    │
              │ (cookies,  │  │ (encrypt,    │
              │  CSRF,     │  │  decrypt,    │
              │  OAuth)    │  │  sign,       │
              └──────┬─────┘  │  rewrap)     │
                     │        └──────┬───────┘
                     │               │
                     └───────┬───────┘
                             │
                      ┌──────▼──────┐
                      │    Keyva    │
                      │ (keys,     │
                      │  passwords,│
                      │  tokens)   │
                      └─────────────┘
```

Session depends on Keyva (for auth primitives). Transit depends on Keyva's foundation (crypto, storage) but not on Keyva's credential types. They don't depend on each other.
