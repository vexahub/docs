# Vexahub — Cryptography Specification

**Document version:** 2
**Protocol version:** 1
**Status:** Draft — pre-MVP

This document is the single source of truth for all cryptographic decisions in Vexahub. Any change to the parameters, algorithms, derivation paths, or binary formats defined here is a breaking change for existing accounts and MUST bump the protocol version (see §13).

## 1. Overview

Vexahub is a zero-knowledge end-to-end encrypted cloud storage service. The server never has access to user passwords, plaintext files, file names, or encryption keys capable of decrypting user data during normal operation.

Cryptographic goals:

- The server cannot decrypt user files, even with full database access.
- An attacker stealing only the database cannot mount offline password attacks (OPAQUE OPRF defense).
- Password changes do not require re-encrypting user files.
- File mutation is supported without nonce-reuse vulnerabilities.
- Sharing is possible between users without the server learning shared content.
- Post-quantum resistance for sharing key exchange.
- Cross-platform consistency (web, desktop, future Android/iOS) via a single Rust implementation compiled to WASM, native, NAPI, and UniFFI targets.

Explicit non-goals:

- Defense against a fully compromised server colluding with itself to attack a user during an active session. A persistent session (§9.2) opt-in widens this surface and is documented as such.
- Defense against a malicious client update pushed via the normal distribution channel. Reproducible builds are tracked as future work (§18).
- Defense against an attacker with physical control of the user's unlocked device.

## 2. Primitives

| Purpose                     | Algorithm                  | Parameters                                           |
|-----------------------------|----------------------------|------------------------------------------------------|
| Password-authenticated AKE  | OPAQUE (RFC 9807)          | Ristretto255 ciphersuite, 3DH AKE                    |
| Key stretching (in OPAQUE)  | Argon2id                   | m = 196608 KiB (192 MiB), t = 3, p = 4               |
| Symmetric AEAD              | XChaCha20-Poly1305         | 24-byte nonces, 16-byte tags                         |
| Key derivation              | HKDF-SHA-512               | Domain-separated `info`, zero salt                   |
| Classical key agreement     | X25519                     | Sharing only                                         |
| Post-quantum KEM            | ML-KEM-768 (FIPS 203)      | Hybrid with X25519 for sharing                       |
| CSPRNG                      | OS CSPRNG                  | `getrandom` (Rust), `crypto.getRandomValues` (web)   |
| Memory hygiene              | `zeroize` crate            | All key material wrapped in `Zeroizing<T>`           |

**Rationale:**

- **Ristretto255** over P-256: prime-order group, simpler hash-to-curve, better-maintained constant-time implementations in the Rust ecosystem.
- **Argon2id 192 MiB / t=3 / p=4**: well above OWASP 2024 and industry baselines (Bitwarden, 1Password sit around 64 MiB), while staying below the ~256 MiB threshold where Safari iOS WASM allocations begin to fail. OPAQUE OPRF already neutralizes pre-computation attacks against the database; the Argon2id cost is a defense-in-depth layer for the case where `serverSetup` is also compromised. Frozen identical for all users on protocol version 1 — no per-user fallback, no heterogeneous parameters.
- **XChaCha20-Poly1305** over AES-GCM: 24-byte nonces make random nonce generation safe without counters; constant-time on all platforms; no hardware AES dependency.
- **HKDF-SHA-512**: matches the OPAQUE ciphersuite hash, universally available, larger output reservoir than SHA-256 with no performance penalty in this context.
- **Hybrid X25519 + ML-KEM-768** for sharing: defense in depth against both classical and post-quantum cryptanalytic advances.

## 3. Key Hierarchy

```rs
password (user input, never leaves the client)
    │
    ▼ OPAQUE (Argon2id client-side, OPRF server-side)
    │
    ├──► exportKey (64 bytes, client-only, stable across logins)
    │       │
    │       ▼ HKDF-SHA-512
    │       │
    │       └──► masterKeyWrapper (32 bytes) ──► unwraps masterKey
    │
    └──► sessionKey (negotiated with server, used to mint API session cookie)


masterKey (32 bytes, generated once at registration via CSPRNG)
    │
    ├──► wrapped by masterKeyWrapper ──► VXWM blob (stored server-side)
    ├──► wrapped by recoveryKey       ──► VXRM blob (stored server-side)
    │
    └──► HKDF-SHA-512 with collection_id as info
          │
          └──► collectionKey (32 bytes, per collection)
                 │
                 └──► HKDF-SHA-512 with file_id as info
                        │
                        └──► fileKey (32 bytes, per file)
                               │
                               ├──► fileContentKey  = HKDF(fileKey, "...fileContentKey")
                               └──► fileMetadataKey = HKDF(fileKey, "...fileMetadataKey")


sharingKeyPair (generated at registration)
    │
    ├──► X25519 keypair         (private wrapped by masterKey)
    └──► ML-KEM-768 keypair     (private wrapped by masterKey)
          public keys stored server-side in plaintext
```

The intermediate `masterKeyWrapper` exists for uniformity with all other derivations and to avoid using `exportKey` directly as an AEAD key. It carries no extra security versus a direct slice of `exportKey`, but keeps the derivation graph consistent.

### 3.1 Key summary

| Key              | Size  | Origin                              | Lifetime  | Server sees             |
|------------------|-------|-------------------------------------|-----------|-------------------------|
| password         | var   | User input                          | Typing    | Never                   |
| exportKey        | 64    | OPAQUE output                       | Session   | Never                   |
| masterKeyWrapper | 32    | HKDF(exportKey)                     | Session   | Never                   |
| sessionKey       | 64    | OPAQUE output                       | Session   | Yes (used for cookie)   |
| masterKey        | 32    | CSPRNG at registration              | Permanent | Wrapped only            |
| collectionKey    | 32    | HKDF(masterKey, collection_id)      | Permanent | Never (derived client)  |
| fileKey          | 32    | HKDF(collectionKey, file_id)        | Permanent | Never (derived client)  |
| recoveryKey      | 32    | HKDF(BIP39 seed)                    | Recovery  | Never                   |
| X25519 priv      | 32    | CSPRNG at registration              | Permanent | Wrapped only            |
| ML-KEM-768 priv  | ~2400 | CSPRNG at registration              | Permanent | Wrapped only            |

## 4. HKDF Domain Separation

All HKDF derivations use HKDF-SHA-512 with a 32-byte zero salt and a unique `info` string. Format: `vexahub:v{PROTOCOL_VERSION}:{purpose}[:{context}]`.

| Derivation                          | `info` string                                      | length |
|-------------------------------------|----------------------------------------------------|--------|
| masterKeyWrapper from exportKey     | `vexahub:v1:masterKeyWrapper`                      | 32     |
| collectionKey from masterKey        | `vexahub:v1:collectionKey:{collection_uuid}`       | 32     |
| fileKey from collectionKey          | `vexahub:v1:fileKey:{file_uuid}`                   | 32     |
| fileContentKey from fileKey         | `vexahub:v1:fileContentKey`                        | 32     |
| fileMetadataKey from fileKey        | `vexahub:v1:fileMetadataKey`                       | 32     |
| segmentNonce from fileContentKey    | `vexahub:v1:segmentNonce:{generation}:{index}`     | 24     |
| recoveryKey from BIP39 seed         | `vexahub:v1:recoveryKey:{user_uuid}`               | 32     |
| shareWrapKey from hybrid shared sec | `vexahub:v1:shareWrap:{share_uuid}`                | 32     |

HKDF salts are not secrets; uniqueness is enforced exclusively by the `info` field. Zero salt simplifies cross-platform interoperability and has no security impact when `info` is unique per purpose.

## 5. Binary Blob Formats

All encrypted blobs use versioned, self-describing binary formats prefixed with 4 magic bytes, a format version, and an algorithm ID. Parsers MUST verify magic, version, and algorithm before decryption. Unknown values MUST cause an error, never a silent fallback.

Algorithm IDs:

- `0x01` — XChaCha20-Poly1305

### 5.1 `VXWM` — Wrapped Master Key (password-derived)

```rs
Offset  Size  Field
------  ----  ---------------------------------------
0       4     Magic "VXWM" (0x56 0x58 0x57 0x4D)
4       1     Format version (0x01)
5       1     Algorithm ID (0x01)
6       24    Nonce (random)
30      48    Ciphertext (32 B masterKey + 16 B tag)
------
Total: 78 bytes
```

### 5.2 `VXRM` — Wrapped Master Key (recovery-phrase-derived)

Identical structure to `VXWM`, distinct magic to prevent cross-use.

```rs
Offset  Size  Field
0       4     Magic "VXRM" (0x56 0x58 0x52 0x4D)
4       1     Format version (0x01)
5       1     Algorithm ID (0x01)
6       24    Nonce (random)
30      48    Ciphertext (32 B masterKey + 16 B tag)
Total: 78 bytes
```

### 5.3 `VXFC` — File Content Segment

```rs
Offset  Size   Field
0       4      Magic "VXFC"
4       1      Format version (0x01)
5       1      Algorithm ID (0x01)
6       4      File generation (uint32 BE, see §6.3)
10      8      Segment index (uint64 BE)
18      24    Nonce (derived deterministically, see §6.2)
42      N+16   Ciphertext + tag
```

The AAD bound to each segment is the 14-byte tuple `version || alg_id || generation || segment_index`. This binds every ciphertext to its position and generation, preventing reorder and rollback attacks within a file.

### 5.4 `VXFM` — File Metadata

```rs
Offset  Size   Field
0       4      Magic "VXFM"
4       1      Format version (0x01)
5       1      Algorithm ID (0x01)
6       4      File generation (uint32 BE)
10      24     Nonce (random)
34      N+16   Ciphertext (CBOR-encoded metadata) + tag
```

CBOR schema for plaintext metadata (canonical CBOR, RFC 8949 §4.2.1):

```rs
{
  "n":  tstr,           // filename
  "m":  tstr,           // mime type
  "s":  uint,           // plaintext size in bytes
  "ct": uint,           // creation time, unix seconds
  "mt": uint,           // modification time, unix seconds
  "h":  bstr .size 32,  // BLAKE3 hash of plaintext (integrity)
}
```

Unknown CBOR keys MUST be preserved on re-encryption to allow forward-compatible field additions.

### 5.5 `VXPS` — Persistent Session Blob

Stored in IndexedDB on the user's device when "Remember me" is enabled.

```rs
Offset  Size  Field
0       4     Magic "VXPS"
4       1     Format version (0x01)
5       1     Algorithm ID (0x01)
6       24    Nonce (random)
30      48    Ciphertext (32 B masterKey + 16 B tag)
Total: 78 bytes
```

### 5.6 `VXSK` — Wrapped Sharing Keys

```rs
Offset  Size   Field
0       4      Magic "VXSK"
4       1      Format version (0x01)
5       1      Algorithm ID (0x01)
6       24     Nonce (random)
30      N+16   Ciphertext (CBOR object) + tag
```

CBOR schema:

```json
{
  "x":  bstr .size 32,    // X25519 private key
  "m":  bstr,             // ML-KEM-768 private key (decapsulation key)
}
```

## 6. File Encryption

### 6.1 Segmentation

Files are split into fixed-size plaintext segments. MVP segment size: **1 MiB** (1,048,576 bytes). The last segment may be shorter. Fixed segment size enables byte-precise Range requests on ciphertext, resumable uploads via `tus`, and parallel processing.

### 6.2 Per-segment nonce derivation

Segment nonces are derived deterministically from the file generation and segment index:

```rs
nonce = HKDF-SHA-512(
    ikm  = fileContentKey,
    salt = 32 zero bytes,
    info = "vexahub:v1:segmentNonce:" || uint32_be(generation) || ":" || uint64_be(segment_index),
    L    = 24
)
```

### 6.3 File generation counter (mutability)

Each file carries a `generation` counter starting at `0` at creation. **Any modification to file content increments `generation` by 1** before re-encryption. The new generation is stored server-side atomically with the new ciphertext blobs.

This prevents the catastrophic XChaCha20-Poly1305 nonce-reuse vulnerability that would otherwise occur when re-encrypting a modified segment with the same `(fileContentKey, segment_index)` pair. By including `generation` in the HKDF info, every modification produces a fresh nonce space.

**Mandatory invariants:**

- The server MUST reject any upload whose `generation` value is less than or equal to the currently stored generation for that file.
- The server MUST store `generation` in the file row and return it with file metadata so clients can verify monotonicity.
- When a client uploads a new generation, all segments belonging to that generation MUST be uploaded atomically (transactional or staged commit). Partial generation uploads MUST be garbage-collected after a short TTL.
- Clients MUST refuse to decrypt a segment whose `generation` field in the `VXFC` header does not match the expected generation from file metadata.

The `generation` field is 32 bits, providing 4 billion modifications per file. This is effectively unbounded for any realistic workload.

### 6.4 Content vs metadata key separation

`fileContentKey` and `fileMetadataKey` are derived from the same `fileKey` via distinct HKDF info strings. This prevents any cross-use of nonces between content segments and metadata blobs.

### 6.5 Resumable upload integration

- Format de l'upload tus : `Upload-Length` est en bytes ciphertext.
`segment_index = floor(upload_offset / SEGMENT_CIPHERTEXT_SIZE).`
- Le client MUST ré-uploader depuis le début du segment courant, jamais au milieu d'un segment (parce que XChaCha20 ne supporte pas les writes partiels d'un AEAD).
- Le serveur MUST persister (file_id, generation) avec chaque upload tus en cours et rejeter tout PATCH qui arrive avec un mismatch.
- Sur changement de generation pendant un upload en cours, l'upload tus est invalidé et le client doit en démarrer un nouveau.

## 7. OPAQUE Protocol

### 7.1 Implementation

Vexahub implements OPAQUE (RFC 9807) in a single Rust crate, `vexahub-protocol`, which serves as the cryptographic source of truth for all clients and the server. The crate is compiled to:

- **WebAssembly** via `wasm-bindgen` for the SvelteKit webapp.
- **Native** Rust linkage for the Tauri desktop application.
- **NAPI-RS** bindings for the NestJS backend.
- **UniFFI** bindings for future Android (Kotlin) and iOS (Swift) clients.

A single implementation produces byte-for-byte identical outputs across all targets, verified by the cross-target test vectors in §14.

### 7.2 Ciphersuite (frozen at protocol version 1)

- OPRF group: Ristretto255
- KE group: Ristretto255
- Hash: SHA-512
- Key exchange: 3DH (Triple Diffie-Hellman)
- Key stretching function: Argon2id with the parameters in §2

This ciphersuite is identical across every client and the server. Any change is a protocol version bump.

### 7.3 Server setup

At first deployment, the server generates a one-time `serverSetup` containing the OPRF secret key (the global pepper) and the server's static AKE keypair.

**Storage requirements:**

- Loaded into NestJS via the `OPAQUE_SERVER_SETUP` environment variable.
- NEVER committed to Git, NEVER logged, NEVER returned in any API response.
- Backed up encrypted in at least two independent locations (Passbolt vault + offline encrypted backup on cold storage).
- Rotation invalidates all existing accounts and is treated strictly as a disaster-recovery action.

**Loss of `serverSetup` = permanent loss of all user accounts.** Backup discipline is non-negotiable.

### 7.4 Server static public key pinning

All clients pin the server's static public key, derived from `serverSetup` and hardcoded at build time. On every OPAQUE flow completion, the client compares the received `serverStaticPublicKey` against the pinned value. Mismatch MUST abort the flow and surface a security warning to the user.

This defends against a substituted server, contingent on the client distribution channel not being compromised (see §17 and §18).

## 8. Registration and Login Flows

### 8.1 Registration

1. Client: user enters email and password.
2. Client: `opaque.client.startRegistration({ password })` → `{ clientRegistrationState, registrationRequest }`.
3. Client → Server: `POST /auth/register/start { email, registrationRequest }`.
4. Server: verifies email is not already registered.
5. Server: `opaque.server.createRegistrationResponse({ serverSetup, userIdentifier: email, registrationRequest })` → `{ registrationResponse }`.
6. Server → Client: `{ registrationResponse, continuationToken }`.
7. Client: `opaque.client.finishRegistration(...)` → `{ registrationRecord, exportKey, serverStaticPublicKey }`.
8. Client: verifies `serverStaticPublicKey` matches the hardcoded pin; aborts on mismatch.
9. Client: derives `masterKeyWrapper` from `exportKey`.
10. Client: generates `masterKey` (32 random bytes from CSPRNG).
11. Client: generates X25519 and ML-KEM-768 sharing keypairs.
12. Client: wraps `masterKey` with `masterKeyWrapper` → `VXWM` blob.
13. Client: wraps sharing private keys with `masterKey` → `VXSK` blob.
14. Client: generates a 24-word BIP39 recovery phrase, derives `recoveryKey`, wraps `masterKey` → `VXRM` blob (see §12).
15. Client: requires the user to confirm the recovery phrase by re-entering specific word positions.
16. Client → Server: `POST /auth/register/finish { email, continuationToken, registrationRecord, vxwm, vxsk, vxrm, sharingPublicX25519, sharingPublicMlkem }`.
17. Server: stores the user row atomically.
18. Client: zeroizes `password`, `exportKey`, `masterKeyWrapper`, plaintext private keys, recovery phrase, `recoveryKey`. Keeps `masterKey` and sharing private keys live in the Crypto Worker.

### 8.2 Login

1. Client: user enters email and password.
2. Client: `opaque.client.startLogin({ password })` → `{ clientLoginState, startLoginRequest }`.
3. Client → Server: `POST /auth/login/start { email, startLoginRequest }`.
4. Server: looks up the user, loads `registrationRecord`.
5. Server: `opaque.server.startLogin(...)` → `{ loginResponse, serverLoginState }`.
6. Server: stores `serverLoginState` in Valkey under a random `continuationToken` with a 60-second TTL.
7. Server → Client: `{ loginResponse, continuationToken, vxwm, vxsk }`.
8. Client: `opaque.client.finishLogin(...)` → `{ finishLoginRequest, sessionKey, exportKey, serverStaticPublicKey }`.
9. Client: verifies pinned key.
10. Client: derives `masterKeyWrapper`, parses `VXWM`, decrypts `masterKey`.
11. Client: parses `VXSK`, decrypts sharing private keys with `masterKey`.
12. Client → Server: `POST /auth/login/finish { continuationToken, finishLoginRequest }`.
13. Server: retrieves and immediately deletes `serverLoginState` from Valkey.
14. Server: `opaque.server.finishLogin(...)` → `{ sessionKey }`.
15. Server: derives an HTTP session token from `sessionKey`, stores a hashed session row in Postgres, returns `HttpOnly; Secure; SameSite=Strict` cookie.
16. Client: zeroizes `password`, `exportKey`, `masterKeyWrapper`. `masterKey` and sharing private keys are loaded into the Crypto Web Worker.

## 9. Session Management

### 9.1 Active sessions (default)

- `masterKey` and sharing private keys live exclusively inside a dedicated Crypto Web Worker, never in the main thread's JavaScript heap.
- Main ↔ Worker communication uses a strict request/response protocol (`encryptFileSegment`, `decryptFileSegment`, `deriveCollectionKey`, `wrapForSharing`, `unwrapFromSharing`). The Worker never returns raw key material, only operation results.
- Inactivity timeout: 30 minutes. On timeout, the Worker is terminated and all in-memory key material is zeroized; the user must re-authenticate.
- Session cookie: 24-hour absolute lifetime, renewed on activity, `HttpOnly; Secure; SameSite=Strict`.
- Closing the tab destroys the Worker and the `masterKey`. Without a persistent session, the next visit requires a fresh login.
- Worker script is served same-origin under strict CSP (§16), no inline, no eval beyond `wasm-unsafe-eval`.

### 9.2 Persistent sessions ("Remember me", opt-in)

A device-bound resume mechanism. NEVER enabled by default.

Activation:

1. Client generates `localKey` (32 random bytes).
2. Client wraps `masterKey` with `localKey` → `VXPS` blob, stored in IndexedDB.
3. Client uploads `localKey` to the server via `POST /auth/persistent-session/create { localKey, deviceLabel }`.
4. Server stores `{ userId, localKey, cookieHash, deviceLabel, createdAt, expiresAt }` in `persistent_sessions`.
5. Server issues a `PS-AUTH` cookie: `HttpOnly; Secure; SameSite=Strict; Max-Age=30d`.

Resume:

1. Client detects existing `VXPS` blob and `PS-AUTH` cookie.
2. Client offers a "Resume as <|user|>" prompt instead of the password form.
3. `GET /auth/persistent-session/resume` (cookie auto-attached).
4. Server validates cookie, fetches `localKey`, returns `{ localKey, vxsk }`.
5. Client decrypts `VXPS` with `localKey`, loads `masterKey` into the Worker.
6. Server issues a fresh active-session cookie alongside the persistent one.

**Trade-off (must be displayed at opt-in):**

> Remember me stores an encrypted copy of your keys on this device. The key to unlock them is held by Vexahub servers. Under normal operation your data stays private, but an attacker who fully controls our servers AND captures your session cookie could decrypt this remembered session. For maximum security, leave this option off and sign in with your password each time.

Mandatory safeguards:

- Strict opt-in.
- Settings page listing every persistent session with device label, creation time, last use, and a one-click revoke.
- Password change revokes all persistent sessions.
- Server-side inactivity timeout: `localKey` deleted after 30 days of disuse.
- "Sign out everywhere" wipes server-side persistent sessions and the local IndexedDB blob.
- `localKey` is NEVER stored client-side in plaintext beyond the moment it is used to decrypt the `VXPS` blob.

### 9.3 Session schemas

```sql
CREATE TABLE sessions (
    id           UUID PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cookie_hash  BYTEA NOT NULL,           -- SHA-256 of the cookie value
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ,
    user_agent   TEXT,
    ip_network   INET
);

CREATE TABLE persistent_sessions (
    id           UUID PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    local_key    BYTEA NOT NULL,
    cookie_hash  BYTEA NOT NULL,
    device_label TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ
);

CREATE INDEX ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX ON persistent_sessions (user_id) WHERE revoked_at IS NULL;
```

## 10. Server-side Storage

### 10.1 Users table

```sql
CREATE TABLE users (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                    CITEXT UNIQUE NOT NULL,
    locale                   TEXT NOT NULL DEFAULT 'en',
    opaque_protocol_version  SMALLINT NOT NULL DEFAULT 1,
    registration_record      BYTEA NOT NULL,
    vxwm                     BYTEA NOT NULL,
    vxrm                     BYTEA NOT NULL,
    vxsk                     BYTEA NOT NULL,
    sharing_public_x25519    BYTEA NOT NULL,
    sharing_public_mlkem     BYTEA NOT NULL,
    reset_generation         INTEGER NOT NULL DEFAULT 0,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### 10.2 What the server knows vs does not know

**Knows:** email, `registrationRecord` (opaque envelope), wrapped key blobs, public sharing keys, file existence and ciphertext size, file/collection UUIDs, hierarchy, timestamps, locale, `localKey` for any active persistent sessions only.

**Does not know:** password, `masterKey`, `exportKey`, `masterKeyWrapper`, `collectionKey`, `fileKey`, file content, file names, mime types, any plaintext metadata.

## 11. Sharing (Hybrid X25519 + ML-KEM-768)

Sharing wraps a `collectionKey` or `fileKey` such that only the recipient can unwrap it.

Send flow:

1. Sender fetches recipient's public X25519 and ML-KEM-768 keys from the server.
2. Sender generates an ephemeral X25519 keypair `(eskX, epkX)`.
3. Sender computes `ssX = X25519(eskX, recipientPubX)`.
4. Sender encapsulates to `recipientPubMlkem`: `(ctMlkem, ssMlkem) = ML-KEM-768.Encaps(recipientPubMlkem)`.
5. Sender derives `shareWrapKey = HKDF-SHA-512(ikm = ssX || ssMlkem, info = "vexahub:v1:shareWrap:{share_uuid}", L = 32)`.
6. Sender wraps the target key (collection or file) with `shareWrapKey` using XChaCha20-Poly1305 → `VXSH` blob.
7. Sender uploads `{ share_uuid, recipient_id, epkX, ctMlkem, vxsh }` to the server.

Receive flow:

1. Recipient fetches the share record.
2. Recipient computes `ssX = X25519(privX, epkX)` and `ssMlkem = ML-KEM-768.Decaps(privMlkem, ctMlkem)`.
3. Recipient derives the same `shareWrapKey` and unwraps `vxsh`.
4. Recipient stores the shared key in their own scope (a virtual collection or pinned shared file).

Security degrades only if **both** X25519 and ML-KEM-768 are broken. The hybrid construction follows draft-ietf-tls-hybrid-design conventions adapted to a KEM context.

`VXSH` blob format:

```bash
Offset  Size   Field
0       4      Magic "VXSH"
4       1      Format version (0x01)
5       1      Algorithm ID (0x01)
6       24     Nonce (random)
30      N+16   Ciphertext (CBOR { "k": bstr, "kind": "collection"|"file", "id": bstr }) + tag
```

## 12. Account Recovery

### 12.1 Recovery phrase (non-destructive)

At registration the client generates a 24-word BIP39 phrase (256 bits of entropy) and derives a `recoveryKey` to wrap a copy of `masterKey`.

```bash
seed         = BIP39.mnemonicToSeed(phrase, passphrase = "")
recoveryKey  = HKDF-SHA-512(
    ikm  = seed,
    salt = 32 zero bytes,
    info = "vexahub:v1:recoveryKey:" || user_uuid,
    L    = 32
)
```

HKDF (not Argon2id) is used here because the BIP39 phrase already provides 256 bits of entropy. A memory-hard function would add latency without measurably improving the security margin against any realistic attacker.

The phrase is shown once, never persisted client-side, never transmitted to the server. The user must confirm specific word positions before registration completes.

Recovery flow (forgotten password, phrase available):

1. User enters email and recovery phrase.
2. Client fetches `vxrm` and `user_uuid` from a rate-limited unauthenticated endpoint.
3. Client re-derives `recoveryKey`, unwraps `masterKey`.
4. User chooses a new password.
5. Client performs a fresh OPAQUE registration.
6. Client re-wraps the same `masterKey` with the new `masterKeyWrapper`.
7. Server replaces `registration_record`, `vxwm`, and `vxsk` atomically.
8. All existing files, collections, and shares remain valid.

### 12.2 Destructive reset

Available when both password and phrase are lost. Triggered by email-confirmed link, displays an unambiguous data-loss warning, then atomically wipes all files and rotates all key material under a new `reset_generation`.

### 12.3 Phrase rotation

Authenticated users can regenerate their recovery phrase from settings. The new phrase wraps the existing `masterKey`; the old `vxrm` is replaced atomically.

### 12.4 Safeguards

- Phrase confirmation step at registration is mandatory. No skip option.
- Phrase displayed once, never logged, never persisted.
- Recovery lookup endpoint aggressively rate-limited per IP and per email.
- Destructive reset requires email-token verification.

## 13. Protocol Versioning and Migration

Every user row carries `opaque_protocol_version`. Every blob carries a format version byte. Current protocol version: **1**.

Breaking changes (any of the following) require a version bump:

- Argon2id parameters
- OPAQUE ciphersuite
- HKDF info strings
- Blob binary formats
- Wrapping algorithm

Migration model: new and old protocol versions coexist in the codebase. On next login under the old version, the client prompts the user, runs a fresh OPAQUE registration under the new params, re-wraps `masterKey`, and atomically updates the user row. Users who never log back in remain on the old version until a forced migration window is announced.

What CANNOT be changed without re-encrypting user data: `masterKey` itself, file generation derivation paths, segment nonce derivation. `serverSetup` rotation invalidates all accounts.

## 14. Test Vectors

Cross-target consistency is verified by JSON test vectors in `crates/core/tests/vectors/`, executed by:

- Native Rust via `cargo test`
- WASM via `wasm-bindgen-test`
- Node via the NAPI build
- Future Android via instrumented tests
- Future iOS via XCTest

Vector categories:

1. HKDF derivations (every domain-separated path in §4)
2. VXWM, VXRM, VXFC, VXFM, VXSK, VXPS, VXSH round-trips with fixed keys and nonces
3. Segment nonce derivation across multiple generations and indices
4. OPAQUE registration and login with deterministic test-only RNG seeds
5. ML-KEM-768 encapsulation/decapsulation against FIPS 203 known-answer tests

A vector mismatch is a release blocker.

## 15. Key Zeroization

All key material is wrapped in `Zeroizing<T>` (Rust) and explicitly overwritten on JS/WASM boundaries via `Uint8Array.fill(0)` after use. GC-managed runtimes (JS, Kotlin, Swift) cannot guarantee complete erasure; this is an acknowledged limitation documented in the threat model.

Mandatory zeroization points: after every OPAQUE flow (`password`, `exportKey`, `masterKeyWrapper`), on session timeout, on logout, on password change.

## 16. Web Security Headers

### 16.1 Content Security Policy

```r
Content-Security-Policy:
    default-src 'self';
    connect-src 'self' https://api.vexahub.com;
    script-src 'self' 'wasm-unsafe-eval';
    style-src 'self';
    style-src-attr 'none';
    img-src 'self' data: blob:;
    font-src 'self';
    media-src 'self' blob:;
    worker-src 'self';
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'none';
    upgrade-insecure-requests;
    report-uri https://reports.vexahub.com/csp;
```

`'unsafe-inline'` is excluded from `style-src`. SvelteKit scoped styles are emitted as separate `<style>` blocks compatible with nonce-based CSP; the build pipeline injects per-request nonces. This is stricter than the v1 of this document and closes a real XSS exfiltration vector.

`'wasm-unsafe-eval'` permits WebAssembly compilation only, NOT JavaScript `eval()`.

### 16.2 Other headers

```r
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
X-Frame-Options: DENY
```

`COOP: same-origin` + `COEP: require-corp` enable cross-origin isolation, which is REQUIRED for `SharedArrayBuffer` and therefore for Argon2id `parallelism > 1` in WASM. Without these headers the parallelism degrades silently to 1, weakening the KSF below the spec parameters. Verification of cross-origin isolation status (`crossOriginIsolated === true`) MUST be checked at app bootstrap and surfaced as an error if false.

### 16.3 Cookies

All authentication cookies: `HttpOnly; Secure; SameSite=Strict; Path=/`. No subdomain wildcard in production.

### 16.4 API media type

```r
Content-Type: application/vnd.vexahub.v1+json
Accept:       application/vnd.vexahub.v1+json
```

Unknown or incompatible media types yield HTTP 406. Allows future `vnd.vexahub.v2+json` migration.

### 16.5 Third-party scripts

None. Self-host every asset including fonts, icons, and analytics (Umami).

### 16.6 CSP violation reporting

Violations POSTed to `https://reports.vexahub.com/csp`, rate-limited per IP, stored in Bugsink, never exposed to unauthenticated reads.

## 17. Threat Model Summary

| Attacker capability                                    | Vexahub response                                                                                  |
|--------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| Database snapshot                                      | No decryption possible; OPRF blocks offline password attacks                                      |
| Full server compromise, no active sessions intercepted | Cannot decrypt existing data; can observe future ciphertext                                       |
| Server compromise + active session cookie stolen       | Can decrypt that session's persistent blob if the user opted in (documented trade-off §9.2)       |
| Network MITM with valid TLS                            | Blocked by static public key pinning                                                              |
| Malicious client update                                | Not defended; reproducible builds tracked in §18                                                  |
| Physical device compromise (unlocked)                  | Not defended beyond OS-level protections                                                          |
| XSS in webapp                                          | Strict CSP (no `unsafe-inline`), Worker isolation, no eval beyond WASM                            |
| Compromised `serverSetup`                              | Argon2id 192 MiB still imposes meaningful cost on offline dictionary attacks                      |
| File rollback / segment reorder by malicious server    | Blocked by `generation` counter and per-segment AAD binding                                       |
| CRQC (post-quantum adversary)                          | Sharing protected by hybrid X25519 + ML-KEM-768; account auth remains classical pending PQ OPAQUE |

## 18. Open Questions and Future Work

- PQ-resistant OPAQUE migration when standardized variants land.
- WebAuthn PRF for biometric unlock.
- Reproducible builds for `vexahub-protocol` and the webapp bundle, published to a transparency log.
- Argon2id parameter telemetry on real device distributions to validate the 192 MiB choice.
- `serverSetup` compromise incident response runbook.
- Independent third-party audit of `vexahub-protocol` once funding allows.

## A note from the author

This document is the product of **many** hours of careful thought, research, and back-and-forth decision-making. **Every** parameter, **every** algorithm choice, **every** byte in the blob formats was weighed against real-world constraints.

>What protects users against realistic threats, what stays usable for normal people, what can be audited by security researchers, and what will still make sense five years from now.

**VexaHub** is built on a fundamental belief. We believe that privacy should not be a premium feature, and "trust us" is not a security model. The only encryption worth calling end-to-end is the kind where the people running the servers genuinely cannot read your files, not because they promise not to, but because the math does not allow it.

>Everything in this specification follows from that belief. **OPAQUE** means the server never sees passwords. **Argon2id** at 256 MiB means offline attacks are painfully expensive. **XChaCha20-Poly1305** means no nonce reuse footguns. Hybrid **X25519** + **ML-KEM-768** means sharing survives the arrival of quantum computers. A single Rust crate as the cryptographic source of truth means every Vexahub client (web, desktop, mobile) speaks exactly the same language down to the last byte.

None of this is perfect. **Cryptography** never is. But it is honest, it is documented, and it is open to scrutiny. If you find a mistake in this document, please reach out! **Security** is a collaborative effort, and **VexaHub** is better with your help than without it.

To anyone reading this who is building something similar. Please, **do not** cut corners on the crypto. Your users are trusting you with the most personal things they own. Take that trust seriously.

Built with care in **France** 🇫🇷, for everyone who believes privacy is a right, not a privilege. Love from the team ❤
