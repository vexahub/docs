# Vexahub — Cryptography Specification

**Document version:** 1  
**Protocol version:** 1  
**Status:** Draft - MVP

This document is the single source of truth for all cryptographic decisions in Vexahub. Any change here is a breaking change for existing accounts and must bump the protocol version.

## 1. Overview

Vexahub is a zero-knowledge end-to-end encrypted cloud storage service. The server never has access to user passwords, plaintext files, file names, or encryption keys capable of decrypting user data during normal operation.

Cryptographic goals:

- The server cannot decrypt user files, even with full database access
- An attacker stealing only the database cannot mount offline password attacks
- Password changes do not require re-encrypting user files
- Sharing is possible between users without the server learning shared content
- Post-quantum resistance for sharing key exchange
- Cross-platform consistency (web, future Android/iOS) via a single Rust implementation

Non-goals (explicit):

- The server is trusted to not collude with itself. A fully compromised server could, on persistent sessions, obtain the unlock key for cached blobs. This trade-off is documented in §9 and must be surfaced to users who opt into persistent sessions.

## 2. Primitives

| Purpose                     | Algorithm                    | Parameters                      |
|-----------------------------|------------------------------|---------------------------------|
| Password-authenticated AKE  | OPAQUE (RFC 9807)            | Ristretto255 ciphersuite        |
| Key stretching (in OPAQUE)  | Argon2id                     | m=262144 KiB (256 MiB), t=4, p=4|
| Symmetric encryption (AEAD) | XChaCha20-Poly1305           | 24-byte nonces, 16-byte tags    |
| Key derivation              | HKDF-SHA-256                 | With domain-separated `info`    |
| Classical key agreement     | X25519                       | For file/collection sharing     |
| Post-quantum KEM            | ML-KEM-768 (FIPS 203)        | Hybrid with X25519 for sharing  |
| CSPRNG                      | OS CSPRNG                    | `getrandom`, `/dev/urandom`     |
| Memory hygiene              | `zeroize` crate equivalent   | On all key material             |

**Rationale for choices:**

- **Ristretto255** over P-256: safer constant-time implementations, prime-order group, simpler hash-to-curve, better maintained in Rust ecosystem
- **Argon2id secure (256 MiB / t=4 / p=4)**: ~5-6 s on a modern device. This is at the high end of industry practice and provides significant margin against offline dictionary attacks in the event of a full server compromise. The cost is paid only at signup and at login on a new device (not on persistent session resume, which bypasses OPAQUE entirely). RFC-recommended (~13 s) is unusable for a consumer product. Benchmarks on low-end devices (old Windows, throttled CPU, Safari iOS) are required before public launch; if memory allocation fails on a significant percentage of users, the parameters will be revised downward. The client MUST catch `WebAssembly.Memory` allocation errors and fall back gracefully to a lower-memory configuration (128 MiB) with telemetry logging.
- **XChaCha20-Poly1305** over AES-GCM: 24-byte nonces make random nonce generation safe without counters; no hardware AES dependency; constant-time on all platforms
- **HKDF-SHA-256**: universally supported (WebCrypto native, Rust `hkdf` crate, Android Jetpack Security, iOS CryptoKit)
- **Hybrid X25519 + ML-KEM-768** for sharing: classical fallback if ML-KEM ever breaks, NIST-standardized PQ, well-supported libraries

## 3. Key Hierarchy

```bash
password (user input, never leaves client)
    │
    ▼ [OPAQUE protocol with serverSetup + Argon2id client-side]
    │
    ├──► exportKey (64 bytes, client-only, stable across logins)
    │       │
    │       ▼ [HKDF-SHA-256 with domain separation]
    │       │
    │       └──► keyWrapKey (32 bytes) ──► unwraps masterKey
    │
    └──► sessionKey (shared with server, auth for API)


masterKey (32 bytes, generated once at registration)
    │
    ├──► wrapped by keyWrapKey ──► wrapped_master_key (stored server-side)
    │
    └──► [HKDF-SHA-256 with collection_id as info]
          │
          └──► collectionKey (32 bytes, per collection/folder)
                 │
                 ├──► encrypts collection metadata (name, etc.)
                 │
                 └──► [HKDF-SHA-256 with file_id as info]
                        │
                        └──► fileKey (32 bytes, per file)
                               │
                               ├──► encrypts file content (per segment)
                               └──► encrypts file metadata (name, mime, etc.)


sharingKeyPair (generated at registration, post-quantum hybrid)
    │
    ├──► X25519 keypair (classical)
    └──► ML-KEM-768 keypair (post-quantum)
          │
          └──► Private keys wrapped by masterKey, stored server-side
          └──► Public keys stored server-side in plaintext
```

### 3.1 Key summary

| Key            | Size | Origin                          | Lifetime       | Location             |
|----------------|------|---------------------------------|----------------|----------------------|
| password       | var  | User input                      | Typing only    | Client RAM (zeroized)|
| exportKey      | 64   | OPAQUE output                   | Session        | Client RAM (zeroized)|
| keyWrapKey     | 32   | HKDF(exportKey)                 | Session        | Client RAM (zeroized)|
| sessionKey     | 64   | OPAQUE output                   | Session        | Client + server      |
| masterKey      | 32   | CSPRNG at registration          | Permanent      | Wrapped on server    |
| collectionKey  | 32   | HKDF(masterKey, collection_id)  | Permanent      | Derived on demand    |
| fileKey        | 32   | HKDF(collectionKey, file_id)    | Permanent      | Derived on demand    |
| X25519 priv    | 32   | CSPRNG at registration          | Permanent      | Wrapped on server    |
| ML-KEM-768 priv| ~2.4K| CSPRNG at registration          | Permanent      | Wrapped on server    |

## 4. HKDF Domain Separation

All HKDF derivations MUST use a unique `info` string to prevent cross-domain attacks. Format: `vexahub:v{PROTOCOL_VERSION}:{purpose}[:{context}]`.

| Derivation                       | `info` string                                    | salt            | length |
|----------------------------------|--------------------------------------------------|-----------------|--------|
| keyWrapKey from exportKey        | `vexahub:v1:keyWrapKey`                          | 32 zero bytes   | 32     |
| collectionKey from masterKey     | `vexahub:v1:collectionKey:{collection_uuid}`     | 32 zero bytes   | 32     |
| fileKey from collectionKey       | `vexahub:v1:fileKey:{file_uuid}`                 | 32 zero bytes   | 32     |
| fileMetadataKey from fileKey     | `vexahub:v1:fileMetadataKey`                     | 32 zero bytes   | 32     |
| fileContentKey from fileKey      | `vexahub:v1:fileContentKey`                      | 32 zero bytes   | 32     |

**Why zero salts**: HKDF salts are not secrets, and we rely entirely on the `info` field for domain separation. Using a fixed zero salt simplifies interoperability and has no security impact when `info` is unique per purpose.

**UUIDs in info**: UUIDs are v4 random (128 bits) and are stored server-side. They are not secrets. They ensure that every collection and every file gets a unique derivation path from the same parent key.

## 5. Binary Blob Formats

All encrypted blobs stored server-side or persisted client-side use versioned, self-describing binary formats. This allows future migration to new algorithms without breaking existing data.

### 5.1 `VXWM` — Wrapped Master Key

Used to store the `masterKey` wrapped by `keyWrapKey`.

```bash
Offset  Size  Field
------  ----  -----
0       4     Magic bytes "VXWM" (0x56 0x58 0x57 0x4D)
4       1     Format version (0x01)
5       1     Algorithm ID (0x01 = XChaCha20-Poly1305)
6       24    Nonce (random, per-blob)
30      48    Ciphertext (32 bytes masterKey + 16 bytes Poly1305 tag)
------
Total: 78 bytes
```

### 5.2 `VXRM` - Wrapped Recovery Key

```bash
Offset  Size  Field
------  ----  -----
0       4     Magic bytes "VXRM" (0x56 0x58 0x52 0x4D)
4       1     Format version (0x01)
5       1     Algorithm ID (0x01 = XChaCha20-Poly1305)
6       24    Nonce (random, per-blob)
30      48    Ciphertext (32 bytes masterKey + 16 bytes Poly1305 tag)

Total: 78 bytes
```

### 5.3 `VXFC` — File Content Segment

Used for each chunked segment of an encrypted file.

```bash
Offset  Size   Field
------  ----   -----
0       4      Magic bytes "VXFC"
4       1      Format version (0x01)
5       1      Algorithm ID (0x01)
6       8      Segment index (uint64 big-endian)
14      24     Nonce (derived deterministically from segment index, see §6.2)
38      N+16   Ciphertext + Poly1305 tag
```

Segments are fixed-size plaintext (MVP: 1 MiB) except the last one. This enables efficient random access via Range requests on the ciphertext.

### 5.4 `VXFM` — File Metadata

Encrypts filename, mime type, creation time, and other per-file metadata.

```bash
Offset  Size   Field
------  ----   -----
0       4      Magic bytes "VXFM"
4       1      Format version (0x01)
5       1      Algorithm ID (0x01)
6       24     Nonce (random)
30      N+16   Ciphertext (CBOR-encoded metadata object) + Poly1305 tag
```

### 5.5 `VXPS` — Persistent Session Blob

Used for "Remember me" persistent sessions (see §9.2). Stored client-side in IndexedDB.

```bash
Offset  Size  Field
------  ----  -----
0       4     Magic bytes "VXPS"
4       1     Format version (0x01)
5       1     Algorithm ID (0x01)
6       24    Nonce (random)
30      48    Ciphertext (32 bytes masterKey + 16 bytes Poly1305 tag)
------
Total: 78 bytes
```

### 5.6 Parsing rules

All parsers MUST:

1. Verify the magic bytes before any other operation
2. Verify the format version matches what the client understands; unknown versions result in an error
3. Verify the algorithm ID is supported; unknown algorithms result in an error
4. Use the algorithm ID to select the appropriate decryption routine

Magic byte mismatch, unsupported version, or unsupported algorithm MUST result in an error, never a silent fallback.

## 6. File Encryption

### 6.1 Segmentation

Files are split into fixed-size plaintext segments before encryption. MVP segment size: **1 MiB** (1,048,576 bytes). The last segment may be smaller.

**Why fixed size**: enables byte-precise Range requests on encrypted content for seeking, resumable uploads via `tus`, and parallel segment processing.

### 6.2 Per-segment nonce derivation

Segment nonces are deterministic, derived from the segment index, to prevent accidental nonce reuse across retries and reconstructions. Nonce format (24 bytes for XChaCha20):

```bash
nonce = HKDF(
    ikm    = fileContentKey,
    salt   = 32 zero bytes,
    info   = "vexahub:v1:segmentNonce:" || uint64_be(segment_index),
    length = 24,
)
```

This ensures that two different files (which have different `fileContentKey`) never share nonces even at the same segment index, and that re-uploading a segment produces the same nonce as the original (idempotent).

### 6.3 Content vs metadata keys

Within a single file, the content and metadata use different keys, both derived from the same `fileKey`:

- `fileContentKey = HKDF(fileKey, info = "vexahub:v1:fileContentKey")`
- `fileMetadataKey = HKDF(fileKey, info = "vexahub:v1:fileMetadataKey")`

This prevents any cross-use of nonces between content segments and metadata.

## 7. OPAQUE Protocol

### 7.1 Library

Vexahub uses OPAQUE (RFC 9807) via the Rust `opaque-ke` crate, compiled to:

- WebAssembly via `wasm-bindgen` for the SvelteKit webapp and the NestJS server (both consume the same WASM module)
- Native Rust linkage for the Tauri desktop application (Windows, macOS, Linux) — direct dependency, no FFI overhead
- Native libraries via UniFFI for future Android (Kotlin) and iOS (Swift) clients

**For the MVP web launch**, the webapp and server use `@serenity-kit/opaque` (v1+) as a drop-in, which internally wraps the same `opaque-ke` Rust crate. This ensures that when the dedicated `vexahub-opaque` workspace is built in Phase 2, the cryptographic outputs remain byte-for-byte compatible with existing MVP accounts, provided the ciphersuite and Argon2id parameters match this specification.

Ciphersuite:

- OPRF group: Ristretto255
- KE group: Ristretto255
- Key exchange: 3DH (Triple Diffie-Hellman)
- Key stretching function: Argon2id with the parameters in §2

This ciphersuite is frozen at protocol version 1 and MUST be identical across all clients and the server.

### 7.2 Server setup

At first deployment, the server generates a one-time `serverSetup` via the `opaque-ke` setup routine. This value contains:

- The server's OPRF secret key (acts as the global "pepper")
- The server's static keypair for AKE

**Storage requirements:**

- Loaded by NestJS via `OPAQUE_SERVER_SETUP` environment variable
- NEVER committed to Git, NEVER logged, NEVER returned in any API response
- Backed up encrypted in at least two independent locations (e.g. Passbolt + offline encrypted backup)
- Rotation: changing `serverSetup` invalidates **all existing accounts**. It is treated as a disaster-recovery-only action, requiring a forced password reset for all users

**Loss of `serverSetup` = permanent loss of all user accounts.** Backup discipline is critical.

### 7.3 Server static public key pinning

All Vexahub clients (web, Android, iOS) MUST pin the server's static public key, derived from `serverSetup` via `opaque.server.getPublicKey()`. The pinned value is hardcoded at build time.

On every OPAQUE flow completion (`finishRegistration`, `finishLogin`), the client compares the received `serverStaticPublicKey` with the hardcoded value. Mismatch MUST abort the flow and display a security warning to the user.

This is a defense against a compromised or substituted server: even if an attacker steals `serverSetup` and runs a rogue server, clients with pinned keys will detect the substitution IF the attacker cannot also push a malicious client update.

## 8. Registration and Login Flows

### 8.1 Registration

**Client state:** nothing stored before registration.  
**Server state:** nothing stored for the user before registration.

1. **Client:** user enters email and password
2. **Client:** `opaque.client.startRegistration({ password })` → `{ clientRegistrationState, registrationRequest }`
3. **Client → Server:** `POST /auth/register/start { email, registrationRequest }`
4. **Server:** verifies email is not already registered
5. **Server:** `opaque.server.createRegistrationResponse({ serverSetup, userIdentifier: email, registrationRequest })` → `{ registrationResponse }`
6. **Server → Client:** `{ registrationResponse }` (optionally with a short-lived continuation token to bind the two requests)
7. **Client:** `opaque.client.finishRegistration({ clientRegistrationState, registrationResponse, password })` → `{ registrationRecord, exportKey, serverStaticPublicKey }`
8. **Client:** verifies `serverStaticPublicKey` matches the hardcoded pin; aborts on mismatch
9. **Client:** derives `keyWrapKey = HKDF(exportKey, info="vexahub:v1:keyWrapKey", L=32)`
10. **Client:** generates `masterKey` (32 random bytes from CSPRNG)
11. **Client:** generates sharing keypairs (X25519 + ML-KEM-768)
12. **Client:** wraps `masterKey` with `keyWrapKey` into a `VXWM` blob → `wrapped_master_key`
13. **Client:** wraps sharing private keys with `masterKey` → `wrapped_sharing_keys`
14. **Client → Server:** `POST /auth/register/finish { email, registrationRecord, wrappedMasterKey, wrappedSharingKeys, sharingPublicKeys }`
15. **Server:** stores the user row, returns a short-lived session cookie (or requires an immediate login)
16. **Client:** zeroizes `password`, `exportKey`, `keyWrapKey`, plaintext private keys (but keeps `masterKey` in the Worker for the active session)

### 8.2 Login

**Client state:** nothing stored before login.  
**Server state:** user row with `registrationRecord`, `wrappedMasterKey`, `wrappedSharingKeys`.

1. **Client:** user enters email and password
2. **Client:** `opaque.client.startLogin({ password })` → `{ clientLoginState, startLoginRequest }`
3. **Client → Server:** `POST /auth/login/start { email, startLoginRequest }`
4. **Server:** looks up user by email, loads `registrationRecord`
5. **Server:** `opaque.server.startLogin({ serverSetup, userIdentifier: email, registrationRecord, startLoginRequest })` → `{ loginResponse, serverLoginState }`
6. **Server:** stores `serverLoginState` in Valkey with a short TTL (e.g., 60 seconds), keyed by a random continuation token
7. **Server → Client:** `{ loginResponse, continuationToken, wrappedMasterKey, wrappedSharingKeys }`
8. **Client:** `opaque.client.finishLogin({ clientLoginState, loginResponse, password })` → `{ finishLoginRequest, sessionKey, exportKey, serverStaticPublicKey }`
9. **Client:** verifies `serverStaticPublicKey` matches the hardcoded pin
10. **Client:** derives `keyWrapKey` from `exportKey` (same as registration)
11. **Client:** parses `VXWM` blob, decrypts `masterKey` using `keyWrapKey`
12. **Client:** decrypts sharing private keys using `masterKey`
13. **Client → Server:** `POST /auth/login/finish { continuationToken, finishLoginRequest }`
14. **Server:** retrieves `serverLoginState` from Valkey (and deletes it immediately)
15. **Server:** `opaque.server.finishLogin({ finishLoginRequest, serverLoginState })` → `{ sessionKey }`
16. **Server:** derives an HTTP session token from `sessionKey`, stores a session row in Postgres, returns a `HttpOnly; Secure; SameSite=Strict` cookie
17. **Client:** zeroizes `password`, `exportKey`, `keyWrapKey`. `masterKey` and sharing private keys are moved to the Crypto Web Worker (see §9.1)

## 9. Session Management

### 9.1 Normal sessions — "Active session"

Default behavior for all logins. Inspired by Proton's session model but with the addition of a dedicated Crypto Worker.

- `masterKey` and sharing private keys live **exclusively inside a dedicated Crypto Web Worker**, never in the main thread's JavaScript heap
- The main thread communicates with the Worker via `postMessage` with a request/response protocol:
  - `encryptFileSegment(plaintextSegmentBytes, fileKeyContext) → ciphertextBytes`
  - `decryptFileSegment(ciphertextBytes, fileKeyContext) → plaintextBytes`
  - `deriveCollectionKey(collectionId) → opaqueHandle`
  - `wrapForSharing(plaintext, recipientPublicKeys) → ciphertext`
- The Worker never returns raw keys, only encryption/decryption results
- An inactivity timeout of **30 minutes** nukes the Worker and zeroizes all in-memory key material; the user must re-authenticate
- The session cookie (HttpOnly, Secure, SameSite=Strict) is short-lived in this mode: **24 hours** absolute max, renewed on activity
- Closing the tab destroys the Worker and therefore the `masterKey`; on next tab open, the user must log in again (unless persistent session is enabled)

**Web Worker hardening:**

- The Worker script is served with a strict CSP (`script-src 'self'`, no inline, no eval)
- The Worker script is loaded from the same origin, integrity-checked via SRI hash at bootstrap time
- The main thread never forwards arbitrary code or eval requests to the Worker

### 9.2 Persistent sessions — "Remember me"

Opt-in mechanism inspired by Proton's device-based persistent sessions. **NOT enabled by default.**

**Activation flow** (post-successful-login, user checks "Remember me on this device"):

1. Client generates a random `localKey` (32 bytes, CSPRNG)
2. Client wraps `masterKey` with `localKey` into a `VXPS` blob → `persistentBlob`
3. Client stores `persistentBlob` in IndexedDB (not localStorage) under a user-scoped key
4. Client sends `localKey` to the server via an authenticated request: `POST /auth/persistent-session/create { localKey, deviceLabel }`
5. Server generates a new `persistentSessionId`, stores `{ userId, localKey, cookieHash, deviceLabel, createdAt, expiresAt }` in the `persistent_sessions` table
6. Server returns a `PS-AUTH-{id}` cookie: `HttpOnly; Secure; SameSite=Strict; Max-Age=30d` (configurable, 7–90 days)

**Resume flow** (user returns to the site, regular session expired):

1. Client detects existing `persistentBlob` in IndexedDB and `PS-AUTH` cookie present
2. Client offers "Resume session as <alice@example.com>" instead of the password form
3. On user confirmation: `GET /auth/persistent-session/resume` (cookie sent automatically)
4. Server validates `PS-AUTH` cookie, checks the session is not revoked, updates `lastUsedAt`
5. Server returns `{ localKey, wrappedSharingKeys }`
6. Client parses the `VXPS` blob and decrypts `masterKey` using `localKey`
7. Client loads keys into the Crypto Worker
8. Server issues a fresh short-lived session cookie; the `PS-AUTH` remains valid for subsequent resumes

**Security trade-off disclosure (MUST be shown to the user at opt-in):**

> Remember me stores an encrypted copy of your keys on this device. The key to unlock them is held by Vexahub servers. In normal operation your data remains private, but if an attacker gains full control of our servers AND intercepts your session cookie, they could decrypt this remembered session.
>
> For maximum security, leave this unchecked and sign in with your password each time.

**Mandatory safeguards:**

- Opt-in strict, never enabled by default
- Settings page listing all active persistent sessions with device label, creation time, last use, and a "Revoke" button (immediately invalidates `localKey` server-side)
- Changing password revokes all persistent sessions (except optionally the current device)
- Inactivity timeout on the server side: `localKey` is deleted after N days of inactivity (MVP: 30 days)
- Device label is user-editable (defaults to `${browserName} on ${osName}`)
- Soft binding to a device fingerprint (user-agent + coarse IP network) for anomaly detection, logged but not strictly enforced
- "Sign out everywhere" button in settings wipes all persistent sessions and the IndexedDB blob on the current device
- Never store the `localKey` client-side, and never store the `masterKey` in localStorage, IndexedDB, or any persistent location in unwrapped form

### 9.3 Session table schema (Postgres via Drizzle)

```sql
CREATE TABLE sessions (
    id               UUID PRIMARY KEY,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cookie_hash      BYTEA NOT NULL,        -- SHA-256 of the cookie value
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ NOT NULL,
    revoked_at       TIMESTAMPTZ,
    user_agent       TEXT,
    ip_network       INET
);

CREATE TABLE persistent_sessions (
    id               UUID PRIMARY KEY,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    local_key        BYTEA NOT NULL,        -- 32 bytes, server-held unlock key
    cookie_hash      BYTEA NOT NULL,
    device_label     TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ NOT NULL,
    revoked_at       TIMESTAMPTZ
);

CREATE INDEX ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX ON persistent_sessions (user_id) WHERE revoked_at IS NULL;
```

## 10. Server-side Storage

### 10.1 Users table

```sql
CREATE TABLE users (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                     CITEXT UNIQUE NOT NULL,
    locale                    TEXT NOT NULL DEFAULT 'en',  -- IETF BCP 47 tag (e.g. 'fr', 'en')
    opaque_protocol_version   SMALLINT NOT NULL DEFAULT 1,
    registration_record       BYTEA NOT NULL,   -- OPAQUE envelope, opaque by design
    wrapped_master_key        BYTEA NOT NULL,   -- VXWM blob (78 bytes)
    wrapped_sharing_keys      BYTEA NOT NULL,   -- CBOR-encoded, wrapped by masterKey
    sharing_public_x25519     BYTEA NOT NULL,   -- 32 bytes
    sharing_public_mlkem      BYTEA NOT NULL,   -- ML-KEM-768 public key
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

**Note on `locale`**: stored in plaintext (not sensitive). Set at registration from the client's `navigator.language` detection, modifiable via `PUT /api/v1/users/me/settings/locale`. The server is the source of truth for the user's language preference to ensure cross-device consistency. The client performs an initial detection via `navigator.language` for unauthenticated pages and switches to `user.locale` after receiving the response from `/auth/me` at bootstrap.

### 10.2 What the server knows vs. does not know

**The server knows:**

- The user's email (cannot be zero-knowledge for account lookup)
- The `registrationRecord` (OPAQUE envelope, unusable without the password)
- The `wrapped_master_key` blob (unusable without `keyWrapKey`, which requires the password)
- Public sharing keys
- File existence, size, upload/modification timestamps
- Collection and file UUIDs
- Collection hierarchy (parent/child relationships)
- For persistent sessions only: the `localKey` for that session (see §9.2 trade-off)

**The server does NOT know:**

- The user's password
- The `masterKey`, `exportKey`, `keyWrapKey`, `collectionKey`, `fileKey`
- File names, mime types, or any file metadata
- Collection names
- File content

## 11. Sharing (Post-Quantum Hybrid)

Sharing is designed to be post-quantum resistant using hybrid X25519 + ML-KEM-768. Details to be expanded in a future revision of this document. High-level approach:

1. Sender retrieves the recipient's public X25519 and public ML-KEM-768 keys from the server
2. Sender generates a shared secret via X25519(senderEphemeral, recipientX25519)
3. Sender encapsulates to the recipient's ML-KEM-768 public key, producing an ML-KEM ciphertext and shared secret
4. Sender derives a wrap key: `HKDF(x25519Shared || mlkemShared, info="vexahub:v1:shareWrap:{shareId}")`
5. Sender wraps the `collectionKey` or `fileKey` being shared with this wrap key
6. Sender uploads `{ x25519EphemeralPublic, mlkemCiphertext, wrappedKey }` to the server, tagged with the recipient
7. Recipient downloads, derives the same shared secret via both mechanisms, derives the same wrap key, unwraps the shared key

**Why hybrid:** if X25519 is broken by a CRQC in the future, ML-KEM-768 still protects the shared secret. If ML-KEM-768 has an unknown classical vulnerability, X25519 still protects it. Security degrades only if both are broken simultaneously.

## 12. Account Recovery

In a zero-knowledge system, the server cannot reset a user's password because it does not possess the keys required to decrypt user data. Vexahub provides two recovery mechanisms to handle password loss, with different trade-offs.

### 12.1 Recovery phrase (non-destructive)

At registration, the client generates a 24-word recovery phrase following the BIP39 English wordlist (256 bits of entropy). A copy of the `masterKey` is wrapped with a key derived from this phrase and stored server-side as `recovery_master_key`.

**Generation flow (at registration)**:

1. Client generates 32 bytes of entropy from the CSPRNG
2. Client encodes the entropy as a 24-word BIP39 phrase
3. Client derives a `recoveryKey` from the phrase:

    ```js
        bip39Seed    = BIP39.mnemonicToSeed(phrase, passphrase="")
        recoveryKey  = Argon2id(
            password    = bip39Seed,
            salt        = SHA-256(userId)[..16],   // deterministic 16-byte salt
            memory      = 262144,                   // 256 MiB (matches §2)
            iterations  = 4,
            parallelism = 4,
            length      = 32
        )
    ```

4. Client wraps the `masterKey` with `recoveryKey` into a `VXRM` blob (format in §5.6)
5. Client sends `VXRM` to the server, stored in `users.recovery_master_key`
6. Client displays the phrase to the user with a mandatory confirmation step ("type words #4, #11, #19 to continue") — the phrase MUST NOT be stored anywhere client-side after confirmation

**The recovery phrase is NEVER sent to the server**, only the resulting blob. The server cannot derive `recoveryKey` without the phrase.

**Recovery flow (user forgot password, has phrase)**:

1. User enters email and recovery phrase
2. Client fetches `recovery_master_key` (VXRM blob) and `user.id` via a limited unauthenticated endpoint
3. Client re-derives `recoveryKey` from the phrase
4. Client unwraps the `masterKey` from the VXRM blob
5. User chooses a new password
6. Client performs a fresh OPAQUE registration with the new password
7. Client re-wraps the same `masterKey` with the new `keyWrapKey` derived from the new `exportKey`
8. Server replaces `registration_record` and `wrapped_master_key` atomically
9. All existing files, collections, and sharing keys remain valid because the underlying `masterKey` is unchanged

This is the preferred recovery path. **No data is lost.**

### 12.2 Destructive reset (fallback)

If the user has lost both their password AND their recovery phrase, they can request a destructive account reset. This wipes all encrypted data and creates a fresh account under the same email.

**Reset flow**:

1. User requests reset via `POST /auth/reset-request` with email
2. Server sends a confirmation email with a one-time token (short TTL, e.g. 15 minutes)
3. User clicks the link and is shown a **clear, unambiguous warning**:
   > "All files, folders, and shared items in this account will be permanently deleted. This action cannot be undone. Do you want to continue?"
4. User confirms, chooses a new password
5. Client performs a fresh OPAQUE registration with new parameters (new `masterKey`, new sharing keypairs)
6. Server atomically:
   - Deletes all files associated with the old `userId` from object storage
   - Deletes all collection and file rows from the database
   - Revokes all active sessions and persistent sessions
   - Replaces `registration_record`, `wrapped_master_key`, `wrapped_sharing_keys`, `sharing_public_*`, `recovery_master_key`
   - Bumps a `reset_generation` counter on the user row
7. The user is returned to a clean, empty account

The destructive reset is logged in an admin-visible audit table with timestamp and IP, for abuse monitoring.

### 12.3 Users table additions

```sql
ALTER TABLE users ADD COLUMN recovery_master_key BYTEA NOT NULL;
ALTER TABLE users ADD COLUMN reset_generation   INTEGER NOT NULL DEFAULT 0;
```

`recovery_master_key` is `NOT NULL` because the recovery phrase is mandatory at registration. A user who refuses to save a phrase cannot create an account — this is a deliberate UX constraint to avoid the "lost forever" scenario by default.

### 12.4 `VXRM` — Recovery Wrapped Master Key (blob format)

The `VXRM` format is defined in **§5.2** and has identical structure to `VXWM` with a different magic byte to prevent cross-use.

### 12.5 Recovery phrase rotation

Users MAY regenerate their recovery phrase at any time via settings. The flow is:

1. User is authenticated (has `masterKey` in Worker memory)
2. Client generates a new 24-word phrase
3. Client derives a new `recoveryKey` from the new phrase
4. Client wraps the existing `masterKey` with the new `recoveryKey` into a new VXRM blob
5. Client uploads the new blob via `PUT /users/me/recovery-key`
6. User confirms they have saved the new phrase
7. The old phrase becomes invalid immediately

Password change does NOT invalidate the recovery phrase. The recovery phrase only wraps the `masterKey`, which is unchanged by password rotation.

### 12.6 Security considerations

- **Phrase confirmation**: at registration, the client MUST require the user to type back several random positions from the phrase before proceeding. This prevents users from clicking through without saving it.
- **No "skip" option**: account creation MUST NOT allow bypassing the recovery phrase step. A skipped phrase = a time bomb for support and user trust.
- **Phrase display**: shown once, never persisted client-side, never logged, never sent to the server, never transmitted in any form.
- **Rate limiting on recovery endpoint**: `POST /auth/recovery-lookup` must be aggressively rate-limited per IP and per email to prevent enumeration and brute-force attempts against the recovery flow.
- **Reset email verification**: the destructive reset path MUST require email verification via a signed token, to prevent an attacker who only has the email (no password, no phrase) from nuking the account.
- **Recovery phrase entropy**: 256 bits is well above any brute-force threshold even with Argon2id removed. The Argon2id step is a defense against weak custom phrases (users who might shorten or modify the generated phrase, which should not be allowed by the UI).

## 13. Protocol Versioning and Migration

### 13.1 Version field

Every user row carries `opaque_protocol_version`. Every encrypted blob carries a format version in its header. The current protocol version is **1**.

### 13.2 Breaking changes require a version bump

Any of the following is a breaking change:

- Modifying Argon2id parameters
- Changing the OPAQUE ciphersuite
- Changing the key derivation `info` strings
- Changing the blob binary format in a non-backward-compatible way
- Changing the wrapping algorithm

When bumping the version:

1. The new protocol version is implemented alongside the old one in all clients
2. Existing users continue on their current version
3. On next login, clients prompt for password and perform an in-place upgrade:
   - Re-run OPAQUE registration with the new params
   - Re-wrap the existing `masterKey` with the new `keyWrapKey`
   - Update `opaque_protocol_version` on the user row
4. Users who cannot upgrade (e.g., never log back in) remain on the old version indefinitely or until a forced migration window

### 13.3 What CANNOT be changed without user action

- The `masterKey` itself (changing it requires re-encrypting all files)
- Per-file `fileKey` derivation paths (changing them requires re-encrypting all files)
- The `serverSetup` (changing it invalidates all accounts)

## 14. Test Vectors

Cross-platform consistency is verified via a shared set of test vectors stored in `crypto/test-vectors/`. Each vector file is a JSON document consumed by unit tests on:

- Rust native (via `cargo test` in the `vexahub-opaque` workspace)
- WASM (via `wasm-bindgen-test`)
- Android (via instrumented tests reading from `assets/`)
- iOS (via XCTest reading from a resource bundle)

Vector categories:

1. **HKDF derivations** — exportKey → keyWrapKey, masterKey → collectionKey, etc.
2. **VXWM blob round-trips** — encrypt + decrypt with known keys and nonces
3. **VXFC segment encryption** — deterministic nonce derivation for known segment indices
4. **OPAQUE registration and login** — with deterministic RNG seed (test-only code path) to ensure byte-level identical outputs across platforms

Test vectors are generated from the Rust reference implementation and committed to the repo. Any change that breaks a vector requires explicit version bump and migration plan.

## 15. Key Zeroization

All clients MUST zeroize key material as soon as it is no longer needed.

**Rust:** use `zeroize::Zeroizing<T>` wrappers on all key buffers. The `opaque-ke` crate already applies this internally.

**JavaScript/WASM:** zeroing is best-effort. The WASM boundary returns `Uint8Array` to JS; after use, explicitly overwrite: `buf.fill(0)`. Garbage-collected JS runtimes may still leave copies in memory; this is an acknowledged limitation.

**Kotlin (Android, future):** use `javax.crypto.SecretKeySpec` where possible, explicitly `fill(0)` on `ByteArray` after use. The GC may still move objects; acknowledged limitation.

**Swift (iOS, future):** use `Data` with explicit `resetBytes(in:)` after use.

**Critical zeroization points:**

- After every OPAQUE flow: `password`, `exportKey`, `keyWrapKey`
- On session timeout: all in-Worker keys
- On logout: all in-Worker keys + any IndexedDB blobs if logging out of persistent session
- On password change: all keys derived from the old password

## 16. Web Security Headers

The Vexahub webapp MUST be served with a strict set of security headers. The baseline configuration is inspired by Proton's production deployment (verified via browser DevTools) and hardened for the Vexahub threat model.

### 16.1 Content Security Policy (CSP)

```s
Content-Security-Policy:
    default-src 'self';
    connect-src 'self' https://api.vexahub.com;
    script-src 'self' 'wasm-unsafe-eval';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data: blob:;
    font-src 'self';
    media-src 'self' blob:;
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'none';
    upgrade-insecure-requests;
    report-uri https://reports.vexahub.com/csp;
```

**Rationale per directive:**

- `default-src 'self'`: deny all by default, whitelist per category
- `connect-src`: only the Vexahub API host for XHR/fetch/WebSocket
- `script-src 'self' 'wasm-unsafe-eval'`: allow WebAssembly (required for libsodium and `@serenity-kit/opaque`), no inline scripts, no external JS, no eval beyond WASM needs
- `style-src 'self' 'unsafe-inline'`: `unsafe-inline` is required by many CSS-in-JS solutions and Svelte's scoped styles; mitigated by the absence of user-controlled style injection
- `img-src 'self' data: blob:`: `data:` for inline SVG icons, `blob:` for decrypted file previews held in memory
- `media-src 'self' blob:`: `blob:` for decrypted video/audio streaming via MSE
- `object-src 'none'`: no `<object>`, `<embed>`, `<applet>` — legacy attack vectors
- `frame-ancestors 'none'`: prevent clickjacking (stricter than `X-Frame-Options: DENY`)
- `upgrade-insecure-requests`: force HTTPS for any accidentally-HTTP resource
- `report-uri`: collect CSP violations for monitoring

**No `unsafe-eval` without WASM qualifier**: only `wasm-unsafe-eval` is permitted, which allows WebAssembly compilation but NOT arbitrary JavaScript `eval()`. This is the modern standard.

### 16.2 Additional security headers

```s
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
X-Frame-Options: DENY
```

**Rationale:**

- `HSTS` with 2-year max-age and `preload`: force HTTPS, submit domain to HSTS preload list
- `nosniff`: prevent MIME type confusion attacks
- `Referrer-Policy`: do not leak full URLs to third parties
- `Permissions-Policy`: disable browser features the app does not use
- `COOP: same-origin` + `COEP: require-corp`: enable `SharedArrayBuffer` which allows true multi-threading for WASM crypto (Argon2id `parallelism=4` only works with these headers)
- `X-Frame-Options: DENY`: legacy fallback for `frame-ancestors 'none'` in older browsers

### 16.3 Cookie configuration

All authentication cookies MUST be set with:

```s
HttpOnly
Secure
SameSite=Strict
Path=/
Domain=.vexahub.com    (or exact host, no subdomain wildcard in production)
```

`SameSite=Strict` prevents CSRF on navigation and is appropriate for an authenticated SPA. There is no cross-site flow that requires lax mode.

### 16.4 API response Content-Type

The Vexahub API uses a versioned custom media type to allow future evolution without breaking changes:

```s
Content-Type: application/vnd.vexahub.v1+json
```

Clients MUST send:

```s
Accept: application/vnd.vexahub.v1+json
```

Unknown or incompatible media types result in HTTP 406. This allows introducing `vnd.vexahub.v2+json` in the future with a migration window.

### 16.5 Subresource Integrity (SRI)

The webapp bundle is served from the same origin (`self`) so SRI is not strictly required for application code. However, if any third-party script is ever introduced (telemetry, analytics, etc.), it MUST be loaded with an `integrity` attribute and `crossorigin="anonymous"`.

**Recommendation**: introduce no third-party scripts. Self-host everything, including fonts, icons, and analytics (Umami is already chosen for this reason).

### 16.6 CSP violation reporting

Violations are POSTed to `https://reports.vexahub.com/csp` as JSON. This endpoint:

- Accepts only CSP violation reports (validated structure)
- Rate-limited by IP (max 100/min per IP)
- Stored in Bugsink or equivalent for developer review
- Never exposed to unauthenticated reads
- Does not log any personal data beyond the violation details themselves

## 17. Threat Model Summary

| Attacker capability                                      | Vexahub response                                                                   |
|----------------------------------------------------------|------------------------------------------------------------------------------------|
| Snapshots the database                                   | Cannot decrypt anything; cannot mount offline password attacks (OPAQUE OPRF)       |
| Full server compromise, no active sessions intercepted   | Cannot decrypt existing data; can only observe new data going forward              |
| Full server compromise + active session cookie stolen    | Can decrypt that session's persistent blob (if persistent) — documented trade-off  |
| Network MITM with valid TLS cert                         | Blocked by `serverStaticPublicKey` pinning                                         |
| Malicious client update pushed                           | NOT defended; requires user to trust delivery channel (reproducible builds future) |
| User's device physically compromised                     | NOT defended beyond OS-level protections; persistent session blob is readable      |
| XSS in Vexahub webapp                                    | Partial defense via Web Worker isolation; strong CSP required                      |
| Compromised serverSetup                                  | Attacker can attempt offline dictionary attacks on stolen registration records     |
| Post-quantum adversary (CRQC)                            | Sharing protected by hybrid X25519 + ML-KEM-768; account auth uses OPAQUE          |

- **Post-quantum**: future PQ OPAQUE planned (see **§18**)

## 18. Open Questions and Future Work

- **PQ-resistant OPAQUE**: current OPAQUE ciphersuite is classical. When PQ OPAQUE variants are standardized, plan a protocol version 2 migration
- **WebAuthn PRF for biometric unlock**: explored but deferred post-MVP
- **Reproducible builds**: ensure the `vexahub-opaque` Rust crate and the webapp bundle can be independently verified
- **Transparency log**: publish all binary releases in a tamper-evident log (e.g. sigstore)
- **Argon2id parameter benchmarking** on low-end devices: benchmark current params (256 MiB / t=4 / p=4) on old Windows, throttled CPU, Safari iOS. If memory allocation fails on a significant percentage of users, revise downward with telemetry data.

## 19. Change Log

| Version | Date       | Changes                                                                                                           |
|---------|------------|-------------------------------------------------------------------------------------------------------------------|
| 1       | 2026-04-08 | Initial draft, MVP specification. Added §15 Web Security Headers, `users.locale` field, Argon2id 256 MiB/t=4/p=4. |

---

## A note from the author

This document is the product of **many** hours of careful thought, research, and back-and-forth decision-making. **Every** parameter, **every** algorithm choice, **every** byte in the blob formats was weighed against real-world constraints.

>What protects users against realistic threats, what stays usable for normal people, what can be audited by security researchers, and what will still make sense five years from now.

**VexaHub** is built on a fundamental belief. We believe that privacy should not be a premium feature, and "trust us" is not a security model. The only encryption worth calling end-to-end is the kind where the people running the servers genuinely cannot read your files, not because they promise not to, but because the math does not allow it.

>Everything in this specification follows from that belief. **OPAQUE** means the server never sees passwords. **Argon2id** at 256 MiB means offline attacks are painfully expensive. **XChaCha20-Poly1305** means no nonce reuse footguns. Hybrid **X25519** + **ML-KEM-768** means sharing survives the arrival of quantum computers. A single Rust crate as the cryptographic source of truth means every Vexahub client (web, desktop, mobile) speaks exactly the same language down to the last byte.

None of this is perfect. **Cryptography** never is. But it is honest, it is documented, and it is open to scrutiny. If you find a mistake in this document, please reach out! **Security** is a collaborative effort, and **VexaHub** is better with your help than without it.

To anyone reading this who is building something similar. Please, **do not** cut corners on the crypto. Your users are trusting you with the most personal things they own. Take that trust seriously.

Built with care in **France** 🇫🇷, for everyone who believes privacy is a right, not a privilege. Love from the team ❤
