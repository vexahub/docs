# VexaHub - Authentication & Key Material Reference

> **Status:** (Draft) Proposed
>
> This document covers the authentication system: the OPAQUE protocol, what gets created at registration, what gets reconstructed at login, and how sessions are managed. For the full cryptographic specification see the [master crypto spec](CRYPTO.md).

## Table of Contents

1. [Authentication Overview](#1-authentication-overview)
2. [OPAQUE Protocol](#2-opaque-protocol)
3. [Registration](#3-registration)
4. [Login](#4-login)
5. [Session Management](#5-session-management)
6. [Account Recovery](#6-account-recovery)
7. [Key Material Quick Reference](#7-key-material-quick-reference)

## 1. Authentication Overview

VexaHub uses **OPAQUE** ([RFC 9807](https://www.rfc-editor.org/info/rfc9807)) as its password-authenticated key exchange. **OPAQUE** is a zero-knowledge protocol: the server never sees the user's password, not even a hash of it. Instead, the password is used **client-side** to participate in an **Oblivious Pseudo-Random Function (OPRF)** with the server, producing a stable `exportKey` that only the correct password can derive.

This `exportKey` is the root of all client-side key material for a session. The server stores only an opaque registration envelope.

It **cannot** perform offline dictionary attacks even with full database access.

### Why OPAQUE instead of SRP or bcrypt?

With standard password hashing `(e.g. bcrypt or Argon2id on the server)`, if the database is **compromised**, an attacker obtains password hashes and can perform offline brute-force **attacks**. The cost is bounded only by the hash parameters (memory/time), which helps but **does not** prevent large-scale guessing.

**Argon2id** does support additional inputs (like a secret `pepper`), which can improve security if it is stored separately. However, this shifts the problem to protecting that server-side secret. If both the **database** and the **secret** are **compromised**, offline attacks become **possible** again.

**SRP** ([RFC 2945](https://www.rfc-editor.org/info/rfc2945)) improves on this by **avoiding** sending the password directly and **resisting** passive eavesdropping, but it still stores a password-derived verifier. If the verifier database is **stolen**, attackers can mount offline dictionary attacks **against** it.

**OPAQUE** ([RFC 9807](https://www.rfc-editor.org/info/rfc9807)) goes **further**. It uses an **OPRF** `(Oblivious Pseudorandom Function)` so that the server **never** sees the raw password or a directly usable verifier. The stored data is **hardened** by a server-side secret key (`serverSetup`). Without that key, a database dump alone **is not** sufficient to test password guesses offline.

**OPAQUE** is also designed to **resist** pre-computation attacks and to hide the password even during registration, while providing forward secrecy.

That said, if both the **server's secret key** and the **database** are **compromised**, **OPAQUE** falls back to the security level of a strong password hashing scheme. Its main **advantage** is defense-in-depth: it removes the single point of failure where a database leak alone enables **offline** cracking.

For a **zero-knowledge**, **end-to-end encrypted** cloud storage system, this property is **especially** important. The server **cannot** efficiently test password guesses or craft responses that help it learn the user's password-derived key material. This reduces the risk of active or offline attacks by the server itself and better aligns with a **"zero knowledge"** design, where the server **should not** be able to derive or recover user encryption keys.

### Ciphersuite (frozen at protocol version 1)

| Parameter      | Value                                           |
|----------------|-------------------------------------------------|
| OPRF group     | Ristretto255                                    |
| KE group       | Ristretto255                                    |
| Hash           | SHA-512                                         |
| Key exchange   | TripleDhKem (`Triple DH` + `ML-KEM-768` hybrid) |
| Key stretching | Argon2id (`m=128 MiB, t=3, p=4`)                |

The `TripleDhKem` variant augments standard OPAQUE 3DH with a post-quantum KEM hop. During KE1 the client generates an ephemeral ML-KEM-768 keypair and sends the encapsulation key alongside the DH ephemeral. In KE2 the server encapsulates to the client's ML-KEM-768 key. Both parties mix the ML-KEM shared secret into the key schedule alongside the three DH products. The result: session keys are quantum-resistant. An attacker recording login transcripts today cannot recover session keys with a future cryptographically-relevant quantum computer (CRQC). The OPRF itself remains classical Ristretto255.

### `serverSetup`

At first deployment the server generates a one-time `serverSetup` blob containing the OPRF secret key (the global pepper) and the server's static AKE keypair. This blob:

- Is loaded via the `OPAQUE_SERVER_SETUP` environment variable only.
- Is never committed to Git, never logged, never returned in any API response.
- Must be backed up encrypted in at least two independent locations.
- If lost, all user accounts are permanently unrecoverable.

**Loss of `serverSetup` = permanent loss of all user accounts.**

### Server static public key pinning

Every client hardcodes the server's static public key at build time (derived from `serverSetup`). On every OPAQUE flow completion the client compares the received `serverStaticPublicKey` against this pinned value. A mismatch aborts the flow immediately and surfaces a security warning. This defends against a substituted server.

## 2. OPAQUE Protocol

OPAQUE produces two outputs from a successful exchange:

- **`exportKey`** (64 bytes) client-only, stable across every login for the same password. Never sent to the server. The root from which `masterKeyWrapper` is derived.
- **`sessionKey`** (64 bytes)  negotiated with the server and used to mint the API session cookie. The server derives the cookie token from this; the raw `sessionKey` is zeroized afterward.

Both are derived from the password + **OPRF** interaction and the three-DH key exchange. Neither can be reconstructed without the correct password and the server's `serverSetup`.

## 3. Registration

Registration is the only time most permanent key material is generated. Everything created here is either stored server-side in wrapped (encrypted) form, or shown once to the user (recovery phrase) and then discarded.

### 3.1 Full Registration Flow

```rs
1.  User enters email + password
2.  Client → opaque.client.startRegistration({ password })
              → { clientRegistrationState, registrationRequest }

3.  Client → Server: POST /auth/register/start
              { email, registrationRequest }

4.  Server verifies email is not already registered

5.  Server → opaque.server.createRegistrationResponse(
              { serverSetup, userIdentifier: email, registrationRequest })
              → { registrationResponse }

6.  Server → Client: { registrationResponse, continuationToken }

7.  Client → opaque.client.finishRegistration(...)
              → { registrationRecord, exportKey, serverStaticPublicKey }

8.  Client verifies serverStaticPublicKey == hardcoded pin
              ↳ ABORT if mismatch

9.  Client derives masterKeyWrapper = HKDF-SHA-512(exportKey, "vexahub:v1:masterKeyWrapper")

10. Client generates masterKey (32 bytes, CSPRNG) ← generated ONCE, permanent

11. Client generates X-Wing keypair    ← generated ONCE, permanent
    Client generates ML-DSA-65 keypair ← generated ONCE, permanent

12. Client wraps masterKey with masterKeyWrapper
              → VXWM blob (78 bytes)

13. Client wraps { X-Wing decaps key, ML-DSA-65 signing key } with masterKey
              → VXSK blob

14. Client generates 24-word BIP39 recovery phrase (256 bits entropy)
    Client derives recoveryKey from phrase
    Client wraps masterKey with recoveryKey
              → VXRM blob (78 bytes)

15. Client shows recovery phrase to user
    Client requires confirmation of specific word positions ← no skip

16. Client → Server: POST /auth/register/finish
              {
                email,
                continuationToken,
                registrationRecord,   ← OPAQUE envelope (server stores, cannot decrypt)
                vxwm,                 ← wrapped masterKey (password-derived)
                vxsk,                 ← wrapped sharing keypair
                vxrm,                 ← wrapped masterKey (recovery-derived)
                sharingPublicXwing,   ← X-Wing encapsulation key (plaintext, 1216 bytes)
                sharingPublicMldsa    ← ML-DSA-65 verification key (plaintext, ~1952 bytes)
              }

17. Server stores the user row atomically

18. Client zeroizes: password, exportKey, masterKeyWrapper,
                     plaintext private keys, recovery phrase, recoveryKey
    Client keeps live in Crypto Worker: masterKey, X-Wing decaps key, ML-DSA-65 signing key
```

### 3.2 What Gets Created at Registration

| Item                 | How                                             | Stored where                                          | Server can read?     |
|----------------------|-------------------------------------------------|-------------------------------------------------------|----------------------|
| `registrationRecord` | OPAQUE output                                   | Server (DB)                                           | No (opaque envelope) |
| `masterKey`          | CSPRNG (32 bytes)                               | Server as `VXWM` (wrapped)                            | No                   |
| `VXWM` blob          | `masterKey` encrypted with `masterKeyWrapper`   | Server (DB)                                           | No                   |
| `VXRM` blob          | `masterKey` encrypted with `recoveryKey`        | Server (DB)                                           | No                   |
| X-Wing keypair       | CSPRNG                                          | Decaps key in `VXSK`; encaps key plaintext on server  | Public key only      |
| ML-DSA-65 keypair    | CSPRNG                                          | Signing key in `VXSK`; verify key plaintext on server | Public key only      |
| `VXSK` blob          | Sharing private keys encrypted with `masterKey` | Server (DB)                                           | No                   |
| Recovery phrase      | BIP39 (256-bit entropy)                         | Shown once, never stored                              | Never                |

### 3.3 What the Server Stores (Users Table)

```sql
CREATE TABLE users (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                    CITEXT UNIQUE NOT NULL,
    locale                   TEXT NOT NULL DEFAULT 'en',
    opaque_protocol_version  SMALLINT NOT NULL DEFAULT 1,
    registration_record      BYTEA NOT NULL,        -- OPAQUE envelope
    vxwm                     BYTEA NOT NULL,        -- wrapped masterKey (password)
    vxrm                     BYTEA NOT NULL,        -- wrapped masterKey (recovery)
    vxsk                     BYTEA NOT NULL,        -- wrapped sharing keys
    sharing_public_xwing     BYTEA NOT NULL,        -- 1216 bytes, plaintext
    sharing_public_mldsa     BYTEA NOT NULL,        -- ~1952 bytes, plaintext
    reset_generation         INTEGER NOT NULL DEFAULT 0,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### 3.4 Key Derivation at Registration

```rs
password
    └─► OPAQUE (Argon2id 128 MiB client-side, OPRF server-side)
            ├─► exportKey (64 bytes) ─► HKDF ─► masterKeyWrapper (32 bytes)
            │                                        └─► encrypts masterKey ─► VXWM
            └─► sessionKey (64 bytes) ─► mints session cookie

masterKey (CSPRNG)
    ├─► encrypts { X-Wing decaps key, ML-DSA-65 signing key } ─► VXSK
    └─► encrypts masterKey via recoveryKey ─► VXRM

BIP39 phrase (CSPRNG, 256-bit)
    └─► HKDF ─► recoveryKey (32 bytes) ─► encrypts masterKey ─► VXRM
```

## 4. Login

Login reconstructs the session-time key material from the user's password and the blobs stored on the server. No permanent key material changes during login.

The `masterKey` is unwrapped and loaded into the Crypto Worker, then discarded from memory on logout or timeout.

### 4.1 Full Login Flow

```rs
1.  User enters email + password

2.  Client → opaque.client.startLogin({ password })
              → { clientLoginState, startLoginRequest }

3.  Client → Server: POST /auth/login/start
              { email, startLoginRequest }

4.  Server looks up user, loads registrationRecord

5.  Server → opaque.server.startLogin(...)
              → { loginResponse, serverLoginState }

6.  Server stores serverLoginState in Valkey
              (random continuationToken, 60-second TTL)

7.  Server → Client: { loginResponse, continuationToken, vxwm, vxsk }

8.  Client → opaque.client.finishLogin(...)
              → { finishLoginRequest, sessionKey, exportKey, serverStaticPublicKey }

9.  Client verifies serverStaticPublicKey == hardcoded pin
              ↳ ABORT if mismatch

10. Client derives masterKeyWrapper = HKDF-SHA-512(exportKey, "vexahub:v1:masterKeyWrapper")
    Client decrypts VXWM with masterKeyWrapper → masterKey
    Client decrypts VXSK with masterKey → { X-Wing decaps key, ML-DSA-65 signing key }

11. Client → Server: POST /auth/login/finish
              { continuationToken, finishLoginRequest }

12. Server retrieves + immediately deletes serverLoginState from Valkey

13. Server → opaque.server.finishLogin(...) → { sessionKey }

14. Server derives HTTP session token from sessionKey
    Server stores hashed session row in Postgres
    Server → Client: Set-Cookie (HttpOnly; Secure; SameSite=Strict)

15. Client zeroizes: password, exportKey, masterKeyWrapper
    Client loads into Crypto Worker: masterKey, X-Wing decaps key, ML-DSA-65 signing key
```

### 4.2 What Gets Reconstructed at Login

Nothing permanent is created at login. The following are derived transiently from the correct password and discarded when the session ends:

| Item                  | Derived from                          | Lives where                        | Discarded when                                  |
|-----------------------|---------------------------------------|------------------------------------|-------------------------------------------------|
| `exportKey`           | OPAQUE exchange                       | Client memory only                 | Immediately after `masterKeyWrapper` derivation |
| `masterKeyWrapper`    | HKDF(`exportKey`)                     | Client memory only                 | Immediately after unwrapping `masterKey`        |
| `masterKey`           | Unwrapped from `VXWM`                 | Crypto Worker only                 | Session timeout / logout                        |
| X-Wing decaps key     | Unwrapped from `VXSK` via `masterKey` | Crypto Worker only                 | Session timeout / logout                        |
| ML-DSA-65 signing key | Unwrapped from `VXSK` via `masterKey` | Crypto Worker only                 | Session timeout / logout                        |
| `sessionKey`          | OPAQUE exchange                       | Used to mint cookie, then zeroized | Immediately                                     |

### 4.3 Key Derivation at Login

```rs
password
    └─► OPAQUE (same Argon2id + OPRF as registration, same exportKey emerges)
            ├─► exportKey (64 bytes)
            │       └─► HKDF ─► masterKeyWrapper (32 bytes)
            │                        └─► decrypt VXWM ─► masterKey
            │                                              └─► decrypt VXSK ─► sharing keys
            └─► sessionKey ─► session cookie (server-side)
```

The `exportKey` is stable: as long as the password is the same and `serverSetup` has not changed, the same 64-byte value emerges from every login. This is how the server can store the wrapped `masterKey` once and have it be unwrappable on every future login without the server ever knowing the wrapping key.

### 4.4 Session Cookie

The server derives an HTTP session token from `sessionKey` and stores a **SHA-256 hash** of it in Postgres. The raw token is returned to the client as a cookie. Cookie attributes:

```rs
HttpOnly; Secure; SameSite=Strict; Path=/
```

Absolute lifetime: 24 hours, renewed on activity. The raw `sessionKey` is zeroized on both client and server immediately after the cookie is issued. The server never stores it.

## 5. Session Management

### 5.1 Active Session (Default)

Once logged in, the `masterKey` and sharing private keys live exclusively inside a dedicated **Crypto Web Worker**. They never touch the main JavaScript thread's heap.

The Worker exposes only operation endpoints. It never returns raw key material:

| Worker endpoint       | What it does                       |
|-----------------------|------------------------------------|
| `encryptFileSegment`  | Returns ciphertext                 |
| `decryptFileSegment`  | Returns plaintext                  |
| `deriveCollectionKey` | Returns encrypted operation result |
| `wrapForSharing`      | Returns VXSH blob                  |
| `unwrapFromSharing`   | Returns unwrapped key              |

**Inactivity timeout:** 30 minutes. The Worker is terminated and all in-memory key material is zeroized. The user must re-authenticate. Closing the browser tab has the same effect.

### 5.2 Persistent Session - "Remember Me" (opt-in only)

Never enabled by default. When opted in, a device-bound blob lets the user resume without re-entering their password.

**Activation:**

```rs
1. Client generates localKey (32 random bytes, CSPRNG)
2. Client wraps masterKey with localKey → VXPS blob → stored in IndexedDB
3. Client → Server: POST /auth/persistent-session/create { localKey, deviceLabel }
4. Server stores { userId, localKey, cookieHash, deviceLabel, createdAt, expiresAt }
5. Server issues PS-AUTH cookie (HttpOnly; Secure; SameSite=Strict; Max-Age=30d)
```

**Resume:**

```rs
1. Client detects VXPS blob in IndexedDB + PS-AUTH cookie
2. Client shows "Resume as <user>" prompt (no password form)
3. Client → Server: GET /auth/persistent-session/resume (cookie auto-attached)
4. Server validates cookie, returns { localKey, vxsk }
5. Client decrypts VXPS with localKey → masterKey → loaded into Worker
6. Server issues fresh active-session cookie alongside the persistent one
```

**Security trade-off (displayed at opt-in):**

> Remember me stores an encrypted copy of your keys on this device. The key to unlock them is held by VexaHub servers. Under normal operation your data stays private, but an attacker who fully controls our servers AND captures your session cookie could decrypt this remembered session. For maximum security, leave this option off and sign in with your password each time.

**Zero-knowledge tiers:**

| Mode                                 | True ZK?                          | Server holds         |
|--------------------------------------|-----------------------------------|----------------------|
| Web (no `Remember me`)               | ✅ Yes                            | Nothing session-side |
| Web (`Remember me`)                  | ⚠️ Trade-off (opt-in, documented) | `localKey`           |
| Web (`Remember me` + `WebAuthn` PRF) | ✅ Yes                            | Nothing              |
| Desktop / Mobile                     | ✅ Yes                            | Nothing              |

**Mandatory safeguards:**

- Strict opt-in only. No nudging.
- Settings page lists every persistent session with device label, creation time, last use, and one-click revoke.
- Password change revokes all persistent sessions server-side.
- `localKey` deleted server-side after 30 days of disuse.
- "Sign out everywhere" wipes all server-side persistent sessions and the local IndexedDB blob.
- `localKey` is never stored client-side in plaintext beyond the instant it is used to decrypt the `VXPS` blob.

### 5.3 Session Database Schema

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

## 6. Account Recovery

### 6.1 Recovery Phrase (Non-Destructive)

At registration a 24-word BIP39 phrase (256 bits of entropy) is generated and used to produce a second wrapped copy of `masterKey`. This means forgetting a password does not mean losing all data.

```rs
seed        = BIP39.mnemonicToSeed(phrase, passphrase = "")
recoveryKey = HKDF-SHA-512(
    ikm  = seed,
    salt = 32 zero bytes,
    info = "vexahub:v1:recoveryKey:{user_uuid}",
    L    = 32
)
```

**HKDF** rather than **Argon2id** is used here because the **BIP39** phrase already provides 256 bits of entropy. Memory-hardening would add latency with no meaningful security gain.

The phrase is shown once at registration, never stored client-side, never transmitted to the server. The user confirms specific word positions before registration completes. There is no skip option.

**Recovery flow (password forgotten, phrase available):**

1. User enters email + recovery phrase
2. Client → Server: `GET /auth/recovery/lookup?email={email}`  (rate-limited)
              ← { vxrm, user_uuid }
3. Client re-derives `recoveryKey` from phrase + user_uuid
4. Client decrypts `VXRM` → `masterKey` (same `masterKey` as always)
5. User chooses a new password
6. Client runs a fresh OPAQUE registration with the new password
7. Client re-wraps masterKey with the new `masterKeyWrapper` → new `VXWM`
8. Client → Server: `POST /auth/recovery/finish`
              { registrationRecord, vxwm, vxsk }  (atomic replace)
9. All existing files, collections, and shares remain valid. `masterKey` never changed

### 6.2 Destructive Reset

When both password and recovery phrase are lost. Triggered only via an email-confirmed link. Displays an explicit data-loss warning, then atomically wipes all files and rotates all key material under a new `reset_generation`. There is no way back from this path.

### 6.3 Phrase Rotation

From settings, an authenticated user can regenerate their recovery phrase. The new phrase wraps the existing `masterKey`; the old `VXRM` is replaced atomically. The `masterKey` itself does not change, so no file re-encryption is needed.

## 7. Key Material Quick Reference

### What exists only at registration

| Item              | Notes                                                                   |
|-------------------|-------------------------------------------------------------------------|
| `masterKey`       | Generated once via CSPRNG. Never regenerated unless destructive reset.  |
| X-Wing keypair    | Permanent. Decaps key wrapped in `VXSK`.                                |
| ML-DSA-65 keypair | Permanent. Signing key wrapped in `VXSK`.                               |
| `VXWM` blob       | Wrapped `masterKey` keyed to the password. Replaced on password change. |
| `VXRM` blob       | Wrapped `masterKey` keyed to the recovery phrase.                       |
| `VXSK` blob       | Wrapped sharing keypair. Re-wrapped on password change.                 |
| Recovery phrase   | Shown once. Never stored anywhere.                                      |

### What exists only during a session

| Item                         | Origin                | Discarded                                       |
|------------------------------|-----------------------|-------------------------------------------------|
| `exportKey`                  | OPAQUE output         | Immediately after `masterKeyWrapper` derivation |
| `masterKeyWrapper`           | HKDF(`exportKey`)     | Immediately after unwrapping `masterKey`        |
| `sessionKey`                 | OPAQUE output         | Immediately after cookie is issued              |
| `masterKey` (live)           | Unwrapped from `VXWM` | Session timeout / logout / tab close            |
| X-Wing decaps key (live)     | Unwrapped from `VXSK` | Session timeout / logout / tab close            |
| ML-DSA-65 signing key (live) | Unwrapped from `VXSK` | Session timeout / logout / tab close            |

### What the server knows vs does not know

| Server knows                                        | Server never knows                   |
|-----------------------------------------------------|--------------------------------------|
| Email address                                       | Password (or any hash of it)         |
| OPAQUE `registrationRecord` (opaque envelope)       | `exportKey`                          |
| `VXWM`, `VXRM`, `VXSK` blobs (ciphertext only)      | `masterKeyWrapper`                   |
| X-Wing encapsulation key (public)                   | `masterKey`                          |
| ML-DSA-65 verification key (public)                 | `collectionKey`, `fileKey`           |
| Session cookie hash                                 | File content, file names, mime types |
| `localKey` (persistent sessions only)               | Recovery phrase                      |
| File/collection UUIDs, ciphertext sizes, timestamps | Any plaintext metadata               |
