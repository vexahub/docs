# VexaHub - Cryptography Specification

**Document version:** 3
**Protocol version:** 1
**Status:** (Draft) pre-MVP

This document is the single source of truth for all cryptographic decisions in VexaHub. Any change to the parameters, algorithms, derivation paths, or binary formats defined here is a breaking change for existing accounts and MUST bump the protocol version (see [§13](#13-protocol-versioning-and-migration)).

## 1. Overview

VexaHub is a **zero-knowledge end-to-end encrypted** cloud storage service. The server never has access to user passwords, plaintext files, file names, or encryption keys capable of decrypting user data during normal operation.

Cryptographic goals:

- The server **cannot** decrypt user files, even with full database access.
- An attacker stealing only the database **cannot** mount offline password attacks **(OPAQUE OPRF defense)**.
- Password changes **do not** require re-encrypting user files.
- File mutation is supported **without** nonce-reuse vulnerabilities.
- Sharing is possible between users **without** the server learning shared content.
- **Post-quantum resistance** for *sharing key exchange*.
- Cross-platform **consistency** (web, desktop, future Android/iOS) via a Rust implementation compiled to **WASM**, **native**, and **UniFFI** targets.

Explicit non-goals:

- Defense **against** a fully compromised server colluding with itself to **attack a user** during an active session. A **persistent** session ([§9.2](#92-persistent-sessions-remember-me-opt-in)) opt-in widens this surface and is documented as such.
- Defense **against** a **malicious client update** pushed via the normal distribution channel. **Reproducible** builds are tracked as future work (See [§18](#18-open-questions-and-future-work)).
- Defense **against** an **attacker** with physical control of the user's unlocked device.

## 2. Primitives

| Purpose                     | Algorithm                              | Parameters                                                      |
|-----------------------------|----------------------------------------|-----------------------------------------------------------------|
| Password-authenticated AKE  | OPAQUE (RFC 9807)                      | Ristretto255 ciphersuite, `(3DH + ML-KEM-768)`                  |
| Key stretching (in OPAQUE)  | Argon2id                               | m = 131072 KiB (128 MiB), t = 3, p = 4                          |
| Symmetric AEAD              | XChaCha20-Poly1305                     | 24-byte nonces, 16-byte tags                                    |
| Key derivation              | HKDF-SHA-512                           | Domain-separated `info`, zero salt                              |
| Hybrid KEM (Sharing)        | X-Wing (draft-connolly-cfrg-xwing-kem) | ML-KEM-768 + X25519, 32-byte shared secret                      |
| Hybrid KEM (OPAQUE AKE)     | TripleDhKem (`opaque-ke`)              | 3DH + ML-KEM-768 encapsulation in KE1/KE2                       |
| Digital signatures          | ML-DSA-65 (FIPS 204)                   | Share invitation authenticity, device attestation, key rotation |
| CSPRNG                      | OS CSPRNG                              | `getrandom` (Rust), `crypto.getRandomValues` (web)              |
| Memory hygiene              | `zeroize` crate                        | All key material wrapped in `Zeroizing<T>`                      |

**Rationale:**

- **Ristretto255** over **P-256**: prime-order group, simpler hash-to-curve, better-maintained **constant-time** implementations in the **Rust** ecosystem.
- **Argon2id 128 MiB / t=3 / p=4**: above **OWASP 2024** and industry baselines (Bitwarden, 1Password sit around 64 MiB), while staying below the **~256 MiB** threshold where **Safari iOS WASM** allocations begin to fail. **OPAQUE OPRF** already neutralizes **pre-computation attacks** against the database; the **Argon2id** cost is a **defense-in-depth** layer for the case where `serverSetup` is also **compromised**. Frozen identical for all users on protocol version 1. No per-user fallback, no heterogeneous parameters.
- **XChaCha20-Poly1305** over **AES-GCM**: 24-byte nonces make random nonce generation safe without counters; constant-time on all platforms; no hardware AES dependency.
- **HKDF-SHA-512**: matches the **OPAQUE** ciphersuite hash, universally available, larger output reservoir than **SHA-256** with no performance penalty in this context.
- **X-Wing** over manual **ML-KEM-768 + X25519** combiner: formally proven IND-CCA secure construction (IACR 2024) with an optimized combiner that avoids hashing the ML-KEM ciphertext. Secure if either **X25519** or **ML-KEM-768** is secure. Eliminates a custom KDF combiner from our attack surface. Still an **IETF Internet-Draft** ([draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)) but the underlying algorithms are **NIST-finalized** and the wire format is stable.
- **TripleDhKem** over standard **TripleDH**: the `opaque-ke` crate's `TripleDhKem` variant augments the **OPAQUE 3DH** key exchange by having the client send an **ML-KEM-768** encapsulation key in **KE1** and the server encapsulate to it in **KE2**. The **ML-KEM** shared secret is mixed into the key schedule alongside the **three DH** products. This closes the **harvest-now-decrypt-later** threat on login transcripts. An **attacker** recording **OPAQUE** flows today **cannot** derive session keys with a future **CRQC**. The **Ristretto255** OPRF remains classical; a **CRQC** + database + `serverSetup` theft would allow offline password attacks, but Argon2id 128 MiB remains as the final barrier. This is the **strongest** hybrid OPAQUE available today; **full** PQ OPAQUE ([draft-vos-cfrg-pqpake](https://datatracker.ietf.org/doc/draft-vos-cfrg-pqpake/)) is tracked as **future** work.
- **ML-DSA-65** (NIST Level 3): matches the security level of **ML-KEM-768** inside **X-Wing**. Without **PQ** signatures, a **CRQC** could forge share invitations, device registrations, and key rotations. Compromising the trust graph **without** ever breaking encryption. Signature sizes (~3.3 KB) and public keys (~1.95 KB) are larger than **Ed25519** but acceptable for metadata-layer operations.

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
    ├──► X-Wing keypair          (decaps key wrapped by masterKey)
    └──► ML-DSA-65 keypair       (signing key wrapped by masterKey)
          public keys (encaps + verify) stored server-side in plaintext
```

The intermediate `masterKeyWrapper` exists for uniformity with all other derivations and to avoid using `exportKey` directly as an AEAD key. It carries no extra security versus a direct slice of `exportKey`, but keeps the derivation graph consistent.

### 3.1 Key summary

| Key                        | Size  | Origin                         | Lifetime  | Server sees            |
|----------------------------|-------|--------------------------------|-----------|------------------------|
| password                   | var   | User input                     | Typing    | Never                  |
| exportKey                  | 64    | OPAQUE output                  | Session   | Never                  |
| masterKeyWrapper           | 32    | HKDF(exportKey)                | Session   | Never                  |
| sessionKey                 | 64    | OPAQUE output                  | Session   | Yes (used for cookie)  |
| masterKey                  | 32    | CSPRNG at registration         | Permanent | Wrapped only           |
| collectionKey              | 32    | HKDF(masterKey, collection_id) | Permanent | Never (derived client) |
| fileKey                    | 32    | HKDF(collectionKey, file_id)   | Permanent | Never (derived client) |
| recoveryKey                | 32    | HKDF(BIP39 seed)               | Recovery  | Never                  |
| X-Wing decaps key          | 32    | CSPRNG at registration         | Permanent | Wrapped only           |
| X-Wing encaps key (pub)    | 1216  | Derived from decaps key        | Permanent | Plaintext              |
| ML-DSA-65 signing key      | ~4032 | CSPRNG at registration         | Permanent | Wrapped only           |
| ML-DSA-65 verify key (pub) | ~1952 | Derived from signing key       | Permanent | Plaintext              |

## 4. HKDF Domain Separation

All HKDF derivations use HKDF-SHA-512 with a 32-byte zero salt and a unique `info` string. Format: `vexahub:v{PROTOCOL_VERSION}:{purpose}[:{context}]`.

| Derivation                             | `info` string                                      | length |
|----------------------------------------|----------------------------------------------------|--------|
| masterKeyWrapper from exportKey        | `vexahub:v1:masterKeyWrapper`                      | 32     |
| collectionKey from masterKey           | `vexahub:v1:collectionKey:{collection_uuid}`       | 32     |
| contentIdKey from masterKey            | `vexahub:v1:contentIdKey`                          | 32     |
| fileKey from collectionKey             | `vexahub:v1:fileKey:{file_uuid}`                   | 32     |
| fileContentKey from fileKey            | `vexahub:v1:fileContentKey`                        | 32     |
| fileMetadataKey from fileKey           | `vexahub:v1:fileMetadataKey`                       | 32     |
| segmentNonce from fileContentKey       | `vexahub:v1:segmentNonce:{generation}:{index}`     | 24     |
| recoveryKey from BIP39 seed            | `vexahub:v1:recoveryKey:{user_uuid}`               | 32     |
| shareWrapKey from X-Wing shared secret | `vexahub:v1:shareWrap:{share_uuid}`                | 32     |

HKDF salts are not secrets; uniqueness is enforced exclusively by the `info` field. Zero salt simplifies cross-platform interoperability and has no security impact when `info` is unique per purpose.

## 5. Binary Blob Formats

All encrypted blobs use versioned, self-describing binary formats prefixed with 4 magic bytes, a format version, and an algorithm ID. Parsers MUST verify magic, version, and algorithm before decryption. Unknown values MUST cause an error, never a silent fallback.

Algorithm IDs:

- `0x01` >  XChaCha20-Poly1305
- `0x02` > X-Wing (ML-KEM-768 + X25519)

Signature algorithm IDs (new, for share records):

- `0x10` > ML-DSA-65

### 5.1 `VXWM` - Wrapped Master Key (password-derived)

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

### 5.2 `VXRM` - Wrapped Master Key (recovery-phrase-derived)

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

### 5.3 `VXFC` - File Content Segment

```rs
Offset  Size   Field
0       4      Magic "VXFC"
4       1      Format version (0x01)
5       1      Algorithm ID (0x01)
6       4      File generation (uint32 BE)
10      8      Segment index (uint64 BE)
18      24     Nonce (derived deterministically)
42      N+16   Ciphertext + tag
```

The AAD bound to each segment is the 14-byte tuple `version || alg_id || generation || segment_index`. This binds every ciphertext to its position and generation, preventing reorder and rollback attacks within a file.

### 5.4 `VXFM` - File Metadata

```rs
Offset  Size   Field
0       4      Magic "VXFM"
4       1      Format version (0x01)
5       1      Algorithm ID (0x01)
6       4      File generation (uint32 BE)
10      24     Nonce (random)
34      N+16   Ciphertext (CBOR-encoded metadata) + tag
```

CBOR schema for plaintext metadata (canonical CBOR, [RFC 8949 §4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html#name-core-deterministic-encoding)):

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

### 5.5 `VXPS` - Persistent Session Blob

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

### 5.6 `VXSK` - Wrapped Sharing Keys

```rs
Offset  Size   Field
0       4      Magic "VXSK"
4       1      Format version (0x01)
5       1      Algorithm ID (0x01)
6       24     Nonce (random)
30      N+16   Ciphertext (CBOR object) + tag
```

CBOR schema:

```asm
{
  "xw": bstr .size 32,    // X-Wing decapsulation key (seed)
  "ds": bstr,             // ML-DSA-65 signing key
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

### 6.5 Content Identification and Resumable Upload Integration

VexaHub uses the [tus 1.0.0](https://tus.io/protocols/resumable-upload/1-0-x) resumable upload protocol for all file transfers between clients and the server. This section specifies how the cryptographic design integrates with **tus**, and how the **client** identifies file content in a way that preserves the **zero-knowledge** guarantee.

### 6.5.1 Goals

- Allow a **client** to detect that a previously interrupted upload exists on the server and resume it from the correct offset, **without** re-uploading already-transferred segments.
- Allow a **client** to detect that the file the user is about to upload **already** exists in their account, and offer to skip, replace, or duplicate it.
- Preserve the **zero-knowledge** property: the server **MUST NOT** be able to determine the plaintext content of a file from its content identifier, and **MUST NOT** be able to detect that two distinct users hold the same plaintext file.

### 6.5.2 Per-user content identifier

For **each** file, the **client** computes a content identifier as a keyed hash bound to the user's `masterKey`:

```rs
contentIdKey = HKDF-SHA-512(
    ikm  = masterKey,
    salt = 32 zero bytes,
    info = "vexahub:v1:contentIdKey",
    L    = 32
)

content_id = BLAKE3_keyed(contentIdKey, plaintext)   // 32 bytes
```

Properties:

- **Deterministic per user**: the same plaintext produces the same `content_id` for the **same** user, enabling **reliable** resume detection.
- **Distinct across users**: two different **users** with the same plaintext produce different `content_id` values, because their `contentIdKey` differs.
- **Not invertible**: the **server** cannot recover plaintext from `content_id`.
- **Not testable against known content**: the **server** cannot pre-compute hashes of known files (leaks, public datasets, copyrighted material) and look them up in the **database**, because the keyed hash requires `contentIdKey` which the **server** never sees.

The **client** transmits `content_id` to the **server** in the clear as part of upload lookup and creation requests. The **server** stores it indexed **per user** but **cannot** use it for any **cross-user analysis**.

### 6.5.3 No cross-user deduplication

By design, **VexaHub** does **NOT** perform **cross-user deduplication** of stored content. If two **users** upload the same file, **two distinct ciphertext blobs** are **stored**.

This is a deliberate **trade-off**: **cross-user deduplication** is **incompatible** with **strong zero-knowledge** guarantees because it **leaks** the existence of duplicate content across **accounts** and creates an **oracle** for content presence.

### 6.5.4 Streaming computation

`BLAKE3_keyed` supports **incremental** hashing. The client **MUST** compute `content_id` in a **streaming** fashion as it reads the **local** file, never loading the **full** plaintext into **memory**. For **very** large files (multi-GiB), the client **SHOULD** display a **"Preparing upload"** progress indicator during this phase, since it **precedes** the actual upload.

### 6.5.5 tus integration

VexaHub uses the [tus 1.0.0](https://tus.io/protocols/resumable-upload/1-0-x) core protocol with the **Creation** and **Termination** extensions. The **Checksum** extension is **NOT** used: per-segment **Poly1305** authentication tags already provide **cryptographic** integrity, and adding a tus-level **checksum** (md5/sha1/crc32) would be **redundant** and **weaker**.

**Upload-Length semantics**: the tus `Upload-Length` header carries the **ciphertext** length, not the plaintext length. The client computes the expected ciphertext length deterministically from the plaintext length:

```rs
plaintext_size                        = N bytes
SEGMENT_PLAINTEXT_SIZE                = 1 MiB = 1,048,576 bytes
SEGMENT_HEADER_SIZE                   = 42 bytes (VXFC header)
SEGMENT_TAG_SIZE                      = 16 bytes (Poly1305)
SEGMENT_CIPHERTEXT_OVERHEAD           = SEGMENT_HEADER_SIZE + SEGMENT_TAG_SIZE = 58 bytes
SEGMENT_CIPHERTEXT_SIZE_FULL          = SEGMENT_PLAINTEXT_SIZE + SEGMENT_TAG_SIZE + SEGMENT_HEADER_SIZE = 1,048,634 bytes

full_segments                         = floor(N / SEGMENT_PLAINTEXT_SIZE)
last_segment_plaintext                = N mod SEGMENT_PLAINTEXT_SIZE
last_segment_ciphertext               = (last_segment_plaintext > 0)
                                          ? last_segment_plaintext + SEGMENT_CIPHERTEXT_OVERHEAD
                                          : 0

ciphertext_length = full_segments × SEGMENT_CIPHERTEXT_SIZE_FULL + last_segment_ciphertext
```

The **plaintext** size is **never** sent to the **server**. The **server** knows **only** the ciphertext size as `Upload-Length`.

### 6.5.6 Upload lookup flow

Before **creating** a new tus upload, the **client** queries the **server** to detect a **resumable upload** or an **existing** committed file:

```rs
GET /api/v1/uploads/lookup?content_id={hex}&collection_id={uuid}
Accept: application/vnd.vexahub.v1+json
```

Server responses:

- **404 Not Found**: No existing upload or committed file matches.

    The client MUST proceed with a fresh tus `POST /uploads` to create a new upload resource.

- **200 OK** with `{ "kind": "incomplete", "tus_url": "...", "upload_offset": <int>, "generation": <int>, "expires_at": "..." }`:

    An incomplete upload exists for this user with this `content_id`. The client SHOULD send a tus `HEAD` to `tus_url` to confirm the offset, then resume with `PATCH` requests.

- **200 OK** with `{ "kind": "committed", "file_id": "...", "generation": <int> }`:

    The file already exists fully committed in the user's account. The client MUST prompt the user to choose between skip, replace (creates generation+1), or duplicate (creates a new `file_id`).

The server MUST scope the lookup to the authenticated user. Cross-user lookups by `content_id` MUST return 404 even if a match exists in another account.

### 6.5.7 Resume alignment

A tus `PATCH` MAY contain any number of bytes, and may interrupt at any byte boundary. When an interrupted upload is resumed via `HEAD` followed by `PATCH`, the server-reported `Upload-Offset` may fall in the middle of a VexaHub crypto segment. The client MUST NOT submit ciphertext starting at that arbitrary offset, because XChaCha20-Poly1305 does not support partial AEAD writes. A segment is a single atomic encryption unit.

Resume procedure:

1. Client sends `HEAD {tus_url}` and reads `Upload-Offset` (`O`).
2. Client computes the index of the segment that contains byte `O`:
        ```
segment_index = floor(O / SEGMENT_CIPHERTEXT_SIZE_FULL)
segment_start = segment_index × SEGMENT_CIPHERTEXT_SIZE_FULL
        ```
3. If `O > segment_start`, the server holds a partial segment. The client MUST request the server to truncate the upload back to `segment_start` via the custom endpoint:
        ```
POST /api/v1/uploads/{upload_id}/rewind
{ "to_offset": <segment_start> }
        ```
   The server MUST verify the requested offset is segment-aligned, truncate the underlying storage object, update `tus_uploads.upload_offset`, and respond 204.
4. Client resumes with `PATCH` from `segment_start`, re-deriving each segment nonce from `(generation, segment_index)` as defined in [§6.2](#62-per-segment-nonce-derivation).

The rewind endpoint is NOT part of the tus standard. It is a VexaHub extension necessary because tus alone cannot express the constraint that uploads must be aligned to AEAD segment boundaries.

### 6.5.8 Generation transitions during in-progress uploads

If the user modifies a file locally while an upload for that file is still in progress, the client MUST:

1. Send `DELETE {tus_url}` (tus Termination extension) to discard the in-progress upload server-side.
2. Recompute `content_id` for the new plaintext.
3. Increment the file's `generation` counter by 1.
4. Create a new tus upload via `POST /uploads` with the new `content_id`, the new `Upload-Length`, and the incremented `generation` in the upload metadata.

The server MUST NOT allow two concurrent uploads for the same `(user_id, file_id)` pair. The unique constraint defined in [§6.5.10](#6510-server-side-schema) enforces this.

### 6.5.9 Final integrity verification

After a download completes, the client MUST recompute `BLAKE3(plaintext)` and compare it against the `h` field stored in the file's `VXFM` blob (see [§5.4](#54-vxfm---file-metadata)). A mismatch indicates corruption, truncation, or tampering, and the client MUST refuse to surface the file to the user, MUST log the incident, and SHOULD offer to retry the download.

This BLAKE3 hash is the unkeyed plaintext hash and serves only as an integrity check on a reconstructed download. It is distinct from `content_id` in [§6.5.2](#652-per-user-content-identifier), which is keyed and serves as a per-user identifier for resume and duplicate detection.

### 6.5.10 Server-side schema

```sql
CREATE TABLE tus_uploads (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    file_id       UUID,                       -- NULL until commit
    collection_id UUID NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    content_id    BYTEA NOT NULL,             -- 32 bytes BLAKE3_keyed
    generation    INTEGER NOT NULL,
    upload_length BIGINT NOT NULL,            -- ciphertext bytes
    upload_offset BIGINT NOT NULL DEFAULT 0,
    storage_path  TEXT NOT NULL,              -- e.g. tus-incomplete/{id}
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,       -- TTL for abandoned uploads
    completed_at  TIMESTAMPTZ                 -- NULL until commit
);

-- Prevents two concurrent uploads of the same content for the same user
CREATE UNIQUE INDEX tus_uploads_user_content_active
    ON tus_uploads (user_id, content_id)
    WHERE completed_at IS NULL;

-- Prevents two concurrent uploads for the same logical file
CREATE UNIQUE INDEX tus_uploads_user_file_active
    ON tus_uploads (user_id, file_id)
    WHERE completed_at IS NULL AND file_id IS NOT NULL;

CREATE INDEX tus_uploads_expires_active
    ON tus_uploads (expires_at)
    WHERE completed_at IS NULL;

CREATE INDEX tus_uploads_user_collection
    ON tus_uploads (user_id, collection_id);
```

### 6.5.11 Abandoned upload garbage collection

A scheduled job MUST periodically (recommended: hourly) remove rows from `tus_uploads` where `completed_at IS NULL AND expires_at < now()`, and MUST delete the corresponding object at `storage_path` from the object storage backend. The default TTL for an incomplete upload is **7 days** from `created_at`, refreshed to 7 days on each successful `PATCH`. Long-running uploads of very large files therefore stay alive as long as the user is making progress, but truly abandoned uploads are reaped within a week.

### 6.5.12 Threat model additions

| Attacker capability                                          | VexaHub response                                                                                                                         |
|--------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| Server tries to test database for known plaintext via hash   | Blocked: `content_id` is keyed by per-user `contentIdKey`, never seen by server                                                          |
| Server tries cross-user deduplication to infer relationships | Blocked: distinct users produce distinct `content_id` for identical plaintext                                                            |
| Server truncates an upload to inject a shorter file          | Detected at download via BLAKE3 plaintext hash in `VXFM` ([§5.4](#54-vxfm---file-metadata), [§6.5.9](#659-final-integrity-verification)) |
| Server reorders segments within a generation                 | Blocked by per-segment AAD binding `(version, alg, generation, segment_index)`                                                           |
| Server rolls back to an older generation                     | Blocked by monotonic `generation` enforcement ([§6.3](#63-file-generation-counter-mutability)) and client-side verification              |

## 7. OPAQUE Protocol

### 7.1 Implementation

VexaHub implements **OPAQUE** ([RFC 9807](https://www.rfc-editor.org/info/rfc9807)) in Rust crates, which serves as the cryptographic source of truth for all clients and the server. The crates are compiled to:

- **WebAssembly** via `wasm-bindgen` for the **SvelteKit** webapp.
- **Native** Rust linkage for the **Tauri** desktop application.
- **NAPI-RS** bindings for the **backend**.
- **UniFFI** bindings for future **Android (Kotlin)** and **iOS (Swift)** clients.

A **single** implementation produces **byte-for-byte** identical outputs across all targets, verified by the cross-target test vectors in [§14](#14-test-vectors).

### 7.2 Ciphersuite (frozen at protocol version 1)

- OPRF group: Ristretto255
- KE group: Ristretto255
- Hash: SHA-512
- Key exchange: TripleDhKem (Triple Diffie-Hellman + ML-KEM-768 hybrid)
- Key stretching function: Argon2id with the parameters in [§2](#2-primitives)

This ciphersuite is identical across every client and the server. Any change is a protocol version bump.

> The `TripleDhKem` variant extends the standard OPAQUE 3DH key exchange with a post-quantum KEM hop. During KE1, the client generates an ephemeral ML-KEM-768 keypair and sends the encapsulation key alongside the standard DH ephemeral. In KE2, the server encapsulates to the client's ML-KEM-768 key and includes the ciphertext in the response. Both parties absorb the KEM ciphertext into the transcript hash and mix the ML-KEM shared secret with the three DH products when deriving session keys.
>
> This ensures session keys are quantum-resistant: an attacker must break both the Ristretto255 DH and ML-KEM-768 to recover a session key from a recorded login transcript. The OPRF (Ristretto255) remains classical. See [§17](#17-threat-model-summary) for the residual threat model.

### 7.3 Server setup

At first deployment, the server generates a one-time `serverSetup` containing the **OPRF** secret key (the global pepper) and the server's static **AKE** keypair.

**Storage requirements:**

- Loaded into SERVER via the `OPAQUE_SERVER_SETUP` environment variable.
- NEVER committed to Git, NEVER logged, NEVER returned in any API response.
- Backed up encrypted in at least two independent locations (Pass **vault** + offline encrypted **backup** on **cold storage**).
- Rotation invalidates all existing accounts and is treated strictly as a disaster-recovery action.

**Loss of `serverSetup` = permanent loss of all user accounts.** Backup discipline is **non-negotiable**.

### 7.4 Server static public key pinning

All clients pin the server's static public key, derived from `serverSetup` and hardcoded at build time. On every OPAQUE flow completion, the client compares the received `serverStaticPublicKey` against the pinned value. Mismatch MUST abort the flow and surface a security warning to the user.

This defends against a substituted server, contingent on the client distribution channel not being compromised (see [§17](#17-threat-model-summary) and [§18](#18-open-questions-and-future-work)).

## 8. Registration and Login Flows

### 8.1 Registration

1. Client: user enters email and password.
2. Client: `opaque.client.startRegistration({ password })` ➜ `{ clientRegistrationState, registrationRequest }`.
3. Client ➜ Server: `POST /auth/register/start { email, registrationRequest }`.
4. Server: verifies email is not already registered.
5. Server: `opaque.server.createRegistrationResponse({ serverSetup, userIdentifier: email, registrationRequest })` ➜ `{ registrationResponse }`.
6. Server ➜ Client: `{ registrationResponse, continuationToken }`.
7. Client: `opaque.client.finishRegistration(...)` ➜ `{ registrationRecord, exportKey, serverStaticPublicKey }`.
8. Client: verifies `serverStaticPublicKey` matches the hardcoded pin; aborts on mismatch.
9. Client: derives `masterKeyWrapper` from `exportKey`.
10. Client: generates `masterKey` (32 random bytes from CSPRNG).
11. Client: generates X-Wing keypair and ML-DSA-65 signing keypair.
12. Client: wraps `masterKey` with `masterKeyWrapper` ➜ `VXWM` blob.
13. Client: wraps sharing private keys with `masterKey` ➜ `VXSK` blob.
14. Client: generates a 24-word BIP39 recovery phrase, derives `recoveryKey`, wraps `masterKey` ➜ `VXRM` blob (see [§12](#12-account-recovery)).
15. Client: requires the user to confirm the recovery phrase by re-entering specific word positions.
16. Client ➜ Server: `POST /auth/register/finish { email, continuationToken, registrationRecord, vxwm, vxsk, vxrm, sharingPublicXwing, sharingPublicMldsa }`.
17. Server: stores the user row atomically.
18. Client: zeroizes `password`, `exportKey`, `masterKeyWrapper`, plaintext private keys, recovery phrase, `recoveryKey`. Keeps `masterKey` and sharing private keys live in the Crypto Worker.

### 8.2 Login

1. Client: user enters email and password.
2. Client: `opaque.client.startLogin({ password })` ➜ `{ clientLoginState, startLoginRequest }`.
3. Client ➜ Server: `POST /auth/login/start { email, startLoginRequest }`.
4. Server: looks up the user, loads `registrationRecord`.
5. Server: `opaque.server.startLogin(...)` ➜ `{ loginResponse, serverLoginState }`.
6. Server: stores `serverLoginState` in Valkey under a random `continuationToken` with a 60-second TTL.
7. Server ➜ Client: `{ loginResponse, continuationToken, vxwm, vxsk }`.
8. Client: `opaque.client.finishLogin(...)` ➜ `{ finishLoginRequest, sessionKey, exportKey, serverStaticPublicKey }`.
9. Client: verifies pinned key.
10. Client: derives `masterKeyWrapper`, parses `VXWM`, decrypts `masterKey`.
11. Client: parses `VXSK`, decrypts sharing private keys with `masterKey`.
12. Client ➜ Server: `POST /auth/login/finish { continuationToken, finishLoginRequest }`.
13. Server: retrieves and immediately deletes `serverLoginState` from Valkey.
14. Server: `opaque.server.finishLogin(...)` ➜ `{ sessionKey }`.
15. Server: derives an HTTP session token from `sessionKey`, stores a hashed session row in Postgres, returns `HttpOnly; Secure; SameSite=Strict` cookie.
16. Client: zeroizes `password`, `exportKey`, `masterKeyWrapper`. `masterKey` and sharing private keys are loaded into the Crypto Web Worker.

## 9. Session Management

### 9.1 Active sessions (default)

- `masterKey` and sharing private keys live exclusively inside a dedicated Crypto Web Worker, never in the main thread's JavaScript heap.
- Main ↔ Worker communication uses a strict request/response protocol (`encryptFileSegment`, `decryptFileSegment`, `deriveCollectionKey`, `wrapForSharing`, `unwrapFromSharing`). The Worker never returns raw key material, only operation results.
- Inactivity timeout: 30 minutes. On timeout, the Worker is terminated and all in-memory key material is zeroized; the user must re-authenticate.
- Session cookie: 24-hour absolute lifetime, renewed on activity, `HttpOnly; Secure; SameSite=Strict`.
- Closing the tab destroys the Worker and the `masterKey`. Without a persistent session, the next visit requires a fresh login.
- Worker script is served same-origin under strict CSP ([§16](#16-web-security-headers)), no inline, no eval beyond `wasm-unsafe-eval`.

### 9.2 Persistent sessions ("Remember me", opt-in)

A device-bound resume mechanism. NEVER enabled by default.

Activation:

1. Client generates `localKey` (32 random bytes).
2. Client wraps `masterKey` with `localKey` ➜ `VXPS` blob, stored in IndexedDB.
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

> Remember me stores an encrypted copy of your keys on this device. The key to unlock them is held by VexaHub servers. Under normal operation your data stays private, but an attacker who fully controls our servers AND captures your session cookie could decrypt this remembered session. For maximum security, leave this option off and sign in with your password each time.
>
> Users who require strict zero-knowledge guarantees on web should leave `Remember me` unchecked and authenticate with their password each session. Desktop and mobile clients achieve zero-knowledge persistent sessions via OS keychain. The server holds no key material in either case.

#### Zero-knowledge tiers

| Mode                                 | Zero-knowledge                     | Server holds         |
|--------------------------------------|------------------------------------|----------------------|
| Web (no `Remember me`)               | ✅ True ZK                         | Nothing session-side |
| Web (`Remember me`)                  | ⚠️ Trade-off (opt-in, documented)  | `localKey`           |
| Web (`Remember me` + `WebAuthn` PRF) | ✅ True ZK                         | Nothing              |
| Desktop / Mobile                     | ✅ True ZK                         | Nothing              |

#### WebAuthn PRF (future, non-trivial)

Browsers supporting the WebAuthn `prf` extension can derive a device-bound secret from a passkey or hardware authenticator that never leaves the device, replacing `localKey` entirely.

Support as of early 2026 is now broad:

- Chrome, Edge, Brave, and Samsung Internet via Google Password Manager passkeys (100% PRF-on-create success in Q1 2026 community testing)
- Firefox 148+
- Safari via Apple Passwords/iCloud Keychain
- Windows Hello after the February 2026 update (KB5077181).

> The main remaining gap is roaming authenticators (YubiKeys) on iOS/macOS
>
> Apple has acknowledged this but not yet shipped it.

Implementation requires a registered passkey per device and a graceful fallback to the standard `localKey` model for unsupported combinations. Tracked in [§18](#18-open-questions-and-future-work).

#### Mandatory safeguards

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
    sharing_public_xwing     BYTEA NOT NULL,   -- 1216 bytes, X-Wing encapsulation key
    sharing_public_mldsa     BYTEA NOT NULL,   -- ~1952 bytes, ML-DSA-65 verification key
    reset_generation         INTEGER NOT NULL DEFAULT 0,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### 10.2 What the server knows vs does not know

**Knows:** email, `registrationRecord` (opaque envelope), wrapped key blobs, public sharing keys, file existence and ciphertext size, file/collection UUIDs, hierarchy, timestamps, locale, `localKey` for any active persistent sessions only.

**Does not know:** password, `masterKey`, `exportKey`, `masterKeyWrapper`, `collectionKey`, `fileKey`, file content, file names, mime types, any plaintext metadata.

## 11. Sharing (X-Wing Hybrid KEM + ML-DSA-65 Signatures)

> Sharing wraps a `collectionKey` or `fileKey` such that only the recipient can unwrap it, and authenticates the invitation so the recipient can verify it came from the claimed sender. Not from the server or an attacker.

Send flow:

1. Sender fetches recipient's **X-Wing** encapsulation key and **ML-DSA-65** verification key from the server.
2. Sender encapsulates: `(ctXwing, sharedSecret) = X-Wing.Encaps(recipientPubXwing)`.
3. Sender derives `shareWrapKey = HKDF-SHA-512(ikm = sharedSecret, info = "vexahub:v1:shareWrap:{share_uuid}", L = 32)`.
4. Sender wraps the target key (collection or file) with `shareWrapKey` using **XChaCha20-Poly1305** ➜ `VXSH` blob.
5. Sender builds the **signed payload**: canonical CBOR encoding of `{ share_uuid, sender_id, recipient_id, ctXwing, vxsh, timestamp }`.
6. Sender signs the payload with their **ML-DSA-65** signing key ➜ `signature`.
7. Sender uploads `{ signedPayload, signature }` to the server.

Receive flow:

1. Recipient fetches the share record.
2. Recipient fetches sender's **ML-DSA-65** verification key **independently** from the server (Not from the share record! Prevents server substitution of both payload and key).
3. Recipient verifies `signature` against sender's verification key. **Reject on failure. Do not proceed to decryption.**
4. Recipient decapsulates: `sharedSecret = X-Wing.Decaps(privXwing, ctXwing)`.
5. Recipient derives `shareWrapKey` and unwraps `VXSH`.
6. Recipient stores the shared key in their own scope.

> Security degrades only if **both** X25519 and ML-KEM-768 are broken (X-Wing hybrid guarantee). Share authenticity degrades only if ML-DSA-65 is broken. The signature covers the entire invitation payload including `recipient_id` and `ctXwing`, preventing the server from redirecting shares to other users or swapping the encapsulated key material.
>
> **Critical design note:** The ML-DSA-65 signature sits **outside** the encrypted `VXSH` blob, at the transport layer. The recipient MUST verify the signature before trusting or decrypting the ciphertext. If the signature were inside the encrypted envelope, a malicious server could swap the entire `{ctXwing, vxsh}` package and the forgery would only be discovered after decryption (And that's too late).

`VXSH` blob format:

```bash
Offset  Size   Field
0       4      Magic "VXSH"
4       1      Format version (0x02)
5       1      KEM algorithm ID (0x02 = X-Wing)
6       24     Nonce (random)
30      N+16   Ciphertext (CBOR { "k": bstr, "kind": "collection"|"file", "id": bstr }) + tag
```

The signature is not part of the `VXSH` blob. It is stored alongside it in the share database record:

```sql
CREATE TABLE shares (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id       UUID NOT NULL REFERENCES users(id),
    recipient_id    UUID NOT NULL REFERENCES users(id),
    ct_xwing        BYTEA NOT NULL,         -- X-Wing ciphertext (1120 bytes)
    vxsh            BYTEA NOT NULL,         -- encrypted wrapped key blob
    sig_algorithm   SMALLINT NOT NULL,      -- 0x10 = ML-DSA-65
    signature       BYTEA NOT NULL,         -- ML-DSA-65 signature over canonical payload
    signed_payload  BYTEA NOT NULL,         -- canonical CBOR of the signed fields
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
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

1. HKDF derivations (every domain-separated path in [§4](#4-hkdf-domain-separation))
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

| Attacker capability                                    | VexaHub response                                                                                                                                                                                                                                                                                                                   |
|--------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Database snapshot                                      | No decryption possible; OPRF blocks offline password attacks                                                                                                                                                                                                                                                                       |
| Full server compromise, no active sessions intercepted | Cannot decrypt existing data; can observe future ciphertext                                                                                                                                                                                                                                                                        |
| Server compromise + active session cookie stolen       | Can decrypt that session's persistent blob if the user opted in (documented trade-off [§9](#9-session-management).2)                                                                                                                                                                                                               |
| Network MITM with valid TLS                            | Blocked by static public key pinning                                                                                                                                                                                                                                                                                               |
| Malicious client update                                | Not defended; reproducible builds tracked in [§18](#18-open-questions-and-future-work)                                                                                                                                                                                                                                             |
| Physical device compromise (unlocked)                  | Not defended beyond OS-level protections                                                                                                                                                                                                                                                                                           |
| XSS in webapp                                          | Strict CSP (no `unsafe-inline`), Worker isolation, no eval beyond WASM                                                                                                                                                                                                                                                             |
| Compromised `serverSetup`                              | Argon2id 128 MiB still imposes meaningful cost on offline dictionary attacks                                                                                                                                                                                                                                                       |
| File rollback / segment reorder by malicious server    | Blocked by `generation` counter and per-segment AAD binding                                                                                                                                                                                                                                                                        |
| CRQC (post-quantum adversary)                          | Sharing key exchange protected by X-Wing (ML-KEM-768 + X25519 hybrid); share authenticity protected by ML-DSA-65; login session keys protected by TripleDhKem (3DH + ML-KEM-768 hybrid); OPRF remains classical Ristretto255 (CRQC + database + `serverSetup` theft allows offline password attacks mitigated by Argon2id 128 MiB) |

## 18. Open Questions and Future Work

- PQ-resistant OPRF migration when standardized variants land (tracking draft-vos-cfrg-pqpake). Note: TripleDhKem already protects session keys; the remaining gap is the classical OPRF which exposes passwords to offline attack only under CRQC + database + `serverSetup` compromise, mitigated by Argon2id 128 MiB.
- WebAuthn PRF for biometric unlock.
- Reproducible builds for `vexahub-protocol` and the webapp bundle, published to a transparency log.
- Argon2id parameter telemetry on real device distributions to validate the 128 MiB choice.
- Argon2id experimental parameter for users to freely customize.
- `serverSetup` compromise incident response runbook.
- Possible independent third-party audit of `vexahub-protocol` once funding allows.
- X-Wing RFC finalization tracking. If wire format changes before RFC, bump `VXSH` format version and KEM algorithm ID.
- Hybrid signatures (Ed25519 + ML-DSA-65) evaluation for ANSSI/BSI compliance if regulatory requirements harden before 2030.
