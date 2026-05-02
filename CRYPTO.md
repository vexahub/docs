# VexaHub - Cryptography Specification

**Document version:** 7
**Protocol version:** 1
**Status:** (Draft) pre-MVP

This document is the single source of truth for all cryptographic decisions in VexaHub. Any change to the parameters, algorithms, derivation paths, or binary formats defined here is a breaking change for existing accounts and **MUST** bump the protocol version (see [§13](#13-protocol-versioning-and-migration)).

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
    └──► wraps collectionKey(s)
          │
          collectionKey (32 bytes, CSPRNG, per collection, wrapped by masterKey)
            │
            ├──► collectionMetadataKey = HKDF(collectionKey, "...collectionMetadataKey")
            └──► wraps fileKey(s)
                    │
                    fileKey (32 bytes, CSPRNG, per file, wrapped by collectionKey)
                            │
                            ├──► fileContentKey  = HKDF(fileKey, "...fileContentKey")
                            └──► fileMetadataKey = HKDF(fileKey, "...fileMetadataKey")


sharingKeyPair (generated at registration)
    │
    ├──► X-Wing keypair          (decaps key wrapped by masterKey)
    └──► ML-DSA-65 keypair       (signing seed wrapped by masterKey)
          public keys (encaps + verify) stored server-side in plaintext
```

The intermediate `masterKeyWrapper` exists for uniformity with all other derivations and to avoid using `exportKey` directly as an AEAD key. It carries no extra security versus a direct slice of `exportKey`, but keeps the derivation graph consistent.

### 3.1 Key summary

| Key                        | Size  | Origin                         | Lifetime         | Server sees            |
|----------------------------|-------|--------------------------------|------------------|------------------------|
| password                   | var   | User input                     | Typing           | Never                  |
| exportKey                  | 64    | OPAQUE output                  | Session          | Never                  |
| masterKeyWrapper           | 32    | HKDF(exportKey)                | Session          | Never                  |
| sessionKey                 | 64    | OPAQUE output                  | Session          | Yes (used for cookie)  |
| masterKey                  | 32    | CSPRNG at registration         | Permanent        | Wrapped only           |
| collectionKey              | 32    | CSPRNG at collection creation  | Until rotation   | Wrapped only           |
| fileKey                    | 32    | CSPRNG at file creation        | Until rotation   | Wrapped only           |
| recoveryKey                | 32    | HKDF(BIP39 seed)               | Recovery         | Never                  |
| X-Wing decaps key          | 32    | CSPRNG at registration         | Permanent        | Wrapped only           |
| X-Wing encaps key (pub)    | 1216  | Derived from decaps key        | Permanent        | Plaintext              |
| ML-DSA-65 signing seed     | 32    | CSPRNG at registration         | Permanent        | Wrapped only           |
| ML-DSA-65 verify key (pub) | 1952  | Derived from signing seed      | Permanent        | Plaintext              |

## 4. HKDF Domain Separation

Format: `vexahub:v{PROTOCOL_VERSION}:{purpose}[:{context}]`.

**Salt policy:** All HKDF derivations use a 32-byte zero salt except `shareWrapKey`, which uses a random 32-byte salt.

For derivations where the IKM is uniformly random (e.g. `masterKey`, `exportKey`, `collectionKey`, `fileKey`), zero salt has no security impact when `info` is unique per purpose, and simplifies cross-platform interoperability.

For `shareWrapKey`, the IKM is the X-Wing shared secret (output of a KEM combiner), not raw CSPRNG output. If the combiner ever produced biased output due to an implementation flaw or a weakness in one of the constituent KEMs, a random salt provides a meaningful extra defense layer. The salt is transmitted alongside the X-Wing ciphertext in the share record and does not need to be secret.

| Derivation                                   | `info` string                                                                 | length                |
|----------------------------------------------|-------------------------------------------------------------------------------|-----------------------|
| masterKeyWrapper from exportKey              | `vexahub:v1:masterKeyWrapper`                                                 | 32                    |
| collectionKeyWrap from masterKey             | `vexahub:v1:collectionKeyWrap:{collection_uuid}`                              | 32                    |
| fileKeyWrap from collectionKey               | `vexahub:v1:fileKeyWrap:{file_uuid}`                                          | 32                    |
| contentIdKey from masterKey (per collection) | `vexahub:v1:contentIdKey:{collection_uuid}`                                   | 32                    |
| fileContentKey from fileKey                  | `vexahub:v1:fileContentKey`                                                   | 32                    |
| fileMetadataKey from fileKey                 | `vexahub:v1:fileMetadataKey`                                                  | 32                    |
| collectionMetadataKey from collectionKey     | `vexahub:v1:collectionMetadataKey`                                            | 32                    |
| segmentNonce from fileContentKey             | `vexahub:v1:segmentNonce:` ‖ uint32_be(generation) ‖ uint64_be(segment_index) | 24                    |
| recoveryKey from BIP39 seed                  | `vexahub:v1:recoveryKey:{user_uuid}`                                          | 32                    |
| shareWrapKey from X-Wing shared secret       | `vexahub:v1:shareWrap:{share_uuid}`                                           | 32 (RNG 32-byte salt) |

> HKDF salts are not secrets; uniqueness is enforced exclusively by the `info` field.
>
> Zero salt simplifies cross-platform interoperability and has no security impact when `info` is unique per purpose.
>
> All UUIDs embedded in HKDF `info` strings MUST be encoded as **raw 16-byte big-endian binary**, not as hyphenated text.
>
> This eliminates formatting ambiguity across platforms and implementations. Example: UUID `550e8400-e29b-41d4-a716-446655440000` is encoded as 16 bytes `0x55 0x0e 0x84 ...`, not as 36-byte ASCII.

The `collectionKey` in `collectionMetadataKey` is unique per collection, so no `collection_uuid` is needed in the `info` string.

```rs
collectionMetadataKey = HKDF-SHA-512(
    ikm  = collectionKey,
    salt = 32 zero bytes,
    info = "vexahub:v1:collectionMetadataKey",
    L    = 32
)
```

The `collectionKeyWrapKey` and `fileKeyWrapKey` are derived solely to wrap/unwrap their respective stored keys:

```rs
collectionKeyWrapKey = HKDF-SHA-512(
    ikm  = masterKey,
    salt = 32 zero bytes,
    info = "vexahub:v1:collectionKeyWrap:" || collection_uuid,
    L    = 32
)

fileKeyWrapKey = HKDF-SHA-512(
    ikm  = collectionKey,
    salt = 32 zero bytes,
    info = "vexahub:v1:fileKeyWrap:" || file_uuid,
    L    = 32
)
```

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

```rs
AAD: user_id (16 bytes, raw UUID)
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

```rs
AAD: user_id (16 bytes, raw UUID)
```

### 5.3 `VXFC` - File Content Segment

```rs
Offset  Size   Field
0       4      Magic "VXFC"
4       1      Format version (0x01)
5       1      Algorithm ID (0x01)
6       16     File ID (UUID, raw bytes)
22      4      File generation (uint32 BE)
26      8      Segment index (uint64 BE)
34      24     Nonce (derived deterministically)
58      N+16   Ciphertext + tag
```

```rs
AAD = version ‖ alg_id ‖ file_id ‖ generation ‖ segment_index
// 1 + 1 + 16 + 4 + 8 = 30 bytes
```

The **AAD** bound to each segment is the **30-byte** tuple `version ‖ alg_id ‖ file_id ‖ generation ‖ segment_index`. This binds every ciphertext to its position and generation, preventing reorder and rollback attacks within a file.

### 5.4 `VXFM` - File Metadata

```rs
Offset  Size   Field
0       4      Magic "VXFM"
4       1      Format version (0x01)
5       1      Algorithm ID (0x01)
6       16     File ID (UUID, raw bytes)
22      4      File generation (uint32 BE)
26      24     Nonce (random)
50      N+16   Ciphertext (CBOR-encoded metadata) + tag
```

```rs
AAD = version ‖ alg_id ‖ file_id ‖ generation
// 1 + 1 + 16 + 4 = 22 bytes
```

CBOR schema for plaintext metadata (canonical CBOR, [RFC 8949 §4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html#name-core-deterministic-encoding)):

```rs
{
  "n":  tstr,           // filename
  "m":  tstr,           // mime type
  "s":  uint,           // plaintext size in bytes
  "sc": uint,           // total segment count
  "ct": uint,           // creation time, unix seconds
  "mt": uint,           // modification time, unix seconds
  "h":  bstr .size 32,  // BLAKE3 hash of plaintext (integrity)
}
```

> **Nonce requirement:** A fresh random nonce **MUST** be generated for every `VXFM` encryption, including re-encryption on generation increment. `fileMetadataKey` is derived from `fileKey` without `generation` in the derivation path, meaning the metadata key is **stable across generations**. Nonce reuse under the same `fileMetadataKey` is catastrophic. It breaks **XChaCha20-Poly1305** confidentiality.
>
> Implementors **MUST NOT** cache or reuse a previous `VXFM` nonce.
>
> **Segment count verification:** Before starting a download, the client **MUST** read `sc` from `VXFM` and verify that the number of segments received matches. A mismatch indicates truncation or tampering and the client **MUST** abort the download without surfacing partial content. This catches truncation before committing bandwidth, unlike the **BLAKE3** hash check in [§6.5.9](#659-final-integrity-verification) which only runs after the full download.

Unknown CBOR keys MUST be preserved on re-encryption to allow forward-compatible field additions.

> Parsers **MUST** reject non-canonical **CBOR** input. Any blob or payload that does not conform to [RFC 8949 §4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1) deterministic encoding **MUST** cause a hard error, **never** silent acceptance or re-canonicalization.

### 5.5 `VXCM` - Collection Metadata

```rs
Offset  Size  Field
------  ----  ---------------------------------------
0       4     Magic "VXCM"
4       1     Format version (0x01)
5       1     Algorithm ID (0x01)
6       16    Collection ID (UUID, raw bytes)
22      24    Nonce (random, fresh on every write)
46      N+16  Ciphertext (CBOR-encoded metadata) + tag
```

```rs
AAD = version ‖ alg_id ‖ collection_id
```

CBOR schema:

```asm
{
  "n": tstr,   // collection name
  "ct": uint,  // creation time
  "mt": uint,  // modification time
}
```

> **Nonce requirement:** `collectionMetadataKey` is stable for the lifetime of a `collectionKey`. A fresh random nonce **MUST** be generated on every `VXCM` write (rename, timestamp update). Nonce reuse under the same `collectionMetadataKey` is catastrophic.
>
> On `collectionKey` rotation (share revocation), `collectionMetadataKey` changes and the nonce space resets, but this **does not** relax the fresh-nonce requirement.

### 5.6 `VXPS` - Persistent Session Blob

Stored in **IndexedDB** on the user's device when `"Remember me"` is **enabled**.

```rs
Offset  Size  Field
0       4     Magic "VXPS"
4       1     Format version (0x01)
5       1     Algorithm ID (0x01)
6       24    Nonce (random)
30      48    Ciphertext (32 B masterKey + 16 B tag)
Total: 78 bytes
```

```rs
AAD: user_id (16 bytes, raw UUID)
```

### 5.7 `VXSK` - Wrapped Sharing Keys

```rs
Offset  Size   Field
0       4      Magic "VXSK"
4       1      Format version (0x01)
5       1      Algorithm ID (0x01)
6       24     Nonce (random)
30      N+16   Ciphertext (CBOR object) + tag
```

```rs
AAD: user_id (16 bytes, raw UUID)
```

CBOR schema:

```asm
{
  "xw": bstr .size 32,    // X-Wing decapsulation key (seed)
  "ds": bstr .size 32,    // ML-DSA-65 seed (not expanded signing key)
}
```

> Parsers **MUST** reject non-canonical **CBOR** input. Any blob or payload that does not conform to [RFC 8949 §4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1) deterministic encoding **MUST** cause a hard error, **never** silent acceptance or re-canonicalization.

### 5.8 `VXCK` - Wrapped Collection Key (new section)

```rs
Offset  Size  Field
------  ----  ---------------------------------------
0       4     Magic "VXCK" (0x56 0x58 0x43 0x4B)
4       1     Format version (0x01)
5       1     Algorithm ID (0x01)
6       24    Nonce (random)
30      48    Ciphertext (32 B collectionKey + 16 B tag)
------
Total: 78 bytes
```

```rs
AAD: user_id ‖ collection_id (32 bytes, both raw UUID)
```

### 5.9 `VXFK` - Wrapped File Key (new section)

```rs
Offset  Size  Field
------  ----  ---------------------------------------
0       4     Magic "VXFK" (0x56 0x58 0x46 0x4B)
4       1     Format version (0x01)
5       1     Algorithm ID (0x01)
6       24    Nonce (random)
30      48    Ciphertext (32 B fileKey + 16 B tag)
------
Total: 78 bytes
```

```rs
AAD: collection_id ‖ file_id (32 bytes, both raw UUID)
```

### 5.10 `VXSH` - Wrapped sharing key

```rs
Offset  Size   Field
------  ----  ---------------------------------------
0       4      Magic "VXSH"
4       1      Format version (0x02)
5       1      KEM algorithm ID (0x02 = X-Wing)
6       24     Nonce (random)
30      N+16   Ciphertext (CBOR { "k": bstr, "kind": "collection"|"file", "id": bstr }) + tag
------
Total: 112 bytes (file share) / 118 bytes (collection share)
```

```rs
AAD: sender_id ‖ recipient_id (32 bytes, both raw UUID)
```

This is **defense-in-depth** alongside the **ML-DSA-65** signature. If a signature verification is **accidentally** skipped due to a bug, the **AAD** binding still **prevents** the server from redirecting shares between users.

> Parsers **MUST** reject non-canonical **CBOR** input. Any blob or payload that does not conform to [RFC 8949 §4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1) deterministic encoding **MUST** cause a hard error, **never** silent acceptance or re-canonicalization.

## 6. File Encryption

### 6.1 Segmentation

Files are split into fixed-size plaintext segments. MVP segment size: **1 MiB** (1,048,576 bytes). The last segment may be shorter. Fixed segment size enables byte-precise Range requests on ciphertext, resumable uploads via `tus`, and parallel processing.

Zero-byte files are **supported**. A file with N=0 plaintext bytes produces zero segments, `ciphertext_length = 0`, and `VXFM.sc = 0`. The segment count verification check **MUST** pass for `sc = 0` with **zero** segments received. The **BLAKE3** integrity hash in `VXFM` **MUST** be computed over empty input.

### 6.2 Per-segment nonce derivation

Segment nonces are derived deterministically from the file generation and segment index:

```rs
nonce = HKDF-SHA-512(
    ikm  = fileContentKey,
    salt = 32 zero bytes,
    info = "vexahub:v1:segmentNonce:" ‖ uint32_be(generation) ‖ uint64_be(segment_index),
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

> **Warning to implementors:** `fileMetadataKey` does **NOT** include `generation` in its derivation path. It is stable across all generations of a file. This is by design.
>
> Metadata key separation from content keys is the goal. However, this means every `VXFM` encryption **MUST** use a fresh random nonce. See [§5.4](#54-vxfm---file-metadata) for the explicit nonce requirement.

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
    info = "vexahub:v1:contentIdKey:" || collection_uuid,
    L    = 32
)

content_id = BLAKE3_keyed(contentIdKey, plaintext)   // 32 bytes
```

Properties:

- **Deterministic per user per collection**: the same plaintext produces the same `content_id` for the same user in the same collection, enabling reliable resume detection.
- **Distinct across users**: two different users with the same plaintext produce different `content_id` values, because their `masterKey` differs.
- **Distinct across collections**: the same plaintext in different collections produces different `content_id` values, because the `collection_uuid` in the HKDF info differs. The server cannot correlate content across a user's collections.
- **Not invertible**: the server cannot recover plaintext from `content_id`.
- **Not testable against known content**: the server cannot pre-compute hashes of known files, because the keyed hash requires `contentIdKey` which the server never sees.
- **No recomputation on key rotation**: `contentIdKey` is derived from `masterKey` (which never rotates), not from `collectionKey`. Resume and duplicate detection remain fully functional immediately after a share revocation and `collectionKey` rotation.

> **Accepted trade-off:** After a `collectionKey` rotation on share revocation, the `content_id` values within the collection remain unchanged. The server can observe that the same set of files exists before and after rotation.
>
> This is a **minor** metadata leak. The server already knows the collection exists, how many files it contains, and their ciphertext sizes. Knowing that the file set didn't change after a key rotation leaks negligible additional information.
>
> File content, names, and all other metadata remain fully protected by the rotated keys.
>
> Deriving `contentIdKey` from `collectionKey` would eliminate this leak but would require downloading and re-hashing every file's full plaintext on every revocation. Which is impractical for large collections and a severe UX penalty that outweighs the marginal privacy gain.

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
SEGMENT_HEADER_SIZE                   = 58 bytes (VXFC header, includes file_id)
SEGMENT_TAG_SIZE                      = 16 bytes (Poly1305)
SEGMENT_CIPHERTEXT_OVERHEAD           = SEGMENT_HEADER_SIZE + SEGMENT_TAG_SIZE = 74 bytes
SEGMENT_CIPHERTEXT_SIZE_FULL          = SEGMENT_PLAINTEXT_SIZE + SEGMENT_CIPHERTEXT_OVERHEAD = 1,048,650 bytes

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
    crypto_version SMALLINT NOT NULL DEFAULT 1,
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

> The `crypto_version` on a tus upload **MUST** match the `crypto_version` that will be committed to the `files` table.
>
> If a client upgrades crypto version mid-upload (e.g. during a protocol migration), the in-progress upload **MUST** be discarded and restarted under the new version.

### 6.5.11 Abandoned upload garbage collection

A scheduled job MUST periodically (recommended: hourly) remove rows from `tus_uploads` where `completed_at IS NULL AND expires_at < now()`, and MUST delete the corresponding object at `storage_path` from the object storage backend. The default TTL for an incomplete upload is **7 days** from `created_at`, refreshed to 7 days on each successful `PATCH`. Long-running uploads of very large files therefore stay alive as long as the user is making progress, but truly abandoned uploads are reaped within a week.

### 6.5.12 Threat model additions

| Attacker capability                                                          | VexaHub response                                                                                                                                               |
|------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Server tries to test database for known plaintext via hash                   | Blocked: `content_id` is keyed by per-user `contentIdKey`, never seen by server                                                                                |
| Server tries cross-user deduplication to infer relationships                 | Blocked: distinct users produce distinct `content_id` for identical plaintext                                                                                  |
| Server truncates an upload to inject a shorter file                          | Detected at download via BLAKE3 plaintext hash in `VXFM` ([§5.4](#54-vxfm---file-metadata), [§6.5.9](#659-final-integrity-verification))                       |
| Server reorders segments within a generation                                 | Blocked by per-segment AAD binding `(version, alg, file_id, generation, segment_index)`                                                                        |
| Server swaps VXFM metadata between files                                     | Blocked by AAD binding `(version, alg, file_id, generation)` on VXFM                                                                                           |
| Server swaps key-wrapping blobs between users                                | Blocked by user_id AAD binding on VXWM, VXRM, VXPS, VXSK                                                                                                       |
| Server truncates download (drops trailing segments)                          | Detected by segment count `sc` in VXFM before full download completes                                                                                          |
| Server rolls back to an older generation                                     | Blocked by monotonic `generation` enforcement ([§6.3](#63-file-generation-counter-mutability)) and client-side verification                                    |
| Server tries to correlate files across collections for the same user         | Blocked: `contentIdKey` is per-collection, same plaintext produces different `content_id` in different collections                                             |
| Server observes unchanged `content_id` values after `collectionKey` rotation | Accepted: minor metadata leak (file set unchanged), negligible over what server already knows (file count, ciphertext sizes). Content remains fully protected. |

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

    > If the `continuationToken` expires (60-second TTL) before the client sends `finishLogin`, the server **MUST** return HTTP 410 Gone. The client **MUST** restart the registration flow from **step 1**.
    >
    > The **60-second** window accommodates **Argon2id** computation on low-end WASM targets (~3 seconds worst case) plus network latency. If telemetry shows the window is too tight, it can be increased server-side **without** a protocol version bump.

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

    > If the `continuationToken` expires (60-second TTL) before the client sends `finishLogin`, the server **MUST** return HTTP 410 Gone. The client **MUST** restart the login flow from **step 1**.
    >
    > The **60-second** window accommodates **Argon2id** computation on low-end WASM targets (~3 seconds worst case) plus network latency. If telemetry shows the window is too tight, it can be increased server-side **without** a protocol version bump.

7. Server ➜ Client: `{ loginResponse, continuationToken, vxwm, vxsk }`.
8. Client: `opaque.client.finishLogin(...)` ➜ `{ finishLoginRequest, sessionKey, exportKey, serverStaticPublicKey }`.
9. Client: verifies pinned key.
10. Client: derives `masterKeyWrapper`, parses `VXWM`, decrypts `masterKey`.

    > 10a. On every file access, the client **MUST** verify that the `generation` field inside the decrypted `VXFM` blob matches the `generation` stored in the server's file metadata response. A **mismatch** indicates the server is serving a stale metadata blob from a previous generation and the client **MUST** reject the file.

11. Client: parses `VXSK`, decrypts sharing private keys with `masterKey`.
12. Client ➜ Server: `POST /auth/login/finish { continuationToken, finishLoginRequest }`.
13. Server: retrieves and immediately deletes `serverLoginState` from Valkey.
14. Server: `opaque.server.finishLogin(...)` ➜ `{ sessionKey }`.
15. Server: derives an HTTP session token from `sessionKey`, stores a hashed session row in Postgres, returns `HttpOnly; Secure; SameSite=Strict` cookie.
16. Client: zeroizes `password`, `exportKey`, `masterKeyWrapper`. `masterKey` and sharing private keys are loaded into the Crypto Web Worker.

> **Password change note:** `VXSK` is wrapped under `masterKey`, not `masterKeyWrapper`. Since password changes re-wrap `masterKey` under a new `masterKeyWrapper` but do not change `masterKey` itself, the existing `VXSK` blob remains valid and does not need re-wrapping.
>
> The server **MUST** continue to return the existing `VXSK` after a password change.

## 9. Session Management

### 9.1 Active sessions (default)

- `masterKey` and sharing private keys live exclusively inside a dedicated Crypto Web Worker, never in the main thread's JavaScript heap.
- Main <--> Worker communication uses a strict request/response protocol (`encryptFileSegment`, `decryptFileSegment`, `deriveCollectionKey`, `wrapForSharing`, `unwrapFromSharing`). The Worker never returns raw key material, only operation results.
- Inactivity timeout: 30 minutes. On timeout, the Worker is terminated and all in-memory key material is zeroized; the user must re-authenticate.
- Session cookie: 24-hour absolute lifetime, renewed on activity, `HttpOnly; Secure; SameSite=Strict`.
- Closing the tab destroys the Worker and the `masterKey`. Without a persistent session, the next visit requires a fresh login.
- Worker script is served same-origin under strict CSP ([§16](#16-web-security-headers)), no inline, no eval beyond `wasm-unsafe-eval`.

> **Activity definition:** The inactivity timer is reset by any of the following events:
>
> - Any user interaction that triggers an authenticated **API** request (file list, collection browse, metadata fetch, upload, download).
> - Any message sent to the Crypto Worker (encrypt, decrypt, wrap, unwrap).
>
> The main thread is responsible for signalling the Worker on **API** activity. The Worker **MUST** expose a `resetInactivityTimer()` message that the main thread calls on every authenticated API response. The Worker's timer runs independently and is not accessible to the main thread beyond this signal.

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

#### 9.2.1 Zero-knowledge tiers

| Mode                                 | Zero-knowledge                     | Server holds         |
|--------------------------------------|------------------------------------|----------------------|
| Web (no `Remember me`)               | ✅ True ZK                         | Nothing session-side |
| Web (`Remember me`)                  | ⚠️ Trade-off (opt-in, documented)  | `localKey`           |
| Web (`Remember me` + `WebAuthn` PRF) | ✅ True ZK                         | Nothing              |
| Desktop / Mobile                     | ✅ True ZK                         | Nothing              |

#### 9.2.2 WebAuthn PRF (future, non-trivial)

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

#### 9.2.3 Mandatory safeguards

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

### 9.4 Client-side Key Caching in the Crypto Worker

The Crypto Worker holds `masterKey` and sharing private keys for the duration of a session. `collectionKey` and `fileKey` values are unwrapped on demand and cached inside the Worker with a bounded eviction policy. This section defines that policy.

#### 9.4.1 Cache structure

The Worker maintains two separate LRU caches:

- **Collection key cache**: keyed by `collection_id`, holds unwrapped `collectionKey` values.
- **File key cache**: keyed by `file_id`, holds unwrapped `fileKey` values.

Both caches are held exclusively in Worker memory. They are never serialized, never written to IndexedDB, and never passed to the main thread.

Maximum cache sizes are implementation-defined per platform. Implementations MUST define a fixed upper bound for each cache to prevent unbounded accumulation of key material in memory. The chosen bounds SHOULD reflect realistic concurrent working sets for the target platform (desktop, mobile, web) and MUST be documented in the platform-specific implementation notes.

#### 9.4.2 Key fetch and unwrap on demand

When the Worker receives an operation request for a `file_id` or `collection_id` it does not currently hold in cache, it proceeds as follows.

The main thread maintains a network-level cache of encrypted blobs (`VXCK`, `VXFK`) received from the server. This cache holds ciphertext only. The main thread never sees plaintext key material. When the Worker needs a blob it signals the main thread, which either returns the blob from its network cache or fetches it from the server.

**For a `collectionKey`:**

1. Worker signals main thread to provide the `VXCK` blob for `collection_id`.
2. Main thread returns the blob (from network cache or a fresh server fetch).
3. Worker derives `collectionKeyWrapKey` from `masterKey` and `collection_id`.
4. Worker unwraps `collectionKey` and stores it in the collection key LRU cache.
5. `collectionKeyWrapKey` is zeroized immediately after unwrap.

**For a `fileKey`:**

1. Worker first ensures the parent `collectionKey` is in cache, fetching it per the above if needed.
2. Worker signals main thread to provide the `VXFK` blob for `file_id`.
3. Main thread returns the blob (from network cache or a fresh server fetch).
4. Worker derives `fileKeyWrapKey` from `collectionKey` and `file_id`.
5. Worker unwraps `fileKey` and stores it in the file key LRU cache.
6. `fileKeyWrapKey` is zeroized immediately after unwrap.

The main thread is never told which key is being derived or for what operation. It only sees blob fetch requests and blob responses.

#### 9.4.3 Cache eviction

Both caches use LRU eviction. When a cache reaches its maximum size and a new entry must be added, the least recently used entry is evicted and its key material is explicitly zeroized before the memory is released.

Keys are also evicted immediately in the following situations:

- Session timeout (30-minute inactivity): entire cache is cleared and Worker is terminated.
- Logout: entire cache is cleared before Worker termination.
- Password change: entire cache is cleared. The user re-authenticates and keys are re-fetched on demand in the new session.
- Share revocation received from server on sync: the affected `collection_id` or `file_id` is evicted immediately from whichever cache holds it.
- `reset_generation` mismatch detected on login: entire cache is cleared before the Worker processes any further requests.

#### 9.4.4 Concurrency within the Worker

The Worker processes one unwrap operation at a time per key. Concurrent operation requests for the same `(collection_id, file_id)` pair are queued and resolved against the same cached value once it is available. The Worker never initiates two concurrent unwrap operations for the same key.

### 9.5 Key Fetch Ordering on Login and First File Access

Login (§8.2) unwraps `masterKey` and sharing private keys eagerly. All other key material is fetched lazily on first access.

#### 9.5.1 Lazy fetch model

No `collectionKey` or `fileKey` is unwrapped at login time. The Worker holds only `masterKey` and sharing keys after login completes. This keeps login fast regardless of how many collections and files the user has, and avoids loading key material for collections the user may never visit in that session.

#### 9.5.2 First file access flow

When the user opens a file for the first time in a session:

1. Main thread sends a decrypt request to the Worker including `file_id` and `collection_id`.
2. Worker checks file key cache. On miss, Worker checks collection key cache.
3. On collection key cache miss, Worker signals main thread to fetch `VXCK` blob from server.
4. Main thread fetches `VXCK` and passes it to Worker. Main thread never sees the plaintext key.
5. Worker unwraps `collectionKey` and caches it.
6. Worker signals main thread to fetch `VXFK` blob from server.
7. Main thread fetches `VXFK` and passes it to Worker.
8. Worker unwraps `fileKey` and caches it.
9. Worker proceeds with the decrypt operation and returns only the operation result to the main thread.

On subsequent access to the same file within the session, steps 2 through 8 are skipped entirely if both keys are still in cache.

#### 9.5.3 Collection prefetch hint

The main thread MAY send a prefetch hint to the Worker when the user navigates into a collection, to warm the collection key cache before any file is opened. A prefetch hint causes the Worker to unwrap and cache the `collectionKey` for that collection only. It does NOT trigger unwrapping of any `fileKey` values within the collection, since the user has not yet accessed any specific file.

Prefetch hints are a performance optimisation only. The Worker treats a prefetch hint identically to a collection key cache miss triggered by a real operation. Prefetch hints MUST NOT be sent for collections the user has not explicitly navigated to.

### 9.6 Offline and Desktop Behavior

#### 9.6.1 Web clients

Web clients have no persistent local storage of plaintext key material or plaintext file content. When a web client goes offline mid-session:

- The Worker continues to hold `masterKey`, sharing keys, and any cached `collectionKey` and `fileKey` values in memory.
- Operations on already-cached keys continue to function for content whose ciphertext has already been downloaded to the browser.
- Operations requiring a server fetch will fail with a network error. The client MUST surface this to the user as an offline error, not a decryption failure.
- The inactivity timeout continues to run. If the user is offline for 30 minutes, the Worker is terminated and key material is zeroized on timeout as normal. Re-authentication requires network access.

Web clients MUST NOT attempt to cache plaintext file content or unwrapped key material in IndexedDB, localStorage, or any other browser storage. The only persistent browser storage used by VexaHub is the `VXPS` blob (§5.6) for persistent sessions and the session cookie.

#### 9.6.2 Desktop clients (Tauri)

Desktop clients use the OS keychain to store `masterKey` between sessions, achieving true zero-knowledge persistent sessions without server involvement. The keychain entry is created at first login and updated on password change.

**Keychain entry:**

```rs
service:  "vexahub"
account:  user_id
secret:   masterKey (32 raw bytes)
```

The keychain entry is protected by the OS and accessible only to the VexaHub process. It is never written to disk by VexaHub directly.

**Session resume on desktop:**

1. App launches and reads `masterKey` from OS keychain.
2. App sends a request to the server using the stored session cookie to fetch `vxsk`.
3. If the server returns 401 (session expired or revoked), the app MUST discard the cached cookie, prompt the user to re-enter their password, and run the full OPAQUE login flow (§8.2). The keychain entry for `masterKey` remains valid and does not need to be replaced unless the password change flow is triggered.
4. On successful fetch, app decrypts `VXSK` using `masterKey` to recover sharing private keys.
5. Worker is initialised with `masterKey` and sharing keys. No password entry required.

If the keychain entry is missing (first install, or after the user manually cleared it), the user is prompted to authenticate with their password regardless of cookie state.

**Offline operation on desktop:**

Desktop clients MAY maintain an encrypted local cache of file content and metadata for offline access. If a local cache is implemented:

- File content MUST be stored as the original `VXFC` ciphertext segments, not as plaintext. Decryption happens in the Worker at access time.
- File metadata MUST be stored as the original `VXFM` blob, not as plaintext CBOR.
- The local cache index (which files are cached, their sizes and generations) MAY be stored in plaintext, as this information is already known to the server.
- On reconnection, the client MUST fetch current `generation` values for all cached files and evict any whose cached generation is behind the server's current generation. Stale ciphertext MUST NOT be served to the user.
- The local cache MUST be fully deleted on logout and on `reset_generation` mismatch.

> **Argon2id parallelism on Tauri:**
>
> **Tauri**'s webview context does not use browser-origin isolation headers. `crossOriginIsolated` as checked via `window.crossOriginIsolated` is not applicable in the Tauri renderer.
>
> **Tauri** achieves **Argon2id** parallelism via native threads in the **Rust** backend, not via `SharedArrayBuffer`. The WASM **Argon2id** path (used in the browser) is **NOT** used on **Tauri**. The native Rust **Argon2id** implementation runs with `p = 4` as specified in [§2](#2-primitives) without any dependency on cross-origin isolation.
>
> The `crossOriginIsolated` bootstrap check ([§16.2](#162-other-headers)) **MUST** be skipped on **Tauri** targets. **Tauri** builds **MUST** instead verify at startup that the native **Argon2id** implementation is active and that the parallelism parameter matches the spec value.

### 9.7 Multi-tab Behavior on Web

Multiple browser tabs for the same origin do not share Web Workers. Each tab spawns its own Crypto Worker, holds its own copy of `masterKey` in Worker memory, and manages its own key caches independently.

#### 9.7.1 Implications

- `masterKey` may exist in memory in multiple Workers simultaneously when the user has multiple tabs open. This is an accepted consequence of the web security model. The number of in-memory copies is bounded by the number of open tabs.
- Each Worker's inactivity timeout runs independently. A tab left idle for 30 minutes will terminate its Worker and zeroize its key material, even if other tabs remain active.
- There is no cross-tab communication of key material. Tabs MUST NOT use `BroadcastChannel`, `SharedArrayBuffer`, or any other cross-tab mechanism to pass key material between Workers.

#### 9.7.2 Session invalidation across tabs

The session cookie is shared across all tabs automatically by the browser. When a user explicitly logs out in one tab, the client MUST:

1. Call the server logout endpoint to invalidate the session row in Postgres.
2. Terminate its own Worker and zeroize its key material.
3. Broadcast a logout signal to other tabs via `BroadcastChannel` (channel name: `"vexahub:session"`).

Other tabs listening on `"vexahub:session"` MUST terminate their Workers and zeroize their key material immediately on receiving the logout signal, then redirect to the login screen.

Tabs that miss the broadcast (for example, a tab opened in a different browser window without shared `BroadcastChannel` access) will encounter a 401 on their next API request due to the invalidated session cookie. On receiving a 401 response to any authenticated API request, a tab MUST terminate its Worker, zeroize key material, and redirect to the login screen.

A 401 received during normal operation (not following a logout broadcast) should be treated the same way: the session has expired or been revoked server-side, and the client must re-authenticate.

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

### 10.2 File and collection table

```sql
CREATE TABLE collections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    parent_id       UUID REFERENCES collections(id) ON DELETE CASCADE,
    vxcm            BYTEA NOT NULL,             -- encrypted collection metadata (VXCM blob)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON collections (user_id);
CREATE INDEX ON collections (parent_id);

CREATE TABLE files (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id               UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    collection_id         UUID NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    generation            INTEGER NOT NULL DEFAULT 0,
    content_id            BYTEA,                    -- 32 bytes, BLAKE3_keyed
    upload_length         BIGINT,                   -- ciphertext bytes, NULL until first upload completes
    crypto_version        SMALLINT NOT NULL DEFAULT 1,
    pending_key_rotation  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON files (user_id, collection_id);
CREATE INDEX ON files (collection_id) WHERE pending_key_rotation = TRUE;
```

### 10.3 File and collection keys table

```sql
CREATE TABLE collection_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id   UUID NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vxck            BYTEA NOT NULL,
    key_generation  INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at      TIMESTAMPTZ
);

CREATE UNIQUE INDEX collection_keys_active
    ON collection_keys (collection_id, user_id, key_generation);

CREATE TABLE file_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id         UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    collection_id   UUID NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    vxfk            BYTEA NOT NULL,
    key_generation  INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at      TIMESTAMPTZ
);

CREATE UNIQUE INDEX file_keys_active
    ON file_keys (file_id, key_generation);
```

### 10.4 What the server knows vs does not know

**Knows:** email, `registrationRecord` (opaque envelope), wrapped key blobs, public sharing keys, file existence and ciphertext size, file/collection UUIDs, hierarchy, timestamps, locale, `localKey` for any active persistent sessions only.

**Does not know:** password, `masterKey`, `exportKey`, `masterKeyWrapper`, `collectionKey`, `fileKey`, file content, file names, mime types, any plaintext metadata.

## 11. Sharing (X-Wing Hybrid KEM + ML-DSA-65 Signatures)

> Sharing wraps a `collectionKey` or `fileKey` such that only the recipient can unwrap it, and authenticates the invitation so the recipient can verify it came from the claimed sender. Not from the server or an attacker.

Send flow:

1. Sender fetches recipient's **X-Wing** encapsulation key and **ML-DSA-65** verification key from the server.
2. Sender encapsulates: `(ctXwing, sharedSecret) = X-Wing.Encaps(recipientPubXwing)`.
3. Sender derives:

    ```rs
        shareWrapKey = HKDF-SHA-512(
        ikm  = sharedSecret,
        salt = random 32 bytes (stored in share record),
        info = "vexahub:v1:shareWrap:" || share_uuid,
        L    = 32
    ).
    ```

4. Sender wraps the target key (collection or file) with `shareWrapKey` using **XChaCha20-Poly1305** ➜ `VXSH` blob.
5. Sender builds the **signed payload**: canonical CBOR encoding of `{ share_uuid, sender_id, recipient_id, ctXwing, vxsh, timestamp }`.
6. Sender signs the payload with their **ML-DSA-65** signing key using context string `"vexahub:v1:share"` ➜ `signature`. Signatures are **deterministic** (no per-signature randomness).
7. Sender uploads `{ signedPayload, signature }` to the server.

Receive flow:

1. Recipient fetches the share record.
2. Recipient fetches sender's **ML-DSA-65** verification key **independently** from the server (Not from the share record! Prevents server substitution of both payload and key).
3. Recipient verifies `signature` against sender's verification key with context `"vexahub:v1:share"`. **Reject on failure. Do not proceed to decryption.**
4. Recipient decapsulates: `sharedSecret = X-Wing.Decaps(privXwing, ctXwing)`.
5. Recipient derives `shareWrapKey` and unwraps `VXSH`.
6. Recipient stores the shared key in their own scope.

> Security degrades only if **both** X25519 and ML-KEM-768 are broken (X-Wing hybrid guarantee). Share authenticity degrades only if ML-DSA-65 is broken. The signature covers the entire invitation payload including `recipient_id` and `ctXwing`, preventing the server from redirecting shares to other users or swapping the encapsulated key material.
>
> **Critical design note:** The ML-DSA-65 signature sits **outside** the encrypted `VXSH` blob, at the transport layer. The recipient MUST verify the signature before trusting or decrypting the ciphertext. If the signature were inside the encrypted envelope, a malicious server could swap the entire `{ctXwing, vxsh}` package and the forgery would only be discovered after decryption (And that's too late).
>
> When sharing a **collection**, the `VXSH` blob wraps the `collectionKey`. The recipient stores their own `VXCK` blob wrapped by their `masterKey`. When sharing a **file**, the `VXSH` blob wraps the `fileKey`. The recipient stores their own `VXFK` blob wrapped by a `collectionKey` in their scope.
>
> Parsers **MUST** reject non-canonical **CBOR** input. Any blob or payload that does not conform to [RFC 8949 §4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1) deterministic encoding **MUST** cause a hard error, **never** silent acceptance or re-canonicalization.

The signature is not part of the `VXSH` blob. It is stored alongside it in the share database record:

```sql
CREATE TABLE shares (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id       UUID NOT NULL REFERENCES users(id),
    recipient_id    UUID NOT NULL REFERENCES users(id),
    ct_xwing        BYTEA NOT NULL,         -- X-Wing ciphertext (1120 bytes)
    vxsh            BYTEA NOT NULL,         -- encrypted wrapped key blob
    hkdf_salt       BYTEA NOT NULL,         -- 32 bytes, random, for shareWrapKey derivation
    sig_algorithm   SMALLINT NOT NULL,      -- 0x10 = ML-DSA-65
    signature       BYTEA NOT NULL,         -- ML-DSA-65 signature over canonical payload
    signed_payload  BYTEA NOT NULL,         -- canonical CBOR of the signed fields
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### 11.1 Share Revocation

Revocation removes a recipient's access and rotates keys so new content is cryptographically inaccessible to the revoked user.

**Collection share revocation:**

1. Sender calls `DELETE /api/v1/shares/{share_id}`.
2. Server sets `revoked_at = now()`. Revoked recipient gets 403 immediately.
3. Sender generates a new `collectionKey` via CSPRNG, increments `key_generation`.
4. Sender re-wraps the new `collectionKey` with `collectionKeyWrapKey` ➜ new `VXCK` blob.
5. Sender generates new `fileKey` via CSPRNG for each file in the collection, wraps each with new `fileKeyWrapKey` derived from new `collectionKey` ➜ new `VXFK` blobs.
6. Sender re-encrypts all `VXFM` metadata blobs under new `fileMetadataKey` values. Metadata is small, this is immediate.
7. Sender re-shares the new `collectionKey` with all remaining recipients via fresh X-Wing + ML-DSA-65 invitations.
8. File content re-encryption is **lazy**: files are marked `pending_key_rotation`. Content is re-encrypted when next accessed or modified, or by a background client-side task during idle time.

**File share revocation:**

1. Sender calls `DELETE /api/v1/shares/{share_id}`.
2. Server sets `revoked_at = now()`. Revoked recipient gets 403 immediately.
3. Sender generates a new `fileKey` via CSPRNG, increments `key_generation`.
4. Sender re-wraps the new `fileKey` with `fileKeyWrapKey` ➜ new `VXFK` blob.
5. Sender re-encrypts the `VXFM` metadata blob under new `fileMetadataKey`. Immediate.
6. Sender re-shares with remaining recipients via fresh invitations.
7. File content re-encryption is **lazy**, same as above.

**Guarantees and limitations:**

| Property                                                          | Status                                                            |
|-------------------------------------------------------------------|-------------------------------------------------------------------|
| Revoked user cannot access content via the API                    | ✅ Immediate, server-enforced                                     |
| New content after rotation uses fresh keys                        | ✅ Both collection and file level                                 |
| Metadata re-encrypted immediately                                 | ✅ Small blobs, synchronous                                       |
| File content re-encrypted lazily                                  | ⚠️ Old ciphertext remains until rotated, but unreachable via API  |
| File-level revocation without affecting other files in collection | ✅ Independent `fileKey` rotation                                 |
| Revoked user cannot decrypt already-downloaded content            | ❌ Inherent E2EE limitation                                       |

**Mandatory safeguards:**

- The server MUST reject any data request from a recipient whose share has `revoked_at IS NOT NULL`.
- The client MUST delete cached keys for revoked shares on next sync.
- The sender's UI MUST indicate that revocation cannot undo prior access and that key rotation is in progress.

**Schema:**

```sql
ALTER TABLE shares ADD COLUMN revoked_at TIMESTAMPTZ;
CREATE INDEX ON shares (recipient_id) WHERE revoked_at IS NULL;

ALTER TABLE files ADD COLUMN pending_key_rotation BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX ON files (collection_id) WHERE pending_key_rotation = TRUE;
```

### 11.2 Share Timestamp Validation

The `timestamp` field in the signed share payload is a Unix epoch in seconds (UTC), set by the sender at signing time.

**Server enforcement:**

- The server MUST reject share uploads where `timestamp` is more than **5 minutes** in the past or future relative to server time. This prevents replay of old signed payloads and accounts for reasonable clock skew.
- The server records `created_at` independently. The signed `timestamp` and server `created_at` are both available to the recipient.

**Recipient enforcement:**

- The recipient MUST reject share records where the signed `timestamp` differs from the server's `created_at` by more than **5 minutes**. This detects a malicious server holding a valid signed payload and replaying it later.

**Clock skew:**

- The 5-minute window accommodates typical NTP drift across consumer devices. Tighter windows risk false rejections on mobile clients with poor time sync.
- The window applies symmetrically: `|timestamp - server_time| <= 300` seconds at upload, `|timestamp - created_at| <= 300` seconds at verification.

### 11.3 Sharing Keypair Rotation

An authenticated user **MAY** rotate their sharing keypairs at **any** time, for example if they suspect their signing key has been **observed**.

1. Client generates new **X-Wing** keypair and **ML-DSA-65** keypair.
2. Client wraps new private keys under `masterKey` → new `VXSK` blob.
3. Client ➜ Server: `POST /auth/sharing-keys/rotate { vxsk, sharingPublicXwing, sharingPublicMldsa }`.
4. Server atomically replaces `vxsk`, `sharing_public_xwing`, `sharing_public_mldsa`, and sets `revoked_at = now()` on **all outgoing** pending shares for this user.
5. Client **re-shares** any collections or files with affected recipients using the new signing key.

> Already-accepted incoming shares stored by recipients are unaffected. The recipient unwrapped and stored the key locally at accept time.
>
> Password change does NOT automatically trigger sharing keypair rotation.
>
> Rotation is an explicit user action available from security settings.

### 11.4 File Move Between Collections

Moving a file between collections requires re-wrapping the `fileKey` under the destination collection's key hierarchy. A simple `collection_id` update on the file row is **not sufficient**.

The `VXFK` blob remains wrapped under the source `collectionKey` and would be inaccessible to recipients of the destination collection and still accessible to revoked recipients of the source collection.

**Move flow:**

1. Client fetches the source `VXFK` blob, unwraps `fileKey` using `fileKeyWrapKey` derived from source `collectionKey`.
2. Client derives `fileKeyWrapKey` from the destination `collectionKey`:

   ```rust
   fileKeyWrapKey = HKDF-SHA-512(
       ikm  = destinationCollectionKey,
       salt = 32 zero bytes,
       info = "vexahub:v1:fileKeyWrap:" || file_uuid,
       L    = 32
   )
   ```

3. Client wraps the same `fileKey` under the new `fileKeyWrapKey` ➜ new `VXFK` blob.
4. Client → Server: `POST /api/v1/files/{file_id}/move`:

   ```json
   {
     "destination_collection_id": "...",
     "vxfk": "<new VXFK blob>"
   }
   ```

5. Server atomically:
   - Updates `files.collection_id` to `destination_collection_id`.
   - Replaces the `file_keys` row with the new `VXFK` blob, incrementing `key_generation`.
   - Sets `files.updated_at = now()`.

**The server MUST verify before committing:**

- The authenticated user owns both the source and destination collections.
- The destination collection exists and is not the same as the source collection.
- The new `VXFK` blob is well-formed (correct magic, format version, algorithm ID).

**Sharing implications:**

Moving a file does not automatically re-share it with recipients of the destination collection. The file exists in the destination collection but only the owner can decrypt it until explicitly shared. This is the correct behavior. It is automatically inheriting destination collection shares would be a surprise to both the owner and existing recipients.

If the file was previously shared with recipients of the source collection, those shares remain in the `shares` table but the `fileKey` they unwrapped at accept time is still valid.

The `fileKey` itself did not change, only its wrapping. Recipients who already accepted the share retain access to content they already have. This is consistent with the E2EE limitation acknowledged in [§11.1](#111-share-revocation).

If the owner wants to revoke source collection recipients' access after a move, they must explicitly rotate the `fileKey` per [§11.1](#111-share-revocation).

**Guarantees:**

| Property                                                                 | Status                                                                     |
|--------------------------------------------------------------------------|----------------------------------------------------------------------------|
| Destination collection recipients can access file after move             | ❌ Not automatic (**explicit** share required)                             |
| Source collection recipients lose API access after move                  | ✅ Server enforces `collection_id` scoping on all file requests            |
| Source collection recipients who already accepted share retain key       | ⚠️ Inherent E2EE limitation, consistent with [§11.1](#111-share-revocation)|
| `VXFK` is correctly wrapped under destination `collectionKey`            | ✅ Client re-wraps before move commit                                      |
| Move is atomic. No window where file is accessible under wrong wrapping  | ✅ Server commits `collection_id` and new `VXFK` in a single transaction   |

**Schema:** No schema changes required. The existing `file_keys` table with `key_generation` handles the new `VXFK` blob naturally.

### 11.5 Concurrent Modification from Two Devices

[§6.5.8](#658-generation-transitions-during-in-progress-uploads) covers the case where a user modifies a file while an upload is in progress on the **same device**. This section covers **concurrent** modification from **two separate devices**.

The server's monotonic `generation` enforcement ([§6.3](#63-file-generation-counter-mutability)) already **prevents** nonce reuse: if **two** devices both start from `generation = N` and **both** attempt to upload `generation = N+1`, whichever arrives second is **rejected** with `HTTP 409 Conflict`. No ciphertext **corruption** or nonce **reuse** is possible. The gap is purely what the rejected device does next.

#### 11.5.1 Detection

When a **client** receives `HTTP 409` on a generation upload, it **MUST** treat this as a concurrent modification signal and enter the conflict resolution flow below.

The client **MUST NOT** silently retry with an incremented generation. Because, doing so would **overwrite** the winning device's changes without the user's knowledge.

#### 11.5.2 Resolution Flow

The client has two paths depending on whether the local version is newer than the server's committed version, which it cannot determine cryptographically (both are valid generations from the server's perspective). The client MUST therefore always surface a conflict to the user and let them decide.

**Conflict resolution procedure:**

1. Client receives HTTP 409 on upload of `generation = N+1`.
2. Client fetches current file metadata from server: `GET /api/v1/files/{file_id}` → `{ generation: N+1, ... }` (the winning device's committed generation).
3. Client fetches and decrypts the winning `VXFM` to get the committed filename.
4. Client presents the user with a conflict dialog:

   ```sh
   This file was modified on another device.

   Server version:  "report.pdf"  - saved just now
   Your version:    "report.pdf"  - unsaved local changes

   [ Keep server version ]   [ Keep my version ]   [ Keep both ]
   ```

5. User chooses one of three outcomes:

   **Keep server version:**
   - Client discards local changes.
   - Client sends `DELETE {tus_url}` to discard the in-progress upload.
   - No crypto operations required.

   **Keep my version (overwrite):**
   - Client sends `DELETE {tus_url}` to discard the failed upload.
   - Client fetches current `generation` from server (now `N+1`).
   - Client increments to `N+2`, re-encrypts local content under new generation nonce space.
   - Client creates new tus upload and proceeds normally.
   - The winning device's changes are overwritten. The user explicitly chose this.

   **Keep both (conflicted copy):**
   - Client sends `DELETE {tus_url}` to discard the failed upload.
   - Client creates a **new file** from the local version:
     - Generates new `file_id` via server: `POST /api/v1/files` in the same collection.
     - Server generates new `file_id`, client generates new `fileKey` via CSPRNG.
     - Client wraps new `fileKey` → new `VXFK` blob under destination `collectionKey`.
     - Client constructs `VXFM` for the conflicted copy with a modified filename:

       ```sh
       "{original_name} (conflicted copy - {device_label} - {date})"
       ```

       The filename is encrypted inside `VXFM` so the server never sees it.
     - Client uploads the conflicted copy as `generation = 0` under the new `file_id`.
   - The user now has two files: the server's committed version and their local version as a new file. Both are fully accessible and independently modifiable going forward.

#### 11.5.3 Crypto properties of the conflicted copy

A conflicted copy is a first-class new file. It has:

- Its own `file_id` (new UUID).
- Its own `fileKey` (CSPRNG, independent of the original file's key).
- Its own `VXFK` blob wrapped under the collection's `collectionKey`.
- `generation = 0`.
- Its own `content_id` computed with the collection-scoped `contentIdKey`.

No key material is shared between the original file and the conflicted copy. They are cryptographically independent from the moment of creation.

#### 11.5.4 Server-side enforcement

The server **MUST**:

- Return `HTTP 409 Conflict` when a client uploads a generation ≤ the currently stored generation, with a response body identifying the conflict:

  ```json
  {
    "error": "generation_conflict",
    "current_generation": 4
  }
  ```

- **Never** silently accept an **out-of-order** generation. The monotonic invariant from [§6.3](#63-file-generation-counter-mutability) is absolute.
- Allow the client to create a new file in the same collection without any special conflict flag. A conflicted copy is just a new file from the server's perspective.

#### 11.5.5 Guarantees

| Property                                               | Status                                                        |
|--------------------------------------------------------|---------------------------------------------------------------|
| Nonce reuse impossible across concurrent modifications | ✅ Monotonic generation enforcement rejects the second writer |
| Losing device is notified of conflict                  | ✅ HTTP 409 with current generation returned                  |
| User data is never silently discarded                  | ✅ Conflict dialog required before any destructive choice     |
| Conflicted copy is cryptographically independent       | ✅ New `file_id`, new `fileKey`, new `VXFK`                   |
| Server learns the conflict filename                    | ❌ Never  (filename is inside encrypted `VXFM`)               |
| Automatic last-write-wins                              | ❌ Explicitly prohibited (always surfaces to user)            |

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

2. Client sends email to `POST /auth/recovery/lookup`. The server **MUST** respond in **constant time** regardless of whether the email is registered:
    - **Registered:** returns `{ vxrm, user_uuid }`.
    - **Not registered:** returns a **deterministic fake** `{ vxrm, user_uuid }` derived from `HMAC-SHA-256(recovery_enumeration_secret, email)`. The fake `vxrm` is a valid-looking **78-byte** blob that will fail decryption **silently**. The fake `user_uuid` is similarly derived. This prevents email enumeration via timing or response shape differences.

    > The `recovery_enumeration_secret` is a separate **32-byte** random value generated at first deployment and stored alongside `serverSetup`. It **MUST NOT** be derived from `serverSetup` or any other key material.

3. Client re-derives `recoveryKey`, unwraps `masterKey`.

    > **On AEAD authentication failure:** the client **MUST** display a single generic message such as "Incorrect recovery phrase" regardless of the underlying cause.
    >
    > The client **MUST NOT** show distinct messages for "email not found" vs "wrong phrase". Both are indistinguishable at this layer and the error text must reflect that.

4. User chooses a new password.
5. Client performs a fresh OPAQUE registration.
6. Client re-wraps the same `masterKey` with the new `masterKeyWrapper`.
7. Server replaces `registration_record`, `vxwm`, and `vxsk` atomically.
8. All existing files, collections, and shares remain valid.

> The BIP39 passphrase is intentionally left empty (`""`). In cryptocurrency wallets, the passphrase serves as a "25th word" to create hidden wallets.
>
> **VexaHub** has no such requirement. The 24-word phrase already provides 256 bits of entropy, and adding a passphrase would create a second secret the user must remember alongside the phrase itself, defeating the purpose of a recovery mechanism.
>
> A forgotten passphrase would make recovery impossible even with the correct 24 words.

### 12.2 Destructive reset

> Available when **both** password and phrase are lost. Triggered by **email-confirmed** link, displays an unambiguous data-loss **warning**, then atomically:
>
> 1. Deletes **all** files, collections, collection keys, file keys, and shares for the user.
> 2. Increments `reset_generation` on the user row. This value is returned to clients on login and **MUST** be checked against the locally cached value by clients with persistent local state (desktop, mobile, web with "Remember me"). A mismatch indicates a **destructive** reset occurred on another device and the client **MUST** clear all local caches and key material. Web clients without persistent sessions are unaffected. They start **fresh** on every login.
>
> 3. Generates new `masterKey`, new sharing keypairs, new `VXWM`, `VXSK`, `VXRM` under a new **OPAQUE** registration.
>
> The user starts fresh with an **empty** account.

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

> **Cross-version blob handling:**
>
> A **v1** client **MUST NOT** re-encrypt any blob whose `format version` byte indicates a version higher than it implements. In that case, the client **MUST** refuse the operation and prompt the user to upgrade before proceeding.
>
> The unknown **CBOR** key preservation rule from [§5.4](#54-vxfm---file-metadata) applies across protocol versions: when a lower-version client re-encrypts a blob it can parse, it **MUST** preserve any unknown **CBOR** keys verbatim in the re-encrypted output.

What CANNOT be changed without re-encrypting user data: `masterKey` itself, file generation derivation paths, segment nonce derivation. `serverSetup` rotation invalidates all accounts.

> The `crypto_version` field on the `files` table tracks which protocol **version** was used to encrypt each file.
>
> This allows files encrypted under different protocol **versions** to coexist during a **migration** window. The blob `format version` byte describes the binary layout; `crypto_version` describes which key derivation scheme and parameters were used.
>
> For protocol **version 1**, these are effectively the same. They diverge only during a **migration** from **version N** to **version N+1**, where old files retain `crypto_version = N` until re-encrypted.

## 14. Test Vectors

Cross-target consistency is verified by JSON test vectors in `crates/core/tests/vectors/`, executed by:

- Native Rust via `cargo test`
- WASM via `wasm-bindgen-test`
- Node via the NAPI build
- Future Android via instrumented tests
- Future iOS via XCTest

Vector categories:

1. **HKDF** derivations (every domain-separated path in [§4](#4-hkdf-domain-separation))
2. VXWM, VXRM, VXFC, VXFM, VXSK, VXPS, VXSH, VXCM, VXCK, VXFK round-trips with fixed keys and nonces
3. Segment nonce derivation across multiple generations and indices
4. **OPAQUE** registration and login with deterministic test-only RNG seeds
5. **ML-KEM-768** encapsulation/decapsulation against **FIPS 203** known-answer tests
6. **AAD** construction vectors for VXFC (with `file_id`) and VXFM (with `file_id`)
7. **AAD** construction vectors for key-wrapping blobs (VXWM, VXRM, VXPS, VXSK, VXCK, VXFK) with user_id/collection_id/file_id binding
8. `content_id` derivation vectors with `collection_uuid` bound in the HKDF info
9. Segment count **verification** (VXFM `sc` field vs actual segment count), including the zero-byte file case (`sc = 0`, zero segments, **BLAKE3** hash over empty input).
10. **ML-DSA-65** deterministic signing vectors: fixed `(signing_seed, message, context string "vexahub:v1:share")` tuple with expected signature output. Verifies both determinism and correct context string usage. A mismatch indicates the implementation is using a randomized signing API or incorrect context binding.

A vector **mismatch** is a release **blocker**.

## 15. Key Zeroization

All key material is wrapped in `Zeroizing<T>` (Rust) and **explicitly** overwritten on JS/WASM boundaries via `Uint8Array.fill(0)` after use. GC-managed runtimes (JS, Kotlin, Swift) **cannot** guarantee complete erasure; this is an acknowledged limitation documented in the threat model.

**Mandatory** zeroization points: after every OPAQUE flow (`password`, `exportKey`, `masterKeyWrapper`), on session timeout, on logout, on password change.

> `collectionKeyWrapKey` and `fileKeyWrapKey` are ephemeral.
>
> Derived inline for a single **wrap** or **unwrap** operation and **never** stored. `Zeroizing<T>` handles erasure **automatically** when they go out of scope in **Rust**.

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

`COOP: same-origin` + `COEP: require-corp` enable cross-origin isolation, which is **REQUIRED** for `SharedArrayBuffer` and therefore for **Argon2id** `parallelism > 1` in WASM. Without these headers the **parallelism** degrades silently to 1, weakening the **KSF** below the spec parameters. Verification of cross-origin isolation status (`crossOriginIsolated === true`) **MUST** be checked at app bootstrap and surfaced as an error if false.

If `crossOriginIsolated === false`, the app **MUST** block entirely and refuse to proceed. Silent degradation to `parallelism = 1` is not acceptable; the user must not be able to authenticate under weakened parameters **without** explicit acknowledgement.

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

### 16.7 SharedArrayBuffer Usage Restrictions

`SharedArrayBuffer` is available under cross-origin isolation ([§16.2](#162-other-headers)) and is used for Argon2id parallelism during the OPAQUE flow.

`SharedArrayBuffer` **MUST NOT** be used to share key material between tabs, between Workers, or between the main thread and a Worker beyond the scope of a single Argon2id computation. After the OPAQUE flow completes, any `SharedArrayBuffer` used to hold password material, `exportKey`, or `masterKeyWrapper` MUST be zeroed and the reference released before any other code can observe it.

The Argon2id implementation **MUST** zero all intermediate state in the `SharedArrayBuffer` before signalling completion to the calling code, not after.

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
| Server swaps VXFM metadata blob between files          | Blocked by file_id AAD binding on VXFM                                                                                                                                                                                                                                                                                             |
| Server swaps key-wrapping blobs between users          | Blocked by user_id AAD binding on VXWM, VXRM, VXPS, VXSK                                                                                                                                                                                                                                                                           |
| Server serves stale VXFM from previous generation      | Detected by client verifying VXFM generation matches file row generation                                                                                                                                                                                                                                                           |
| Server truncates download (drops trailing segments)    | Detected by segment count in VXFM before full download                                                                                                                                                                                                                                                                             |
| Email enumeration via recovery endpoint                | Blocked by constant-time fake response for unknown emails                                                                                                                                                                                                                                                                          |
| Share revocation by collection/file owner              | New content protected by rotated keys; metadata re-encrypted immediately; old ciphertext unreachable via API + lazy re-encryption; already-downloaded content not recoverable (E2EE limitation)                                                                                                                                    |
| ML-DSA-65 signing key observed by attacker             | Mitigated by explicit sharing keypair rotation (§11.3), which invalidates all pending outgoing shares and replaces public keys server-side                                                                                                                                                                                         |

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
- UX flow for sharing keypair rotation notification to recipients whose pending shares were invalidated.

## 19 Deletion

### 19.1 File deletion

Files are moved to a per-user trash before permanent deletion. This gives users a grace period to recover accidentally deleted files.

**Trash flow:**

1. Client sends `DELETE /api/v1/files/{file_id}`.
2. Server sets `files.trashed_at = now()`. The file is no longer visible in normal collection listings but all ciphertext, `VXFM`, `VXFK`, and `shares` rows remain intact.
3. Server responds 204.

**Permanent deletion (hard delete):**

Triggered either by the user explicitly emptying trash, or automatically after the trash TTL (recommended: 30 days).

1. Client sends `DELETE /api/v1/files/{file_id}/permanent` (or the server's scheduled job triggers for expired trash items).
2. Server atomically:
   - Deletes the `files` row.
   - Deletes all `file_keys` rows for that `file_id`.
   - Deletes all `shares` rows where the shared resource is this `file_id`.
   - Cancels any in-progress `tus_uploads` rows for this `file_id` and schedules their storage objects for deletion.
   - Schedules deletion of all object storage blobs at the file's storage paths. Blob deletion MAY be asynchronous as long as the file row is removed atomically and the blobs become unreachable to any API request immediately.
3. Server responds 204.

**Schema addition:**

```sql
ALTER TABLE files ADD COLUMN trashed_at TIMESTAMPTZ;
CREATE INDEX ON files (user_id) WHERE trashed_at IS NOT NULL;
```

The client MUST evict the `fileKey` from its Worker cache after a successful permanent deletion response. Trashing alone does not require cache eviction.

**Server MUST NOT** serve trashed files in normal collection listing responses. A trashed file is only accessible via an explicit trash listing endpoint.

**On the question of a malicious server retaining deleted content:**

A server that retains ciphertext after deletion cannot usefully serve it without also retaining the `VXFK` blob. The server does not hold the plaintext `fileKey`. If the server re-inserted a deleted file row and served the retained `VXFK`, the client would fetch and unwrap it, making the content accessible again.

This is an inherent limitation of a system where the server stores wrapped key blobs: deletion of the key blob is what makes deletion meaningful at the crypto layer, and the server controls that blob's persistence.

The spec requires the server to delete `file_keys` rows atomically with the `files` row on permanent deletion. Trashed files retain their `VXFK` blobs by design until permanently deleted.

A compliant server **cannot** re-surface deleted content. An adversarial server that retains both blobs and ciphertext can re-surface it. This threat is in the same category as a fully compromised server and is acknowledged in [§17](#17-threat-model-summary).

### 19.2 Collection deletion

The `files` table references `collections` with `ON DELETE RESTRICT` (not CASCADE). This is intentional: cascading deletes would orphan object storage blobs since there is no file-level delete hook in a database cascade. The client is responsible for deleting all files before deleting the collection, giving the server the opportunity to schedule blob cleanup per file.

**Deletion flow:**

1. Client iterates all files in the collection and deletes each per §19.1.
2. Client iterates all child collections recursively (depth-first) and deletes each per this section.
3. Client sends `DELETE /api/v1/collections/{collection_id}`.
4. Server verifies the collection has no remaining `files` rows and no remaining child collections with this `parent_id`. If either check fails, the server MUST return HTTP 409 and the client MUST NOT retry without resolving the remaining children.
5. Server atomically:
   - Deletes the `collections` row.
   - Deletes all `collection_keys` rows for that `collection_id`.
   - Deletes all `shares` rows where the shared resource is this `collection_id`.
   - Deletes the `VXCM` blob associated with the collection.
6. Server responds 204.

The client MUST evict the `collectionKey` from its Worker cache after a successful deletion response.

**Schema note:** The foreign key on `files.collection_id` and `collections.parent_id` MUST use `ON DELETE RESTRICT`, not `ON DELETE CASCADE`:

```sql
-- Corrected from the schema in §10.2
collection_id UUID NOT NULL REFERENCES collections(id) ON DELETE RESTRICT,
parent_id     UUID REFERENCES collections(id) ON DELETE RESTRICT,
```

### 19.3 Account deletion

Account deletion permanently removes the user and all associated data.

**Deletion flow:**

1. User initiates account deletion from settings.
2. Server sends a confirmation email containing a single-use token with a 15-minute TTL.
3. User clicks the confirmation link.
4. Server atomically:
   - Deletes all files and their object storage blobs (scheduled asynchronously).
   - Deletes all `file_keys`, `collection_keys`, `tus_uploads`, and `shares` rows for this user.
   - Deletes all `collections` rows for this user.
   - Deletes all `sessions` and `persistent_sessions` rows for this user.
   - Deletes the `VXWM`, `VXRM`, `VXSK`, and `registration_record` from the `users` row.
   - Deletes the `users` row.
5. All active session cookies for this user become invalid immediately on the next request.
6. Server responds 204 to the deletion confirmation request.

The email address is retained in a suppression table for an operator-configurable period after deletion. This prevents immediate re-registration with the same address, which could be used to abuse sharing or invitation flows that reference the old account by email. After the suppression period the address is permanently purged.

## 20 Audit Log

### 20.1 Purpose

The audit log gives users a record of security-sensitive actions taken on their account. It serves two purposes: allowing users to detect actions they did not take (such as shares created by a compromised client), and providing a forensic record for incident response.

The audit log does not provide cryptographic proof of authenticity. A compromised server can forge or delete log entries. It is a transparency mechanism, not a security enforcement mechanism.

### 20.2 Logged events

The following events MUST be logged:

| Event                      | Logged fields                                                                             |
|----------------------------|-------------------------------------------------------------------------------------------|
| Login (successful)         | `timestamp`, `ip_network`, `user_agent`, `session_id`                                     |
| Login (failed)             | `timestamp`, `ip_network`, `user_agent`                                                   |
| Registration               | `timestamp`, `ip_network`, `user_agent`                                                   |
| Password change            | `timestamp`, `ip_network`, `session_id`                                                   |
| Recovery phrase rotation   | `timestamp`, `session_id`                                                                 |
| Sharing keypair rotation   | `timestamp`, `session_id`                                                                 |
| Share created (outgoing)   | `timestamp`, `session_id`, `recipient_id`, `share_id`, `share_kind`                       |
| Share accepted (incoming)  | `timestamp`, `session_id`, `sender_id`, `share_id`                                        |
| Share revoked              | `timestamp`, `session_id`, `share_id`                                                     |
| Persistent session created | `timestamp`, `device_label`, `session_id`                                                 |
| Persistent session revoked | `timestamp`, `device_label`                                                               |
| File move                  | `timestamp`, `session_id`, `file_id`, `source_collection_id`, `destination_collection_id` |
| Destructive reset          | `timestamp`, `ip_network`                                                                 |
| Account deletion initiated | `timestamp`, `ip_network`                                                                 |

File and collection names are NEVER logged. They are encrypted inside `VXFM` and `VXCM` blobs and the server never sees them. `share_kind` indicates whether a collection or a file was shared, but not its name or content.

### 20.3 Storage

Audit log entries are stored in a dedicated `audit_log` table with append-only access enforced at the database privilege level:

```sql
CREATE TABLE audit_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event       TEXT NOT NULL,
    metadata    JSONB NOT NULL DEFAULT '{}',
    ip_network  INET,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON audit_log (user_id, created_at DESC);
```

The application database role MUST hold INSERT and SELECT privileges on `audit_log` only. UPDATE and DELETE MUST NOT be granted to the application role. A separate privileged role (not used by the application) handles retention purges. This means the application cannot modify or delete log entries even under compromise, unless the attacker escalates beyond the application database role.

Retention period is operator-configurable. Entries are purged by a scheduled job running under the privileged role, not the application role.

### 20.4 User-facing access

Users can retrieve their own audit log via:

```rs
GET /api/v1/account/audit-log?limit=50&before={cursor}

← {
    "entries": [
      {
        "id": "...",
        "event": "share_created",
        "metadata": { "recipient_id": "...", "share_kind": "collection" },
        "ip_network": "192.168.1.0/24",
        "created_at": "2026-04-30T12:00:00Z"
      }
    ],
    "next_cursor": "..."
  }
```

The response uses cursor-based pagination. `ip_network` is coarsened to a /24 (IPv4) or /48 (IPv6) prefix before storage and before display, so precise client IP addresses are never retained or returned.

`recipient_id` and `sender_id` in share events are returned as UUIDs. The client resolves these to display names using the existing user lookup endpoint. The server does not store or return usernames or emails in the audit log.

### 20.5 Limitations

- A compromised server can suppress or fabricate log entries. The audit log is a best-effort transparency tool, not a cryptographic guarantee.
- Actions taken by a compromised client appear legitimate in the log. The log records that a share was created from the user's session, but cannot distinguish between the user and malicious code running in the same session context.
- The log does not record file content access (download events). Recording every download would produce high-volume noise and leak access patterns to anyone who can read the log. Users who need download audit trails should treat any share creation as implying potential access by the recipient.

### 20.6 Threat model addition

| Attacker capability                                      | VexaHub response                                                                                     |
|----------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| Compromised client creates shares without user knowledge | Detectable via `share_created` entries in the audit log visible to the user on next login            |
| Server suppresses or forges audit log entries            | Not preventable at the crypto layer; acknowledged limitation documented in [§20.5](#205-limitations) |
| Attacker reads another user's audit log                  | Blocked: the audit log endpoint is scoped to the authenticated user; cross-user access returns 403   |
