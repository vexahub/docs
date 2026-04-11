# CRYPTO.md — Addendum

These additions extend protocol version 1. They are non-breaking for existing accounts (no key material changes), but the binary blob for the recovery flow and the content identification scheme are new client behaviours that the server MUST support before they are advertised to clients.

## Patch for §4 (HKDF Domain Separation)

Add the following row to the HKDF table:

| Derivation                          | `info` string                                      | length |
|-------------------------------------|----------------------------------------------------|--------|
| contentIdKey from masterKey         | `vexahub:v1:contentIdKey`                          | 32     |

## New §6.5 — Content Identification and Resumable Upload Integration

Vexahub uses the [tus 1.0.0](https://tus.io/protocols/resumable-upload/1-0-x) resumable upload protocol for all file transfers between clients and the server. This section specifies how the cryptographic design integrates with tus, and how the client identifies file content in a way that preserves the zero-knowledge guarantee.

### 6.5.1 Goals

- Allow a client to detect that a previously interrupted upload exists on the server and resume it from the correct offset, without re-uploading already-transferred segments.
- Allow a client to detect that the file the user is about to upload already exists in their account, and offer to skip, replace, or duplicate it.
- Preserve the zero-knowledge property: the server MUST NOT be able to determine the plaintext content of a file from its content identifier, and MUST NOT be able to detect that two distinct users hold the same plaintext file.

### 6.5.2 Per-user content identifier

For each file, the client computes a content identifier as a keyed hash bound to the user's `masterKey`:

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

- **Deterministic per user**: the same plaintext produces the same `content_id` for the same user, enabling reliable resume detection.
- **Distinct across users**: two different users with the same plaintext produce different `content_id` values, because their `contentIdKey` differs.
- **Not invertible**: the server cannot recover plaintext from `content_id`.
- **Not testable against known content**: the server cannot pre-compute hashes of known files (leaks, public datasets, copyrighted material) and look them up in the database, because the keyed hash requires `contentIdKey` which the server never sees.

The client transmits `content_id` to the server in the clear as part of upload lookup and creation requests. The server stores it indexed per user but cannot use it for any cross-user analysis.

### 6.5.3 No cross-user deduplication

By design, Vexahub does NOT perform cross-user deduplication of stored content. If two users upload the same file, two distinct ciphertext blobs are stored. This is a deliberate trade-off: cross-user deduplication is incompatible with strong zero-knowledge guarantees because it leaks the existence of duplicate content across accounts and creates an oracle for content presence.

### 6.5.4 Streaming computation

`BLAKE3_keyed` supports incremental hashing. The client MUST compute `content_id` in a streaming fashion as it reads the local file, never loading the full plaintext into memory. For very large files (multi-GiB), the client SHOULD display a "Preparing upload" progress indicator during this phase, since it precedes the actual upload.

### 6.5.5 tus integration

Vexahub uses the tus 1.0.0 core protocol with the Creation and Termination extensions. The Checksum extension is NOT used: per-segment Poly1305 authentication tags already provide cryptographic integrity, and adding a tus-level checksum (md5/sha1/crc32) would be redundant and weaker.

**Upload-Length semantics**: the tus `Upload-Length` header carries the **ciphertext** length, not the plaintext length. The client computes the expected ciphertext length deterministically from the plaintext length:

```rs
plaintext_size                        = N bytes
SEGMENT_PLAINTEXT_SIZE                = 1 MiB = 1,048,576 bytes
SEGMENT_HEADER_SIZE                   = 42 bytes (VXFC header, see §5.3)
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

The plaintext size is never sent to the server. The server knows only the ciphertext size as `Upload-Length`.

### 6.5.6 Upload lookup flow

Before creating a new tus upload, the client queries the server to detect a resumable upload or an existing committed file:

```rs
GET /api/v1/uploads/lookup?content_id={hex}&collection_id={uuid}
Accept: application/vnd.vexahub.v1+json
```

Server responses:

- **404 Not Found** — no existing upload or committed file matches. The client MUST proceed with a fresh tus `POST /uploads` to create a new upload resource.
- **200 OK** with `{ "kind": "incomplete", "tus_url": "...", "upload_offset": <int>, "generation": <int>, "expires_at": "..." }` — an incomplete upload exists for this user with this `content_id`. The client SHOULD send a tus `HEAD` to `tus_url` to confirm the offset, then resume with `PATCH` requests.
- **200 OK** with `{ "kind": "committed", "file_id": "...", "generation": <int> }` — the file already exists fully committed in the user's account. The client MUST prompt the user to choose between skip, replace (creates generation+1), or duplicate (creates a new `file_id`).

The server MUST scope the lookup to the authenticated user. Cross-user lookups by `content_id` MUST return 404 even if a match exists in another account.

### 6.5.7 Resume alignment

A tus `PATCH` MAY contain any number of bytes, and may interrupt at any byte boundary. When an interrupted upload is resumed via `HEAD` followed by `PATCH`, the server-reported `Upload-Offset` may fall in the middle of a Vexahub crypto segment. The client MUST NOT submit ciphertext starting at that arbitrary offset, because XChaCha20-Poly1305 does not support partial AEAD writes — a segment is a single atomic encryption unit.

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
4. Client resumes with `PATCH` from `segment_start`, re-deriving each segment nonce from `(generation, segment_index)` as defined in §6.2.

The rewind endpoint is NOT part of the tus standard. It is a Vexahub extension necessary because tus alone cannot express the constraint that uploads must be aligned to AEAD segment boundaries.

### 6.5.8 Generation transitions during in-progress uploads

If the user modifies a file locally while an upload for that file is still in progress, the client MUST:

1. Send `DELETE {tus_url}` (tus Termination extension) to discard the in-progress upload server-side.
2. Recompute `content_id` for the new plaintext.
3. Increment the file's `generation` counter by 1.
4. Create a new tus upload via `POST /uploads` with the new `content_id`, the new `Upload-Length`, and the incremented `generation` in the upload metadata.

The server MUST NOT allow two concurrent uploads for the same `(user_id, file_id)` pair. The unique constraint defined in §6.5.10 enforces this.

### 6.5.9 Final integrity verification

After a download completes, the client MUST recompute `BLAKE3(plaintext)` and compare it against the `h` field stored in the file's `VXFM` blob (see §5.4). A mismatch indicates corruption, truncation, or tampering, and the client MUST refuse to surface the file to the user, MUST log the incident, and SHOULD offer to retry the download.

This BLAKE3 hash is the unkeyed plaintext hash and serves only as an integrity check on a reconstructed download. It is distinct from `content_id` in §6.5.2, which is keyed and serves as a per-user identifier for resume and duplicate detection.

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

| Attacker capability                                          | Vexahub response                                                                  |
|--------------------------------------------------------------|-----------------------------------------------------------------------------------|
| Server tries to test database for known plaintext via hash   | Blocked: `content_id` is keyed by per-user `contentIdKey`, never seen by server   |
| Server tries cross-user deduplication to infer relationships | Blocked: distinct users produce distinct `content_id` for identical plaintext     |
| Server truncates an upload to inject a shorter file          | Detected at download via BLAKE3 plaintext hash in `VXFM` (§5.4, §6.5.9)           |
| Server reorders segments within a generation                 | Blocked by per-segment AAD binding `(version, alg, generation, segment_index)`    |
| Server rolls back to an older generation                     | Blocked by monotonic `generation` enforcement (§6.3) and client-side verification |
