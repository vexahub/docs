# VexaHub - Cryptography Specification | **Addendum**

> **Document version:** 6
>
> **Status:** (Draft) Proposed

**Parent document:** [VexaHub - Cryptography Specification](CRYPTO.md)

## 20 Audit Log

### 20.1 Purpose

The **audit log** gives users a record of **security-sensitive** actions taken
on their account. It serves **two** purposes: allowing users to **detect**
actions they **did not** take (such as shares created by a **compromised
client**), and providing a **forensic record** for incident response.

The **audit log** is **enabled by default** at account creation. Users can
disable it in account settings. While it is disabled, no events are logged,
and events from that period are never logged retroactively.

Each entry is **sealed**: the server encrypts it with the user's X-Wing public
key at the moment it is written ([§20.9](#209-sealed-entries)). The server sees
the event when it happens, but cannot read the history afterwards. Entries are
purged after **6 months**.

The **audit log** does **not** provide **cryptographic proof of authenticity**. A **compromised server** can **forge** or **delete** log
entries. It is a transparency mechanism, not a security enforcement mechanism.

### 20.2 Logged events

The following events **MUST** be logged:

| Event                                         | `event` value                       | Logged fields                                                                             |
| --------------------------------------------- | ----------------------------------- | ----------------------------------------------------------------------------------------- |
| Login (successful)                            | `login_success`                     | `timestamp`, `ip_network`, `user_agent`, `session_id`                                     |
| Login (failed)                                | `login_failed`                      | `timestamp`, `ip_network`, `user_agent`                                                   |
| Registration                                  | `registration`                      | `timestamp`, `ip_network`, `user_agent`                                                   |
| Password change                               | `password_change`                   | `timestamp`, `ip_network`, `session_id`                                                   |
| Recovery phrase rotation                      | `recovery_phrase_rotation`          | `timestamp`, `session_id`                                                                 |
| Sharing keypair rotation                      | `sharing_keypair_rotation`          | `timestamp`, `session_id`                                                                 |
| Share created (outgoing)                      | `share_created`                     | `timestamp`, `session_id`, `recipient_id`, `share_id`, `share_kind`, `permission`         |
| Share accepted (incoming)                     | `share_accepted`                    | `timestamp`, `session_id`, `sender_id`, `share_id`                                        |
| Share revoked                                 | `share_revoked`                     | `timestamp`, `session_id`, `share_id`                                                     |
| Persistent session created                    | `persistent_session_created`        | `timestamp`, `device_label`, `session_id`                                                 |
| Persistent session revoked                    | `persistent_session_revoked`        | `timestamp`, `device_label`                                                               |
| File move                                     | `file_move`                         | `timestamp`, `session_id`, `file_id`, `source_collection_id`, `destination_collection_id` |
| File trashed                                  | `file_trashed`                      | `timestamp`, `session_id`, `file_id`, `collection_id`                                     |
| File restored                                 | `file_restored`                     | `timestamp`, `session_id`, `file_id`, `collection_id`                                     |
| File permanently deleted                      | `file_deleted`                      | `timestamp`, `session_id`, `file_id`                                                      |
| Collection trashed                            | `collection_trashed`                | `timestamp`, `session_id`, `collection_id`                                                |
| Collection restored                           | `collection_restored`               | `timestamp`, `session_id`, `collection_id`                                                |
| Collection permanently deleted                | `collection_deleted`                | `timestamp`, `session_id`, `collection_id`                                                |
| Destructive reset                             | `destructive_reset`                 | `timestamp`, `ip_network`                                                                 |
| Account deletion initiated                    | `account_deletion_initiated`        | `timestamp`, `ip_network`                                                                 |
| Withdrawal (right of withdrawal on a payment) | `withdrawal`                        | `timestamp`, `session_id`, `payment_id`                                                   |
| 2FA recovery code used                        | `two_factor_recovery_code_used`     | `timestamp`, `ip_network`, `user_agent`                                                   |
| 2FA recovery codes renewed                    | `two_factor_recovery_codes_renewed` | `timestamp`, `ip_network`, `user_agent`                                                   |
| Audit log enabled                             | `audit_log_enabled`                 | `timestamp`, `session_id`                                                                 |
| Audit log disabled                            | `audit_log_disabled`                | `timestamp`, `session_id`                                                                 |

File and collection names are **NEVER** logged. They are **encrypted** inside `VXFM` and `VXCM` blobs and the server **never sees** them. `share_kind` indicates whether a collection or a file was shared, but **not** its name or content.

The **audit log enabled** and **audit log disabled** events are written
regardless of the current state. Enabling always writes the first
entry, and disabling always writes the last entry, so the user has a clear
record of the periods during which logging was active.

### 20.3 Storage

**Audit log** entries are stored in a dedicated `audit_log` table. Only the columns needed for pagination and purge are in plaintext; everything else is sealed ([§20.9](#209-sealed-entries)). The state is tracked by `users.audit_log_enabled` ([CRYPTO §10.1](./CRYPTO.md#101-users-table)), `TRUE` by default:

```sql
-- users.audit_log_enabled BOOLEAN NOT NULL DEFAULT TRUE

CREATE TABLE audit_log (
    id          UUID PRIMARY KEY DEFAULT uuidv7(),   -- entry_id
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kem_ct      BYTEA NOT NULL,   -- X-Wing ciphertext, 1120 bytes
    vxal        BYTEA NOT NULL,   -- sealed entry, see §20.9
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_user_created_idx ON audit_log (user_id, created_at DESC);
```

The **application database** role **MUST NOT** hold `UPDATE` on `audit_log`: an entry, once written, is never modified. The application keeps `INSERT`, `SELECT` and `DELETE`, because the user can clear their log ([§20.5](#205-clearing-the-audit-log)), account deletion removes it ([CRYPTO §19.3](./CRYPTO.md#193-account-deletion)) and the retention purge removes old entries.

**Retention:** **6 months**. A daily scheduled job deletes entries whose `created_at` is older than 6 months.

### 20.4 Enabling and disabling

The audit log is enabled at account creation (`audit_log_enabled = TRUE`). Users toggle it via:

```sh
POST /api/v1/account/audit-log/enable
POST /api/v1/account/audit-log/disable
```

Both endpoints require an active authenticated session. On enable, the server
sets `audit_log_enabled = TRUE` and writes an **audit log enabled** entry as
the first event. On disable, the server writes an **audit log disabled** entry
as the final event, then sets `audit_log_enabled = FALSE`. This ensures the
log always contains a clear record of the periods during which logging was
active.

Disabling the audit log does **not** delete existing entries. The user retains
access to previously collected events until they reach the 6-month retention.
If the user wishes to clear their log, they do so explicitly (see [§20.5](#205-clearing-the-audit-log)).

### 20.5 Clearing the audit log

Users may explicitly delete all their audit log entries:

```sh
DELETE /api/v1/account/audit-log
```

This permanently removes all entries for the authenticated user. It does
**not** disable audit logging. If logging is enabled, new events continue to
be recorded after the clear. The clear operation itself is **not** logged,
since the log is being wiped.

### 20.6 User-facing access

**Users** can retrieve their own audit log via:

```rs
GET /api/v1/account/audit-log?limit=50&before={cursor}

<- {
    "entries": [
      {
        "id": "...",
        "kem_ct": "<base64url>",
        "vxal": "<base64url>",
        "created_at": "2026-04-30T12:00:00Z"
      }
    ],
    "next_cursor": "..."
   }
```

> The response uses cursor-based pagination. The server returns sealed entries only; the client opens them in the Crypto Worker ([§20.9](#209-sealed-entries)).
>
> `recipient_id` and `sender_id` in share events are UUIDs inside the sealed `metadata`. The client resolves them to display names using the existing user lookup endpoint. The server does not store or return usernames or emails in the audit log.

The backend is written in TypeScript. Before sealing an entry, it **MUST** coarsen the client IP to **/24 (IPv4)** or **/48 (IPv6)**, with host bits zeroed, and store the result as a CIDR string in `ip_network`. The full client IP never enters the audit log.

The `sessions` table stores the exact client IP as `INET`, since it is used for security purposes (active session display, incident response) and is automatically purged when the session expires.

### 20.7 Limitations

- A **compromised server** can suppress or fabricate log entries. The **audit log** is a best-effort transparency tool, **not a cryptographic guarantee**.
- The server sees each event at the moment it writes it, and could copy it elsewhere. Sealing protects the **history** and protects against a **database leak**; it does not protect against a malicious server acting live.
- The operator can no longer read the audit log, including for support.
- **Actions** taken by a **compromised client** appear legitimate in the log. The log records that a share was created from the user's session, but **cannot** distinguish between **the user** and **malicious code** running in the **same session context**.
- The log **does not** record file content access (download events). Recording every download would produce **high-volume noise** and **leak access patterns** to anyone who can read the log. **Users** who need download audit trails should treat any share creation as implying potential access by the recipient.
- Events from periods where the log was **disabled** are **permanently unrecorded**.
- A **sharing keypair rotation** ([CRYPTO §11.3](./CRYPTO.md#113-sharing-keypair-rotation)) makes earlier entries unreadable. The client **MUST** decrypt them and offer an export before starting the rotation.
- A **destructive reset** purges the log with the rest of the account: earlier entries could no longer be decrypted anyway.

### 20.8 Threat model addition

| Attacker capability                                      | VexaHub response                                                                                                          |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Compromised client creates shares without user knowledge | Detectable via `share_created` entries in the audit log, visible to the user on next login (if audit logging was enabled) |
| Server suppresses or forges audit log entries            | Not preventable at the crypto layer; acknowledged limitation documented in [§20.7](#207-limitations)                      |
| Attacker reads another user's audit log                  | Blocked: the audit log endpoint is scoped to the authenticated user; cross-user access returns 403                        |
| Database theft                                           | Audit log unreadable without the user's X-Wing decapsulation key; only `id`, `user_id` and `created_at` are in plaintext  |
| User unaware logging was disabled during an incident     | The `audit_log_disabled` event marks the boundary; gaps in the log are visible by timestamp                               |

### 20.9 Sealed entries

Each entry is encrypted by the server for the user, with the user's X-Wing public key (`users.sharing_public_xwing`), at write time.

**Write:**

```rs
(kem_ct, sharedSecret) = X-Wing.Encaps(sharing_public_xwing)

auditKey = HKDF-SHA-512(
    ikm  = sharedSecret,
    salt = 32 zero bytes,
    info = "vexahub:v1:auditLog:" || entry_uuid,
    L    = 32
)

vxal = XChaCha20-Poly1305(auditKey, nonce, plaintext, AAD)
```

The server then forgets `sharedSecret` and `auditKey`. It keeps no way to decrypt the entry.

**Blob `VXAL`:**

```rs
Offset  Size  Field
------  ----  ---------------------------------------
0       4     Magic "VXAL" (0x56 0x58 0x41 0x4C)
4       1     Format version (0x01)
5       1     KEM algorithm ID (0x02 = X-Wing)
6       24    Nonce (random)
30      N+16  Ciphertext (canonical CBOR) + tag
```

```rs
AAD: user_id ‖ entry_id (32 bytes, both raw UUID)
```

The X-Wing ciphertext (`kem_ct`, 1120 bytes) is stored alongside the blob, in its own column.

**Plaintext columns:** `id`, `user_id`, `created_at` only, for pagination and purge.

**Sealed fields**, in canonical CBOR ([RFC 8949 §4.2.1][cbor_rfc]):

```json
{
  "event":      tstr,          // event value from §20.2
  "metadata":   map,           // event fields from §20.2
  "ip_network": tstr / null,   // CIDR, /24 or /48
  "user_agent": tstr / null,
}
```

Canonical order: `event` < `metadata` < `ip_network` < `user_agent` (length first, then bytewise).

**Read:** the client fetches entries ([§20.6](#206-user-facing-access)) and opens them in the Crypto Worker: `X-Wing.Decaps` with the decapsulation key from `VXSK`, the same HKDF derivation, then AEAD decryption with the AAD above. A failed decryption is shown as an unreadable entry, never silently dropped.

**HKDF domain separation:** the info string `"vexahub:v1:auditLog:"` is distinct from all info strings in [CRYPTO §4](./CRYPTO.md#4-hkdf-domain-separation).

## 21 Sub-collection creation by an editor

> Implemented on the server (`POST /api/v1/shares/{shareId}/subcollections`). Not used by the webapp yet: the key derivation is defined in `engine.ts` (`deriveChildCollectionKeyWrapKey`) but is not called.

When a recipient with `edit` permission creates a **sub-collection** inside a
shared collection, the sub-collection is owned by the parent collection owner
**immediately at creation**. No pending window, no TTL, no handoff required.

Every sub-collection key is a `VXCC` under its parent ([CRYPTO §5.14](CRYPTO.md#514-vxcc---child-wrapped-collection-key)): this section covers the ones an editor creates, which have no owner `VXCK` at first.

### 21.1 Key derivation

The `childCollectionKeyWrapKey` is derived from the parent `collectionKey`, mirroring
the `fileKeyWrap` derivation in [§4](./CRYPTO.md#4-hkdf-domain-separation):

| Derivation                                       | `info` string                                    | Length |
| ------------------------------------------------ | ------------------------------------------------ | ------ |
| `childCollectionKeyWrapKey` from `collectionKey` | `vexahub:v1:childCollectionKeyWrap:{child_uuid}` | 32     |

```rust
childCollectionKeyWrapKey = HKDF-SHA-512(
    ikm  = parentCollectionKey,     // collectionKey of the parent collection
    salt = 32 zero bytes,
    info = "vexahub:v1:childCollectionKeyWrap:" || child_uuid,
    L    = 32
)
```

The IKM is uniformly random **CSPRNG** output (inherited from `collectionKey`),
so zero salt has no security impact per the salt policy in [§4](./CRYPTO.md#4-hkdf-domain-separation).
All UUIDs in `info` strings are encoded as raw 16-byte big-endian binary.

### 21.2 Creation flow

1. Editor generates a new `collectionKey` via **CSPRNG**.
2. Editor generates a client-side `child_uuid` (UUID v7).
3. Editor derives `childCollectionKeyWrapKey` from `parentCollectionKey` and
   `child_uuid`.
4. Editor wraps `collectionKey` with `childCollectionKeyWrapKey` -> `VXCC` blob.

   `VXCC` has the same layout as `VXCK` (78 bytes) with magic `"VXCC"` (0x56 0x58 0x43 0x43) and AAD `parent_id ‖ collection_id ‖ uint32_be(parent_key_generation)` (36 bytes), where `parent_key_generation` is the generation of the parent `collectionKey` it is wrapped under ([CRYPTO §5.14](CRYPTO.md#514-vxcc---child-wrapped-collection-key)). The magic tells every reader to unwrap it with the parent `collectionKey`, not with a `masterKey`.

5. Editor -> Server: `POST /api/v1/shares/{shareId}/subcollections` with:
   - `id` (client-generated `child_uuid`)
   - `parentId`: a collection the share reaches ([CRYPTO §11](CRYPTO.md#11-sharing-x-wing-hybrid-kem--ml-dsa-65-signatures))
   - `vxcm` (encrypted collection metadata)
   - `vxcc` (wrapped `collectionKey`)
   - `parentKeyGeneration`: the generation of the parent key the `VXCC` is wrapped under
6. Server **MUST** verify:
   - The share is accepted, not revoked, and has the `edit` bit (`0x02`) set. Reject `HTTP 403` if not.
   - The parent is reachable through the share and belongs to the share owner. Reject `HTTP 404` if not.
   - `parentKeyGeneration` is the latest generation of the parent key, owner `VXCK` and `VXCC` generations alike. Reject `HTTP 409` if not: the editor reads the parent keys again and wraps again.
   - The provided `id` does not already exist. Reject `HTTP 409` if duplicate.
7. Server creates the collection row with `user_id = parent_collection_owner_id`
   immediately and stores the `VXCC` in `child_collection_keys` ([CRYPTO §10.3](CRYPTO.md#103-file-and-collection-keys-table)) at `key_generation` 0, with `parent_id` and `parent_key_generation`. Like for any sub-collection, this one row serves the owner and every share that reaches the parent ([CRYPTO §11](CRYPTO.md#11-sharing-x-wing-hybrid-kem--ml-dsa-65-signatures)): no copy per share. There is no owner `VXCK` row yet.
8. Server responds `201` with the collection: `keys` is empty and the `VXCC` is in `childKeys`.

### 21.3 Access

Both the editor and the owner derive `childCollectionKeyWrapKey` from their copy
of `parentCollectionKey` and the `child_uuid`. Both can unwrap
`collectionKey` from the `VXCC` blob independently.

- **Owner**: has `parentCollectionKey` via their own `VXCK` -> derives
  `childCollectionKeyWrapKey` -> unwraps sub-collection `collectionKey`. Access
  is immediate, no interaction required.
- **Editor**: has `parentCollectionKey` via their share -> derives
  `childCollectionKeyWrapKey` -> unwraps sub-collection `collectionKey`. Access
  persists as long as their `edit` share on the parent remains valid.

**Server-side access:** a share reaches the sub-collection like anything below its shared collection, through the tree ([CRYPTO §11](CRYPTO.md#11-sharing-x-wing-hybrid-kem--ml-dsa-65-signatures)). A share added above later reaches it too, without a grant.

**Owner `VXCK`:**

> Implemented on the server. Not used by the webapp yet.

The first time the owner's client unwraps a `VXCC` of one of its collections (`childKeys`) for a generation it has no `VXCK` for, it **SHOULD**, to open it later without the chain:

1. Re-wrap the same `collectionKey` with `collectionKeyWrapKey` derived from `masterKey` -> regular `VXCK` (AAD `user_id ‖ collection_id ‖ uint32_be(key_generation)`, [CRYPTO §5.8](CRYPTO.md#58-vxck---wrapped-collection-key)).
2. Send `PUT /api/v1/storage/collections/{id}/key { keyGeneration, vxck }`, where `keyGeneration` is the one of the `VXCC` it unwrapped.

The server **MUST** accept it only from the collection owner, for a generation that has a `VXCC` and no owner `VXCK` yet, and adds the `VXCK` next to the `VXCC`. Otherwise it answers `HTTP 409` (no `VXCC` at that generation, or the `VXCK` already exists) or `HTTP 403` (read-only account): the client keeps using the `VXCC` and retries on a later unwrap.

The `VXCC` stays: the shares keep opening it with the parent key, and the generation counts once. A move to the root sends the missing `VXCK` itself (§21.4), so nothing waits on this.

> The `edit` permission check (`0x02` bit) is enforced server-side only.
> An editor with `view` permission (`0x01`) technically holds `parentCollectionKey`
> and could derive `childCollectionKeyWrapKey` client-side, but the server rejects
> any creation attempt with `HTTP 403`. This is consistent with [§11.6](./CRYPTO.md#116-share-permissions): permissions
> are enforced at the server layer, not the cryptographic layer.

### 21.4 Share revocation, key rotation and move

**Rotation.** When a share on the parent collection is revoked, key rotation proceeds per [§11.1](./CRYPTO.md#111-share-revocation):

1. `parentCollectionKey` rotates.
2. Every `VXCC` directly below the parent is unwrapped with the **old** `childCollectionKeyWrapKey` and re-wrapped with the one derived from the **new** `parentCollectionKey`, in the same rotation call (CRYPTO §11.1 step 7a). The row is updated in place, for the owner and every share at once, even after the owner added its `VXCK`.
3. The revoked editor's `share_collection_keys` rows are deleted at revocation. It no longer reaches the parent, so it no longer reaches the sub-collection. It still knows the sub-collection key: the owner's client rotates the sub-collection too (CRYPTO §11.1 step 10).

**Move.** A `VXCC` is bound to its parent by both the wrap key and the AAD, so a move carries the keys for the target ([CRYPTO §11](CRYPTO.md#11-sharing-x-wing-hybrid-kem--ml-dsa-65-signatures)):

1. Under another parent: one `VXCC` per generation, under the latest key of the new parent (`HTTP 409` otherwise).
2. To the root: one owner `VXCK` per generation held only as a `VXCC` (`HTTP 409` otherwise), since no parent key can wrap it there.

The server replaces the collection's rows in `child_collection_keys` in the same transaction. The shares of the old tree lose the collection, those of the new one reach it.

### 21.5 Schema

One new table, `child_collection_keys` ([CRYPTO §10.3](CRYPTO.md#103-file-and-collection-keys-table)): one `VXCC` per generation of every sub-collection, whoever created it, with its `parent_id` and `parent_key_generation`. `collection_keys` and `share_collection_keys` hold only `VXCK` blobs. The server accepts a client-provided `id` (UUID v7) on collection creation and enforces uniqueness.

```sql
-- child_collection_keys: see CRYPTO §10.3.
-- collections.user_id = parent_collection_owner_id at creation.
```

### 21.6 HKDF domain separation

The info string `"vexahub:v1:childCollectionKeyWrap:"` is distinct from all
existing info strings in [§4](./CRYPTO.md#4-hkdf-domain-separation). No protocol version bump required.

### 21.7 Guarantees

| Property                                                  | Status                                                         |
| --------------------------------------------------------- | -------------------------------------------------------------- |
| Editor has immediate access after creation                | ✅                                                             |
| Owner has immediate cryptographic access after creation   | ✅ No pending window                                           |
| Owner is true owner from creation                         | ✅ `user_id = owner_id` at insert                              |
| No TTL, no pending state, no handoff                      | ✅                                                             |
| Server can read sub-collection content                    | ❌ Zero-knowledge preserved                                    |
| Shares added to the parent later reach the sub-collection | ✅ One `VXCC` row for everyone, no copy per share              |
| Editor loses access on parent share revocation            | ✅ Server-enforced, and the sub-collection key rotates (§21.4) |
| Owner retains access after `parentCollectionKey` rotation | ✅ Through the re-wrapped `VXCC`, or its own `VXCK`            |
| Owner can move the sub-collection                         | ✅ With the keys for the target in the move itself (§21.4)     |
| Server rejects creation if editor lacks `edit` permission | ✅ HTTP 403 on missing `0x02` bit                              |
| No protocol version bump required                         | ✅ New HKDF info string only                                   |

## Changelog

- **6:** every sub-collection key is a `VXCC` under its parent, aligned with CRYPTO v19. Access through the tree (§21.3). The owner `VXCK` becomes a SHOULD (§21.3). A move carries a `VXCC` under the new parent, or the owner `VXCK` at the root (§21.4, §21.7).
- **5:** `VXCC` in their own table `child_collection_keys`, one row for the owner and the shares, re-wrapped in place (§21.2, §21.4, §21.5). `parentKeyGeneration` on creation (§21.2). Access through the parent (§21.3). The owner adds its `VXCK` next to the `VXCC`, implemented on the server (§21.3). Move refused while a generation is held only as a `VXCC`, `VXCC` rows deleted on a move (§21.4). Guarantees updated (§21.7), aligned with CRYPTO v18.
- **4:** key generation in the AAD of `VXCC` and of the owner `VXCK` (§21.2, §21.3), aligned with CRYPTO v17.
- **3:** audit log enabled by default, sealed with the user's X-Wing public key, 6-month retention (§20.1, §20.3, §20.4, new §20.9). Events list aligned with the code (§20.2). `UPDATE` alone is withheld from the application role (§20.3). IP masking described for the TypeScript backend (§20.6). §21 renamed to `childCollectionKeyWrap`, UUID v7, real route, marked as planned. `VXCC` blob for the sub-collection key, re-wrapped as `VXCK` by the owner (§21.2 to §21.5, §21.7).

[//]: # "LINKS"
[cbor_rfc]: https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1
