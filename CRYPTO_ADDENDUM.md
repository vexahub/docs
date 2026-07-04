# VexaHub - Cryptography Specification | **Addendum**

> **Document version:** 2
>
> **Status:** (Draft) Proposed

**Parent document:** [VexaHub - Cryptography Specification](CRYPTO.md)

## 20 Audit Log

### 20.1 Purpose

The **audit log** gives users a record of **security-sensitive** actions taken
on their account. It serves **two** purposes: allowing users to **detect**
actions they **did not** take (such as shares created by a **compromised
client**), and providing a **forensic record** for incident response.

The **audit log** is **opt-in**. Users enable it explicitly in account
settings. No events are logged until the user enables it. The log only covers
events from the point it was enabled. Prior account activity is never
retroactively logged.

The **audit log** does **not** provide **cryptographic proof of authenticity**. A **compromised server** can **forge** or **delete** log
entries. It is a transparency mechanism, not a security enforcement mechanism.

### 20.2 Logged events

The following events **MUST** be logged:

| Event                          | Logged fields                                                                             |
|--------------------------------|-------------------------------------------------------------------------------------------|
| Login (successful)             | `timestamp`, `ip_network`, `user_agent`, `session_id`                                     |
| Login (failed)                 | `timestamp`, `ip_network`, `user_agent`                                                   |
| Registration                   | `timestamp`, `ip_network`, `user_agent`                                                   |
| Password change                | `timestamp`, `ip_network`, `session_id`                                                   |
| Recovery phrase rotation       | `timestamp`, `session_id`                                                                 |
| Sharing keypair rotation       | `timestamp`, `session_id`                                                                 |
| Share created (outgoing)       | `timestamp`, `session_id`, `recipient_id`, `share_id`, `share_kind`, `permission`         |
| Share accepted (incoming)      | `timestamp`, `session_id`, `sender_id`, `share_id`                                        |
| Share revoked                  | `timestamp`, `session_id`, `share_id`                                                     |
| Persistent session created     | `timestamp`, `device_label`, `session_id`                                                 |
| Persistent session revoked     | `timestamp`, `device_label`                                                               |
| File move                      | `timestamp`, `session_id`, `file_id`, `source_collection_id`, `destination_collection_id` |
| File trashed                   | `timestamp`, `session_id`, `file_id`, `collection_id`                                     |
| File restored                  | `timestamp`, `session_id`, `file_id`, `collection_id`                                     |
| File permanently deleted       | `timestamp`, `session_id`, `file_id`                                                      |
| Collection trashed             | `timestamp`, `session_id`, `collection_id`                                                |
| Collection restored            | `timestamp`, `session_id`, `collection_id`                                                |
| Collection permanently deleted | `timestamp`, `session_id`, `collection_id`                                                |
| Destructive reset              | `timestamp`, `ip_network`                                                                 |
| Account deletion initiated     | `timestamp`, `ip_network`                                                                 |

File and collection names are **NEVER** logged. They are **encrypted** inside `VXFM` and `VXCM` blobs and the server **never sees** them. `share_kind` indicates whether a collection or a file was shared, but **not** its name or content.

The **audit log enabled** and **audit log disabled** events are written
regardless of the current opt-in state. Enabling always writes the first
entry, and disabling always writes the last entry, so the user has a clear
record of the periods during which logging was active.

### 20.3 Storage

**Audit log** entries are stored in a dedicated `audit_log` table with append-only access enforced at the database privilege level. The `users` table
gains an `audit_log_enabled` column to track opt-in state:

```sql
ALTER TABLE users ADD COLUMN audit_log_enabled BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE audit_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event       TEXT NOT NULL,
    metadata    JSONB NOT NULL DEFAULT '{}',
    ip_network  CIDR,         -- /24 IPv4 or /48 IPv6, host bits zeroed at insert
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON audit_log (user_id, created_at DESC);
```

The **application database** role **MUST** hold `INSERT` and `SELECT` privileges on `audit_log` only. `UPDATE` and `DELETE` **MUST NOT** be granted to the **application** role. A **separate** privileged role (not used by the application) handles retention purges. This means the application **cannot** modify or delete log entries **even under compromise**, unless the attacker escalates beyond the application database role.

Retention period is **operator-configurable**. Entries are purged by a scheduled job running under the privileged role, **not the application role**.

### 20.4 Enabling and disabling

Users toggle audit logging via:

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
access to previously collected events. If the user wishes to clear their log,
they do so explicitly (see [§20.5](#205-clearing-the-audit-log)).

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
        "event": "share_created",
        "metadata": { "recipient_id": "...", "share_kind": "collection" },
        "ip_network": "192.168.1.0/24",
        "created_at": "2026-04-30T12:00:00Z"
      }
    ],
    "next_cursor": "..."
   }
```

> The response uses cursor-based pagination. `ip_network` is coarsened to a /24 (IPv4) or /48 (IPv6) prefix before storage and before display, so precise client IP addresses are never retained or returned.
>
> `recipient_id` and `sender_id` in share events are returned as UUIDs. The client resolves these to display names using the existing user lookup endpoint. The server does not store or return usernames or emails in the audit log.

The application **MUST** coarsen the client IP to **/24 (IPv4)** or **/48 (IPv6)** before insert, with host bits **explicitly** zeroed. The `CIDR` column type rejects values where host bits are set, providing a database-level safeguard against accidental full-IP storage:

```rust
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

fn coarsen(client_ip: IpAddr) -> IpNet {
    match client_ip {
        IpAddr::V4(v4) => IpNet::V4(Ipv4Net::new(v4, 24).unwrap().trunc()),
        IpAddr::V6(v6) => IpNet::V6(Ipv6Net::new(v6, 48).unwrap().trunc()),
    }
}
```

The `.trunc()` call zeroes host bits.

The `sessions` table stores the exact client IP as `INET`, since it is used for security purposes (active session display, incident response) and is automatically purged when the session expires.

### 20.7 Limitations

- A **compromised server** can suppress or fabricate log entries. The **audit log** is a best-effort transparency tool, **not a cryptographic guarantee**.
- **Actions** taken by a **compromised client** appear legitimate in the log. The log records that a share was created from the user's session, but **cannot** distinguish between **the user** and **malicious code** running in the **same session context**.
- The log **does not** record file content access (download events). Recording every download would produce **high-volume noise** and **leak access patterns** to anyone who can read the log. **Users** who need download audit trails should treat any share creation as implying potential access by the recipient.
- The log only covers events from the point it was enabled. Prior account
  activity is **never retroactively** logged. If the user **disables** and **re-enables**
  logging, events during the disabled period are **permanently unrecorded**.

### 20.8 Threat model addition

| Attacker capability                                      | VexaHub response                                                                                                          |
|----------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| Compromised client creates shares without user knowledge | Detectable via `share_created` entries in the audit log, visible to the user on next login (if audit logging was enabled) |
| Server suppresses or forges audit log entries            | Not preventable at the crypto layer; acknowledged limitation documented in [§20.7](#207-limitations)                      |
| Attacker reads another user's audit log                  | Blocked: the audit log endpoint is scoped to the authenticated user; cross-user access returns 403                        |
| User unaware logging was disabled during an incident     | The `audit_log_disabled` event marks the boundary; gaps in the log are visible by timestamp                               |

## 21 Sub-collection creation by an editor (subject to change)

When a recipient with `edit` permission creates a **sub-collection** inside a
shared collection, the sub-collection is owned by the parent collection owner
**immediately at creation**. No pending window, no TTL, no handoff required.

### 21.1 Key derivation

The `subCollectionWrapKey` is derived from the parent `collectionKey`, mirroring
the `fileKeyWrap` derivation in [§4](./CRYPTO.md#4-hkdf-domain-separation):

| Derivation                                  | `info` string                                       | Length |
|---------------------------------------------|-----------------------------------------------------|--------|
| `subCollectionWrapKey` from `collectionKey` | `vexahub:v1:subCollectionWrap:{subcollection_uuid}` | 32     |

```rust
subCollectionWrapKey = HKDF-SHA-512(
    ikm  = parentCollectionKey,     // collectionKey of the parent collection
    salt = 32 zero bytes,
    info = "vexahub:v1:subCollectionWrap:" || subcollection_uuid,
    L    = 32
)
```

The IKM is uniformly random **CSPRNG** output (inherited from `collectionKey`),
so zero salt has no security impact per the salt policy in [§4](/CRYPTO.md#4-hkdf-domain-separation).
All UUIDs in `info` strings are encoded as raw 16-byte big-endian binary.

### 21.2 Creation flow

1. Editor generates a new `collectionKey` via **CSPRNG**.
2. Editor generates a client-side `subcollection_uuid` (UUID v4).
3. Editor derives `subCollectionWrapKey` from `parentCollectionKey` and
   `subcollection_uuid`.
4. Editor wraps `collectionKey` with `subCollectionWrapKey` -> `VXCK` blob.
5. Editor -> Server: `POST /api/v1/collections` with:
   - `id` (client-generated `subcollection_uuid`)
   - `parent_id` of the shared collection
   - `vxcm` (encrypted collection metadata)
   - `vxck` (wrapped `collectionKey`)
6. Server **MUST** verify:
   - The editor's share on the parent collection has the `edit` bit (`0x02`) set. Reject `HTTP 403` if not.
   - The provided `id` is a valid UUID and does not already exist. Reject `HTTP 409` if duplicate.
7. Server creates the collection row with `user_id = parent_collection_owner_id`
   immediately. The owner is the owner from the first moment.
8. Server responds `201` with the `collection_id`.

### 21.3 Access

Both the editor and the owner derive `subCollectionWrapKey` from their copy
of `parentCollectionKey` and the `subcollection_uuid`. Both can unwrap
`collectionKey` from the `VXCK` blob independently.

- **Owner**: has `parentCollectionKey` via their own `VXCK` -> derives
  `subCollectionWrapKey` -> unwraps sub-collection `collectionKey`. Access
  is immediate, no interaction required.
- **Editor**: has `parentCollectionKey` via their share `VXSH` -> derives
  `subCollectionWrapKey` -> unwraps sub-collection `collectionKey`. Access
  persists as long as their `edit` share on the parent remains valid.

> The `edit` permission check (`0x02` bit) is enforced server-side only.
> An editor with `view` permission (`0x01`) technically holds `parentCollectionKey`
> and could derive `subCollectionWrapKey` client-side, but the server rejects
> any creation attempt with `HTTP 403`. This is consistent with [§11.6](/CRYPTO.md#116-share-permissions): permissions
> are enforced at the server layer, not the cryptographic layer.

### 21.4 Share revocation and key rotation

When the editor's share on the parent collection is revoked, key rotation
proceeds per [§11.1](/CRYPTO.md#111-share-revocation):

1. `parentCollectionKey` rotates. A new `collectionKey` is generated for
   the parent collection.
2. The owner unwraps each sub-collection `collectionKey` using the **old**
   `subCollectionWrapKey` (derived from the old `parentCollectionKey`).
3. The owner derives new `subCollectionWrapKey` values from the **new**
   `parentCollectionKey` and each `subcollection_uuid`.
4. The owner re-wraps each sub-collection `collectionKey` with the new
   `subCollectionWrapKey` -> new `VXCK` blobs, uploaded to the server.
5. The editor can no longer derive `subCollectionWrapKey`; they have no
   access to the new `parentCollectionKey`.

This is identical in cost to re-wrapping `VXFK` blobs after revocation
([§11.1](/CRYPTO.md#111-share-revocation)). Sub-collections are treated as additional
key-wrapped resources alongside files.

### 21.5 Schema

No new tables required. Sub-collections created by editors use the existing
`collections` and `collection_keys` tables. The server accepts a
client-provided `id` (UUID v4) on collection creation and enforces uniqueness.

```sql
-- No schema changes beyond what §11.1 already requires.
-- collections.user_id = parent_collection_owner_id at creation.
```

### 21.6 HKDF domain separation

The info string `"vexahub:v1:subCollectionWrap:"` is distinct from all
existing info strings in [§4](/CRYPTO.md#4-hkdf-domain-separation). No protocol version bump required.

### 21.7 Guarantees

| Property                                                        | Status                                               |
|-----------------------------------------------------------------|------------------------------------------------------|
| Editor has immediate access after creation                      | ✅                                                   |
| Owner has immediate cryptographic access after creation         | ✅ No pending window                                 |
| Owner is true owner from creation                               | ✅ `user_id = owner_id` at insert                    |
| No TTL, no pending state, no handoff                            | ✅                                                   |
| Server can read sub-collection content                          | ❌ Zero-knowledge preserved                          |
| Editor loses access on parent share revocation                  | ✅ `parentCollectionKey` rotation invalidates access |
| Owner retains access after `parentCollectionKey` rotation       | ✅ Re-wraps `VXCK` with new `subCollectionWrapKey`   |
| Server rejects creation if editor lacks `edit` permission       | ✅ HTTP 403 on missing `0x02` bit                    |
| No protocol version bump required                               | ✅ New HKDF info string only                         |
