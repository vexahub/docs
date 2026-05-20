# VexaHub - Cryptography Specification | **Addendum**

> **Document version:** 1
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
they do so explicitly (see §20.5).

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

The `.trunc()` call zeroes host bits, which is what the PostgreSQL `CIDR` type requires.

The `ip_network` column on the `sessions` table ([§9.3](CRYPTO.md#93-session-schemas)) follows the same rule. Update its schema to `CIDR` as well:

```sql
ALTER TABLE sessions ALTER COLUMN ip_network TYPE CIDR USING ip_network::CIDR;
```

For new deployments, declare it as `CIDR` from the start.

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

## 21 Sub-collection creation by an editor

When a recipient with `edit` permission creates a **sub-collection** inside a
shared collection, **ownership is transferred to the parent collection owner**
*asynchronously* **via a server-assisted key handoff**.

> **Sync mechanism:** All notifications in this section are delivered via the
> sync mechanism defined in the API specification. "Notifies via sync" below
> always refers to this mechanism.

### 21.1 Creation flow

1. Editor generates a new `collectionKey` via **CSPRNG**.
2. Editor wraps `collectionKey` under their own `masterKey` -> `VXCK` blob
   (editor-scoped). **Editor has immediate access**.
3. Editor wraps `collectionKey` under a new **X-Wing share invitation** addressed
   to the parent collection owner -> `VXSH` blob. The invitation **MUST** set
   `"p"` to `0x07` (*view* + *edit* + *reshare*). The owner receives full permissions
   on the **sub-collection regardless of the editor's own permission level** on
   the parent.
4. Editor -> Server: `POST /api/v1/collections` with:
   - `parent_id` of the shared collection
   - `vxcm` (**encrypted collection** metadata)
   - `vxck_editor` (**editor-scoped** wrapped key)
   - `vxsh_owner` (**X-Wing invitation** for the owner)
5. Server **MUST** verify the editor's share on the parent collection has the
   `edit` bit (`0x02`) set in `permission` before accepting the request.
   Reject with `HTTP 403` if not.
6. Server stores the new collection row with `user_id = editor_user_id`
   temporarily and inserts a row into `pending_ownership_transfers`.
7. Server notifies the owner via sync that a pending transfer requires their
   approval.

### 21.2 Owner acceptance flow

> If the owner has **auto-accept** enabled in their account settings, the client
> **MUST** process all pending transfers automatically on sync without prompting
> the user. Steps 1-5 execute identically; no confirmation UI is shown.
>
> **`auto_accept` column semantics:** The `auto_accept` column on
> `pending_ownership_transfers` snapshots the owner's `auto_accept_subcollections`
> setting **at the moment the transfer row is created** within the same transaction.
> If the owner changes their setting after creation, the snapshotted value on the row governs that
> specific transfer.
>
> The live `users.auto_accept_subcollections` value governs
> only future transfers. This prevents a race where the owner disables
> auto-accept between creation and sync processing.

On next sync, the **parent collection owner's client** detects the pending
transfer:

1. Owner fetches `vxsh_owner` from the `pending_ownership_transfers` row.
2. Owner verifies the **ML-DSA-65 signature** on the share invitation.
3. Owner decapsulates the **X-Wing ciphertext**, derives `shareWrapKey`, unwraps
   `collectionKey`.
4. Owner wraps `collectionKey` under their own `masterKey` -> new `VXCK` blob
   (owner-scoped).
5. Owner -> Server: `POST /api/v1/collections/{collection_id}/accept-ownership`
   with `vxck_owner`.
6. Server atomically:
   - Replaces `collections.user_id` with the parent collection owner's
     `user_id`.
   - Stores the owner-scoped `VXCK` in `collection_keys`.
   - Retains the editor-scoped `VXCK` in `collection_keys`. The editor
     retains cryptographic access as long as their `edit` share on the
     parent collection remains valid.
   - Deletes the `pending_ownership_transfers` row.

### 21.3 Owner rejection flow

If the owner explicitly rejects the handoff:

1. Owner -> Server: `POST /api/v1/collections/{collection_id}/reject-ownership`.
2. Server atomically:
   - Permanently deletes the sub-collection row.
   - Deletes all `files`, `file_keys`, `collection_keys`, and object storage
     blobs belonging to the sub-collection. Files uploaded by the editor
     during the pending window are included in this deletion.
   - Deletes the `pending_ownership_transfers` row.
3. Server notifies the editor via sync that the sub-collection was rejected.
   The editor's client **MUST** evict the `collectionKey` from its Worker
   cache on receiving this notification.

### 21.4 Share revocation during a pending transfer

If the editor's share on the parent collection is revoked while a pending
ownership transfer exists for a sub-collection they created, the revocation
takes effect **immediately** at the API layer. The editor loses access to the
parent collection right away. Resolution of the pending transfer is
independent and proceeds as follows:

1. Server atomically revokes the share and sets `revocation_pending = TRUE`
   on all `pending_ownership_transfers` rows originated by that editor under
   the affected parent collection.
2. Server notifies the owner via sync of both the revocation and any pending
   transfers requiring resolution.
3. The owner **SHOULD** explicitly accept or reject each pending transfer.
   The server **MUST** surface these as a grouped decision: `"Editor X's
   access was revoked. They created N sub-collections pending your approval.
   Accept or reject each before continuing."`
4. If the owner does not act within the TTL, the server automatically rejects
   all pending transfers from that editor, deletes the sub-collections and
   their contents atomically, and notifies the owner via sync.
5. If the owner is offline indefinitely, the TTL ensures the pending state
   does not persist forever. The parent share revocation is already fully
   in effect regardless of TTL expiry.

### 21.5 Pending window TTL

If the handoff remains pending beyond the operator-configurable TTL
(**recommended**: *7 days*) **without owner action**,
the server **automatically rejects it**, **deletes the sub-collection and all its contents atomically**, and notifies
the editor via sync.

> The server **MUST** notify the owner via sync **at least 24 hours** before a
> pending transfer expires. If the owner **does not act after the warning**,
> the transfer **is rejected and the sub-collection deleted** as normal.

### 21.6 Schema additions

```sql
CREATE TABLE pending_ownership_transfers (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id      UUID NOT NULL REFERENCES collections(id)
                           ON DELETE RESTRICT,
    editor_user_id     UUID NOT NULL REFERENCES users(id)
                           ON DELETE RESTRICT,
    owner_user_id      UUID NOT NULL REFERENCES users(id)
                           ON DELETE RESTRICT,
    vxsh_owner         BYTEA NOT NULL,
    revocation_pending BOOLEAN NOT NULL DEFAULT FALSE,
    auto_accept        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '7 days'
);

CREATE UNIQUE INDEX ON pending_ownership_transfers (collection_id);
CREATE INDEX ON pending_ownership_transfers (owner_user_id)
    WHERE revocation_pending = FALSE;
CREATE INDEX ON pending_ownership_transfers (owner_user_id)
    WHERE revocation_pending = TRUE;
CREATE INDEX ON pending_ownership_transfers (expires_at);

-- FOR users TABLE!
ALTER TABLE users ADD COLUMN auto_accept_subcollections BOOLEAN NOT NULL DEFAULT FALSE;
```

`ON DELETE RESTRICT` on all foreign keys ensures that collections, editors,
and owners involved in a pending transfer cannot be deleted until the transfer
is explicitly resolved. Account deletion flows **MUST** resolve or reject all
pending transfers before deleting the user row, consistent with the dependency
walk defined in §19.3.

### 21.7 Privacy note

During the pending window, only the editor holds the plaintext `collectionKey`.
The parent collection owner has no cryptographic access to the sub-collection
until acceptance. This window should be kept as short as possible. Clients
**SHOULD** process pending ownership transfers eagerly on sync rather than
deferring them.

The UI **MUST** display a `"Pending owner approval"` indicator on the
sub-collection for the editor, and a `"Pending your approval"` indicator for
the owner.

### 21.8 Guarantees

| Property                                                        | Status                                                                                      |
|-----------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| Editor has immediate access after creation                      | ✅                                                                                          |
| Owner has cryptographic access before accepting handoff         | ❌ Pending window                                                                           |
| Owner becomes true owner after acceptance                       | ✅                                                                                          |
| Owner receives full permissions on accepted sub-collection      | ✅ `"p" = 0x07` enforced in `vxsh_owner`                                                    |
| Owner can auto-accept transfers on sync without manual approval | ✅ Per-account opt-in setting                                                               |
| Server can read sub-collection content                          | ❌ Zero-knowledge preserved                                                                 |
| Handoff is cryptographically authenticated                      | ✅ ML-DSA-65 signature on `vxsh_owner`                                                      |
| Editor retains access after ownership transfer                  | ✅ While their `edit` share on the parent remains valid                                     |
| Files uploaded during pending window are deleted on rejection   | ✅                                                                                          |
| Parent share revocation takes effect immediately                | ✅ Independent of pending transfer resolution                                               |
| Pending transfer resolved before account deletion               | ✅ ON DELETE RESTRICT enforced, [§19.3](./CRYPTO.md#193-account-deletion) dependency walk   |
| Pending state cannot persist forever if owner is offline        | ✅ TTL auto-rejection after 7 days                                                          |
| Server rejects creation if editor lacks `edit` permission       | ✅ HTTP 403 on missing `0x02` bit                                                           |
