# VexaHub - Cryptography Specification | **Addendum**

**Document version:** 1
**Parent document:** [VexaHub - Cryptography Specification](CRYPTO.md)
**Status:** (Draft) Proposed

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
| Share created (outgoing)       | `timestamp`, `session_id`, `recipient_id`, `share_id`, `share_kind`                       |
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
