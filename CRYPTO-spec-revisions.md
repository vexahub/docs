# Vexahub Cryptography Spec — Revision Notes

> Items identified during draft review. To be addressed before the spec leaves draft status.

---

## High Priority

### 1. Persistent session `localKey` held in server plaintext

**Location:** §9.2

The server stores `localKey` in plaintext in `persistent_sessions`. A full server compromise means an attacker who also captures a session cookie can decrypt any persistent session's `masterKey`. This is documented as a trade-off, but the severity deserves a stronger treatment:

- `localKey` never rotates unless the user explicitly revokes the session
- There is no forward secrecy on `localKey`
- Full server compromise + cookie = `masterKey` decryptable, no further steps needed

**To do:**
- Strengthen the threat model entry for this case
- Elevate WebAuthn PRF (currently listed as future work in §18) to a higher urgency item — PRF output never leaves the device, the server holds nothing, this closes the gap cleanly

---

### 2. Share revocation is impossible

**Location:** §11, §17

Not addressed anywhere in the spec. Once a recipient accepts a share and re-wraps the shared `collectionKey` or `fileKey` under their own `masterKey`, the sender has no mechanism to revoke access. The server can hide the share record, but the recipient already holds the key.

This is a known hard problem in E2EE sharing, but it must be explicitly acknowledged.

**To do:**
- Add a threat model entry: *"Share revocation — sender cannot revoke access after recipient has accepted; re-encryption of shared content is the only remedy."*
- Document the implication: revoking a share requires the sender to re-encrypt the target collection or file under a new key and re-share with remaining recipients
- Specify whether the server enforces any post-revocation access restrictions (e.g. hiding the share record) as a best-effort layer

---

## Medium Priority

### 3. `collectionKey` and `fileKey` are non-rotatable without full re-encryption

**Location:** §3, §6

Both keys are deterministically derived from `masterKey`:

```
masterKey → HKDF(collection_id) → collectionKey
          → HKDF(file_id)       → fileKey
```

This means:
- A suspected `masterKey` compromise requires a full destructive reset — there is no surgical rotation
- Individual collections cannot be rekeyed independently
- All past and future files are tied to the same `masterKey`

**To do:**
- Either document this limitation explicitly in the threat model
- Or evaluate switching `collectionKey` to a random key wrapped by `masterKey` (stored server-side encrypted), which would allow per-collection rotation independently of `masterKey`

---

### 4. Share timestamp replay window unspecified

**Location:** §11

The signed share payload includes a `timestamp` field:

```
{ share_uuid, sender_id, recipient_id, ctXwing, vxsh, timestamp }
```

However the spec does not define:
- Maximum acceptable age of a share record before rejection
- Clock skew tolerance between sender and recipient
- Which party (client or server) enforces timestamp freshness

Without this, a malicious server could re-present an old revoked share record.

**To do:**
- Define a replay window (e.g. shares older than 30 days are rejected by the client)
- Define clock skew tolerance (e.g. ±5 minutes)
- Specify that the **client** enforces freshness after signature verification, not the server

---

## Low Priority

### 5. Zero salt rationale incomplete for KEM-derived IKM

**Location:** §4

The zero salt rationale states:

> "Zero salt simplifies cross-platform interoperability and has no security impact when info is unique per purpose."

This holds when IKM is uniformly random (e.g. `masterKey`, `exportKey`). However `shareWrapKey` is derived from the X-Wing shared secret, which is the output of a KEM combiner — not raw random bytes. If the combiner ever produced biased output, a random salt would provide a meaningful extra defense.

**To do:**
- Add one sentence to the §4 rationale acknowledging this distinction and documenting the accepted risk

---

### 6. `contentIdKey` is permanent and unscoped

**Location:** §6.5.2

```
contentIdKey = HKDF(masterKey, "vexahub:v1:contentIdKey")
```

This key is the same for all files across all collections, forever. The server accumulates a permanent index of `(user, content_id)` mappings. If `contentIdKey` were ever leaked, this historical index becomes an oracle: an attacker could pre-compute hashes of known files and look them up against the stored `content_id` values.

**To do:**
- Either document this as an accepted limitation
- Or scope `contentIdKey` per collection: `HKDF(masterKey, "vexahub:v1:contentIdKey:{collection_uuid}")` — limits blast radius to one collection at the cost of losing cross-collection resume detection

---

### 7. BIP39 empty passphrase rationale missing

**Location:** §12.1

The spec uses `BIP39.mnemonicToSeed(phrase, passphrase = "")` without explaining the choice of empty passphrase. BIP39 supports an optional passphrase that would extend entropy, which could raise questions from auditors.

**To do:**
- Add one sentence: the empty passphrase is intentional — the 24-word phrase already provides 256 bits of entropy, and requiring users to remember both a phrase and a separate passphrase would create an unacceptable support and usability burden with no meaningful security improvement

---

## Summary Table

| # | Issue | Priority | Effort |
|---|---|---|---|
| 1 | Persistent session `localKey` in server plaintext | High | High |
| 2 | Share revocation impossible | High | High |
| 3 | `collectionKey` non-rotatable without full re-encryption | Medium | Medium |
| 4 | Share timestamp replay window unspecified | Medium | Low |
| 5 | Zero salt rationale incomplete for KEM output | Low | Low |
| 6 | `contentIdKey` permanent and unscoped | Low | Low |
| 7 | BIP39 empty passphrase rationale missing | Low | Low |
