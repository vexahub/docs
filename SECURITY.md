# Security Policy

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Email: [security@vexahub.com](mailto:security@vexahub.com)

GPG key: [51A1030ABEA211C4F22FD7755567F1034E8A2D5C](https://keys.openpgp.org/vks/v1/by-fingerprint/51A1030ABEA211C4F22FD7755567F1034E8A2D5C)

Expected response time: **72 hours**. We will acknowledge receipt, confirm the scope of the issue, and keep you informed throughout the process. We ask for **90 days** to remediate before public disclosure.

## Scope

**In scope:**

- `app.vexahub.com`
- The API, served under `app.vexahub.com/api`
- `checkout.vexahub.com`
- Public link pages (`app.vexahub.com/share/...`)
- Cryptographic protocol implementation
- Authentication and session management
- Key management and sharing flows

**Out of scope:**

- Denial of service attacks
- Social engineering
- Physical access attacks
- Attacks requiring a fully compromised server colluding with itself during an active session (**documented non-goal**)
- Attacks requiring a malicious client update pushed via the distribution channel (**reproducible builds** are tracked as future work).

## Cryptographic Architecture

VexaHub is a **zero-knowledge E2EE cloud storage service**. The server never has access to user passwords, plaintext files, file names, or encryption keys during normal operation.

| Layer                | Algorithm                                                         |
| -------------------- | ----------------------------------------------------------------- |
| Authentication       | `OPAQUE (RFC 9807)`: Ristretto255, TripleDhKem (3DH + ML-KEM-768) |
| Key stretching       | `Argon2id`: 128 MiB / t=3 / p=4                                   |
| Symmetric encryption | `XChaCha20-Poly1305`: 24-byte nonces                              |
| Key derivation       | `HKDF-SHA-512`: domain-separated                                  |
| Sharing KEM          | `X-Wing` (ML-KEM-768 + X25519)                                    |
| Signatures           | `ML-DSA-65` (FIPS 204, NIST Level 3)                              |

The full specification is published at [docs.vexahub.io](https://docs.vexahub.io).

**Post-quantum resistance:** `X-Wing` hybrid KEM is secure if either **X25519 or ML-KEM-768** is secure. `ML-DSA-65` signatures protect share authenticity at matching security level. Login transcripts are quantum-resistant via `TripleDhKem` in the OPAQUE key exchange.

## What the Server Cannot Do

Even with full database access, the server cannot:

- `decrypt` user files, file names, or metadata
- `mount` offline password attacks (`OPAQUE` OPRF defense)
- `learn` shared content between users
- `identify` users who hold identical files (per-user keyed `BLAKE3` content IDs)
- `forge` share invitations (`ML-DSA-65` signatures verified client-side)

## Known Limitations

These are documented, accepted trade-offs: not vulnerabilities.

**Active session with compromised server:** a server fully controlling an active session can serve malicious responses. This is a fundamental limitation of web-based E2EE.

**Malicious client update:** a compromised distribution channel can deliver a backdoored client. Reproducible builds are tracked as future work.

**Physical device access:** an attacker with physical access to an unlocked device can access in-memory key material.

**"Remember me" mode:** the encrypted copy of the master key (`VXPS`) is stored on VexaHub servers, and the key that decrypts it (`localKey`) stays on the device. Documented trade-off, off by default.

**File content after revocation:** revoking a share immediately blocks API access and rotates keys, but does not re-encrypt existing file content by default. An opt-in re-encryption setting is planned. Downloaded copies cannot be retroactively invalidated: inherent E2EE limitation.

## Supported Versions

Only the **current production release** receives security fixes.

## Bug Bounty

There is **no formal bug bounty program** at this time. We will credit researchers in release notes if desired.
