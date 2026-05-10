# A note from the author

This document is the product of **many** hours of careful thought, research, and back-and-forth decision-making. **Every** parameter, **every** algorithm choice, **every** byte in the blob formats was weighed against **real-world** constraints.

What protects users against **realistic** threats, what stays usable for normal people, what can be audited by security researchers, and what will still make sense **five years** from now.

## Our values

**VexaHub** is built on a **fundamental** belief. We believe that **privacy** should not be a premium feature, and **"trust us"** is not a security model. The only encryption worth calling **end-to-end** is the kind where the people running the servers genuinely **cannot** read your files, not because they promise not to, but because the math **does not** allow it.

> Everything in this specification follows from that belief.
>
> - **OPAQUE** means the server never sees passwords.
>
> - **Argon2id** at 128 MiB means offline attacks is hard to overcome.
>
> - **XChaCha20-Poly1305** means no nonce reuse footguns.
>
> - **X-Wing** means sharing survives the arrival of quantum computers.
>
> A single Rust crate as the **cryptographic** source of truth means every VexaHub client (web, desktop, mobile) speaks exactly the same language down to the last byte.

## Notes

None of this is perfect. Cryptography **never** is. But it is **honest**, it is **documented**, and it is **open** to scrutiny.

If you find a mistake in this document, **please** reach out! Security is a **collaborative** effort, and **VexaHub** is better with your help than **without** it.

To anyone reading this who is building something similar. Please, **do not** cut corners on the crypto. Your users are trusting you with the most personal things they own. Take that trust **seriously**.

Built with care in **France** ![Beautiful and magnificent French flag](/public/fr.svg) - For everyone who believes privacy is a **right**, not a **privilege**.

Love from the team ❤
