# users/

Account and local security posture: sudo, polkit, gpg/ssh keys, login. Pointer-and-commentary only — **never** put private key material or secrets here in plaintext (see `meta/conventions.md` "No secrets in plaintext").

## How to behave here

- Document where keys live and how auth is configured, not the secrets themselves.
- Security cross-cuts: each domain owns its own posture; this dir owns account-level concerns.

## Cross-refs

- `services/` — daemons that enforce auth.
