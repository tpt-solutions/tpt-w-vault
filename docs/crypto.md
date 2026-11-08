# tpt-vault cryptographic design

This document describes the on-disk format and the security reasoning behind it. It is the
reference for the Phase 12 security review.

## Keys

| Key | Source | Use |
|-----|--------|-----|
| Master key (32 B) | CSPRNG at vault creation | Root of all other keys |
| Content key (32 B) | HKDF-SHA256(master, `tpt-vault v1 content AES-256-GCM`) | Block AEAD |
| Name key (64 B) | HKDF-SHA256(master, `tpt-vault v1 names AES-256-SIV`) | Filename SIV |
| Passphrase wrap key (32 B) | scrypt(passphrase, 16-byte salt, N=2^log_n, r, p) | Wraps master key |
| Recovery wrap key (32 B) | HKDF-SHA256(recovery secret, `tpt-vault v1 recovery-code wrap`) | Wraps master key |

The recovery secret is 256 random bits. It is never stored; only its wrapped master key is.
Since the secret has full entropy, a fast HKDF is sufficient and scrypt is not needed.

## `vault.conf`

JSON. Fields: `format_version`, `kdf` (algorithm, log_n, r, p, salt), `content_cipher`,
`name_cipher`, `wrapped_master_key`, and optional `recovery.wrapped_master_key`. Both wraps are
AES-256-GCM, with associated data `tpt-vault:vault.conf:v1:passphrase` or `...:recovery`.
A wrap cannot be swapped for the other.

## File contents

```
header: "TPTV" | version (1) | file id (16)                 21 bytes
record i: nonce (12, random) | ciphertext (<= 4096) | tag (16)
```

Each record is AES-256-GCM under the content key. The associated data is
`header || u64le(i) || is_last`:

- The header and index stop reordering and splicing between files.
- `is_last` stops a truncation at a block boundary from verifying.

File names are not in the associated data, so a rename never re-encrypts content.

The plaintext length is implied by the file size. A partial write re-encrypts only the blocks
it touches, plus the old last block when the file grows, because that block's `is_last` flag
changes.

## Filenames

Each path segment is encrypted with AES-256-SIV (RFC 5297) under the name key, with no
associated data, and encoded as base64url. Encryption is deterministic, so directory listings
are stable. The same name in two directories gives the same ciphertext segment.

Encrypted names over 255 bytes are stored as `longname.<base64url(SHA-256(encrypted name))>`.
A sidecar file with the same name plus `.name` holds the full encrypted name. Listing verifies
the sidecar against the hash.

## Error classes

- `WrongPassphrase`: the passphrase or recovery code did not unwrap the master key. It also
  covers a damaged `vault.conf`, because the two cannot be told apart.
- `Corrupt`: a block, name or sidecar failed authentication after the key was accepted. The
  path and block index are reported.
- `InvalidRecoveryCode`: a typed recovery code failed format or checksum checks, before any
  decryption.

## Nonce budget

Content nonces are random 96-bit values, one per block write. The birthday bound for random
96-bit nonces under one key is about 2^32 writes, and collisions there are catastrophic for
GCM. The limit below is a policy, not yet enforced in code:

- **Soft limit: 2^31 block writes per content key.** Above this, the UI should recommend a
  re-key (`FsVault::rekey`).
- **Hard limit: 2^32 block writes per content key.** The vault refuses further writes until
  it is re-keyed.

The write count per key must be persisted for enforcement. That is tracked as a follow-up in
`todo.md`.

## Known gaps

- **Crash consistency.** A multi-block write that is interrupted can leave a file whose last
  record was re-sealed with `is_last = false` before the new last record exists. The result is
  a `Corrupt` error on read, not silent data loss, but the file is damaged. The fix is a
  write-ahead journal, which is not implemented.
- **Memory.** Plaintext is zeroized in the file layer. Caller-supplied buffers and the OS
  pagefile are not covered. Page locking is platform-specific and is tracked under Phases 3
  and 4.
