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
GCM. The limits below are enforced in code (`core/src/budget.rs`):

- **Soft limit: 2^31 block writes per content key.** The session reports `soft_reached`, and
  the app recommends a re-key (`FsVault::rekey`, Settings > Rebuild vault keys).
- **Hard limit: 2^32 block writes per content key.** Further writes fail with
  `WriteLimitReached` until the vault is re-keyed. Reads still work.

The count is kept in `vault.conf` as a *ceiling*. The count never goes above the stored value.
The ceiling is raised by 2^20 before writes pass it, and that update is synced first. A restart
starts from the stored ceiling. So the count can be a little high after a restart (by up to one
chunk) but never low, and a crash cannot reset the budget. Re-keying starts a new count. The
count is per vault, shared by all files in the session.

Vaults written before this counter existed have no ceiling, so they start at 0. No release has
shipped with such vaults.

## Known gaps

- **Crash consistency (handled for writes, with limits).** Writes that change existing records,
  and truncations, run under a write-ahead journal (`core/src/journal.rs`). Before the data
  changes, the original bytes of the affected records (and of the whole tail, for a cut) are
  saved to `<record>.journal`. The journal is written to a temporary file and renamed into place,
  so it is either absent or complete. It is removed only after the new data is synced. A write
  that returns an error is undone at once. After a crash, the next open, stat, rename or remove
  of that file restores the saved bytes and the old length, so the file reads as it did before
  the interrupted write. A write that did not return is treated as not having happened.
  - Creating a file is atomic. The header goes to a temp file, which is hard-linked into place,
    so a crash leaves either no entry or a complete one. A cut (`truncate` to a shorter length)
    saves the whole tail, so its journal is as large as the data removed. Each `write_at` call
    fsyncs twice (journal, then data). The cost was measured and accepted; see `docs/performance.md`.
  - The journal does not defend against an attacker who can write to the vault folder. Such an
    attacker can already replace files with older valid versions.
  - Tests use `failpoint` to simulate a crash (journal left behind) and an ordinary error
    (undone at once). They cover extend, shrink, error mid-write, listing, and stale journals.
- **Memory.** Plaintext and key bytes are zeroized. Each key sits in its own page, which the
  platform layer pins in RAM (`VirtualLock` on Windows, `mlock` on Linux) when it can. If the
  OS refuses, the app reports `keys_locked = false`. Caller-supplied buffers are not covered.
  Nothing stops the OS from paging out memory that was never pinned.
