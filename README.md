# m65-field-jacket

> ⚠️ **Very early.** Expect rough edges, breaking changes, and missing
> features. Don't store anything you can't afford to lose.

`mfj` - local-first secrets management for developers.

Encrypts secrets with [age](https://age-encryption.org) and commits the ciphertext to git. X25519 identities; per-pocket data-encryption keys so group membership changes don't require re-encrypting every secret.

## Build

```
cargo build --release
```

The binary is `mfj`.

## Quick start

```
mfj identity init me --set-default
mfj pocket init shared
mfj set env shared API_KEY sk-...
mfj get shared API_KEY
```
