# Release signing

The release checksum manifest (`SHA256SUMS`) is signed with a **minisign** key
so consumers without `gh` can verify it (see `packaging/aur/README.md`).
Sigstore build-provenance attestation (`gh attestation verify`) is the primary
trust root; the minisign signature is the fallback for the manifest.

## One-time setup (the owner, before the first tag)

1. Generate a passwordless keypair:

   ```
   minisign -G -p packaging/signing/minisign.pub -s ~/.minisign/minisign.key
   ```

   Leave the password **empty** — CI signs headless and cannot prompt. Keep the
   secret key (`~/.minisign/minisign.key`) out of the repo and out of every
   commit.

2. Commit `packaging/signing/minisign.pub` (it is public).

3. Store the secret key as a repository Actions secret:

   ```
   base64 < ~/.minisign/minisign.key
   ```

   → paste the output as the **`MINISIGN_SECRET_KEY`** secret.

The release workflow (`.github/workflows/release.yml` → `publish`) decodes that
secret, signs `SHA256SUMS` → `SHA256SUMS.minisig`, and publishes `minisign.pub`
beside the manifest. Verification:

```
minisign -Vm SHA256SUMS -p minisign.pub
```
