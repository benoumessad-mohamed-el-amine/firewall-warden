# Installing warden

> [!IMPORTANT]
> **Not distributed on npm, and won't be.** `@askalf/warden` on the registry is a deprecated pointer stub that throws on import: npm's automated content scan reads warden's detection-signature corpus as malware, and an allowlist review was declined. We won't obfuscate or split those signatures to pass a scanner — that's detection evasion, and it would destroy the plain-source auditability that makes a security tool worth trusting.

Install from the Sigstore-signed GitHub release — **verify provenance first**, then install globally so the `warden`, `warden-hook`, `warden-mcp`, and `warden-serve` CLIs land on your PATH:

```sh
gh release download --repo askalf/warden --pattern 'warden.tgz*'
gh attestation verify warden.tgz --repo askalf/warden --bundle warden.tgz.sigstore.json   # non-zero unless this exact repo built it
npm i -g ./warden.tgz
```

Or the one-line global install (same signed artifact, verification handled for you):

```sh
curl -fsSL https://ownyourstack.sprayberrylabs.com/warden.sh | sh
```

```powershell
powershell -c "irm https://ownyourstack.sprayberrylabs.com/warden.ps1 | iex"
```

Every tarball is packed in CI and signed with keyless Sigstore. A security tool shouldn't ask for blind trust — that's why the verify step comes *before* the install, not after.

> Git installs (`npm i --allow-git github:askalf/warden`) still work but carry **no attestation** — you're trusting the fetch. npm ≥ 12 [blocks git dependencies by default](https://github.blog/changelog/2026-06-09-upcoming-breaking-changes-for-npm-v12/) (supply-chain hardening warden applauds); the tarball route needs no flags.

Policy lives in `warden.config.json` (`tool(glob)` rules, Claude-Code style — see [`warden.config.example.json`](../warden.config.example.json)), or run `warden init` to generate one from your project.
