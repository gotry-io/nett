# 0020. Release signing: two keys, primary and backup, with the public keys as build parameters

- Status: accepted
- Date: 2026-11-05

## Context

Nodes install only packages that pass verification against the project's release signature, and automatically accept packages with a higher version (ADR 0012). nett-node runs as root, so the release private key is the most impactful key in the whole system:

- If it is stolen, an attacker can sign a "new version" that every node with automatic upgrade enabled will install;
- If it is lost, the project can never again issue upgrades that nodes accept automatically, and machines must be reinstalled one by one;
- With only one public key embedded in `nett`, there is no remedy for either leakage or loss.

nett is an open-source project: anyone can compile it themselves, and those who do not trust the project's keys need to be able to substitute their own.

## Decision

- **The private keys are held by the project maintainers**: official release packages are signed by the project's release private key. All installations carry only public keys and can verify but not sign.
- **Public keys are build parameters**: official builds embed the project's public keys; people who compile it themselves replace them with their own public keys at build time, sign with their own private keys, and distribute through their own Hub. Development builds embed development public keys, and official builds do not accept packages signed with development keys.
- **Two keys, primary and backup**: every build embeds two public keys. The primary key is used for everyday signing; the backup key is kept only offline and is not used normally. Nodes accept packages signed by either key. When the primary key is leaked or lost, the backup key signs a new version that embeds a new pair of primary and backup public keys; once a node has installed it, it no longer accepts signatures from the old primary key.
- **Upgrades are automatic by default**: nodes automatically accept packages signed by the project with a higher version, pushed by the Hub through the `release` partition (low risk); a rollback can only go back to the version this machine last installed; other downgrades require a user signature (`release_override`, design/auth.md section 11.3).
- **Signature format**: Ed25519, in the minisign format. Nodes need only a very small verification-only library; the signature carries a key ID, from which the node selects the public key; users can also check release packages manually with the `minisign` command.
- **CI signs automatically, with no human involved in releases**:
  - The primary private key is stored in CI's `release` environment, which only `v*` version tags may use; version tags are protected by a ruleset, and only repository administrators can create, modify and delete them;
  - Signing is a separate job in the release workflow: it receives only the files produced by the build job, runs only a signing tool of a pinned version with a verified hash, installs no other dependencies and uses no third-party actions; the build job cannot get the private key;
  - Third-party actions in the workflow are pinned to commit hashes, and each job is granted only the minimum permissions it needs;
  - The release page publishes the hash and signature of every file;
  - Version tags are protected; the maintainers' code hosting accounts have two-step verification enabled (hardware key or passkey).
- **Offline backup**: the primary private key also has a local offline backup; the backup private key is kept only offline and never enters CI.
- The two public keys are placed in the repository's `keys/` directory and also published on the project homepage, so users can compare them.
- **First installation trusts the project website**: a new machine installs `nett` with the install script on the project website `nett.gotry.io` (design/release.md section 6); the script checks the archive against the stated hash, but does not check the release signature: the machine does not yet have a trusted verification tool. The website is deployed by the release workflow and is not on the Hub, so a compromised Hub cannot replace the installed program. Every later upgrade checks the release signature as usual.

## Rationale

- Maintainers holding the private key with installations carrying only public keys is the usual way open-source projects distribute official binaries (for example Syncthing's automatic upgrades and Linux distribution package repositories);
- With public keys as build parameters, people who compile it themselves do not have to trust the project;
- Releases are fully automatic with no human involved (the user's choice); the signing job is separate from the build, so a compromised build dependency cannot get the private key;
- The backup key never enters CI: after the primary key in CI is leaked, keys can still be replaced and nodes do not need to be reinstalled;
- Automatic upgrades by default let fixes reach all nodes promptly (the user's choice).

## Alternatives considered

- **Maintainers sign locally by hand**: when the code hosting account or CI is compromised, release packages cannot be signed, but every release needs a human. The user chose CI automatic signing.
- **Sigstore keyless signing**: no private key to keep, but verification depends on Sigstore's certificate chain and public log, the verification code is heavy, and it is hard to guarantee in regions with restricted networks; a stolen code hosting account can also sign.
- **Require the user to approve every version by default** (install only with project signature plus user signature): even a stolen project key could not reach the user's machines, but every upgrade needs a signature, and without approval the node stays on the old version. The user chose automatic by default.
- **Embed only one public key**: when it is leaked or lost, machines can only be reinstalled one by one.

## Consequences

- **Residual risk**: if a maintainer's code hosting account is stolen, or someone can push protected version tags or change the release workflow, they can use the primary key to sign a version that all nodes with automatic upgrade enabled will install, until a new version signed by the backup key replaces the primary key. An optional "upgrades need user approval" mode can be added later;
- **Residual risk of the first installation**: if the project website, its DNS or its hosting account is compromised, machines newly installed in that period are taken over; machines already installed are unaffected. These accounts also have two-step verification enabled;
- The build script accepts the release public keys as parameters; the release handbook documents the configuration of the release workflow and the steps for replacing keys with the backup key;
- The Home Assistant OS add-on is upgraded by HA and does not go through this mechanism (ADR 0017).
