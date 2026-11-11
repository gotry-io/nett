# Release and Installation

- Status: draft
- Phase: M1 (the release workflow and Homebrew items of roadmap M1 "Installation")

## 1. Goals

After a version tag is pushed, CI builds `nett` for each platform, signs it with the project's release key (ADR 0020), publishes a GitHub Release, and updates the Homebrew formula and the project website. The computer that runs the signing tool is installed and upgraded with Homebrew; other machines, Linux and macOS alike, are installed with the install script on the project website (section 6). The enrollment command after joining the Hub and automatic node upgrades are described in hub.md.

## 2. Versions and artifacts

- Version numbers follow semantic versioning and equal `version` in the workspace `Cargo.toml`; tags are written `v<version>`, and the release workflow fails when the two differ. User-visible changes are recorded in `CHANGELOG.md`;
- Each target platform has one archive `nett-<version>-<target>.tar.gz`, containing `nett`, `LICENSE-MIT` and `LICENSE-APACHE`:

| Target | Use |
|---|---|
| `aarch64-apple-darwin`, `x86_64-apple-darwin` | macOS native member (install script) and signing tool (Homebrew) |
| `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` | Linux servers (statically linked) and images for container members |

- Each archive has a `.minisig` of the same name; `SHA256SUMS` lists the hashes of all archives and is signed the same way. Users can verify with `minisign -V -p keys/nett-release-primary.pub -m <file>`.

## 3. Release workflow

`.github/workflows/release.yml`, triggered by `v*` tags (tags are protected by a ruleset, ADR 0020). Each job is granted only the minimum permissions it needs, and third-party actions are pinned to commit hashes:

1. **Build**: native runners for each platform (macOS arm64, Linux x86_64 and arm64) build the release version and package it, and check that the tag matches the workspace version;
2. **Sign**: runs in the `release` environment, receives only the archives produced by the build jobs, downloads a pinned version of minisign whose hash has been verified, signs with the primary key and generates `SHA256SUMS`; it does not check out code or install other dependencies;
3. **Publish**: creates the GitHub Release and uploads the archives, signatures and `SHA256SUMS`; the release notes are the section of `CHANGELOG.md` for this version;
4. **Update the formula**: fills in the version, URLs and hashes according to `packaging/homebrew/nett.rb` (the formula template, the single source) and pushes to `Formula/nett.rb` in `gotry-io/homebrew-tap`, using the repository secret `TAP_PUSH_TOKEN` (write access to the tap repository only);
5. **Update the project website**: verifies the `SHA256SUMS` produced by the signing job, fills in the version and the hashes of the per-platform archives according to `packaging/install.sh` (the install script template, the single source), and deploys it together with this version's archives to `nett.gotry.io` (section 6). The deployment tool `wrangler` is version-pinned, and its configuration is `packaging/site/wrangler.jsonc`; the secrets `CLOUDFLARE_API_TOKEN` (which can only edit this account's Workers and the gotry.io Worker routes) and `CLOUDFLARE_ACCOUNT_ID` live in the `site` environment, which only `v*` tags can use: a new machine trusts this website on first install, so the secrets that deploy it are protected like the signing keys.

## 4. macOS: Homebrew and the mesh service

- The computer that runs the signing tool installs the command line (`nett site` etc.) with `brew install gotry-io/tap/nett`, uses it with the user's privileges, and upgrades it with `brew upgrade`. The formula's install notes, like the output of the nett command, are English only (architecture.md section 14.3). Other Macs use the install script (section 6) to install to `/usr/local/bin/nett`, and the following steps are the same;
- The mesh service of a native member runs as root (design/userspace.md section 6.3). Homebrew directories are writable by ordinary users; if the root service ran the program there directly, a malicious program running with the user's privileges could replace it and obtain root and the mesh private key at the next start. The service therefore runs a root-only copy:
  - `sudo nett install`: one command completes the installation; all paths are fixed and the user does not need to know them:
    - In `/Library/Application Support/nett/` (directory owned by root, mode `0700`) it generates the mesh private key and the identity private key (`0600`; existing ones are reused, and private keys never leave the machine). When the machine has no desired state yet, it prints the line of public keys needed by `nett site add --keys`; when it already has one, it only reports the result;
    - It copies the running `nett` to `nett` in this directory, and writes the launchd configuration (`/Library/LaunchDaemons/io.gotry.nett.mesh.plist`) and the log rotation configuration (`/etc/newsyslog.d/nett.conf`); the contents of the configuration files are defined only in code;
    - It imports the desired state: in `nodes/` of the site directory of the user running `sudo` (site.md section 8, default `~/.config/nett`), it finds the one for this machine (the mesh public key in this node's admission material matches this machine's mesh private key) and copies it in. When the signing tool is not on this machine, or the site is elsewhere, `--config <desired.json>` specifies it, with the same check. Only regular files are read, with a size limit. The recovery key in the site directory is protected only by this user's privileges anyway, and a program able to rewrite this directory can already sign, so importing from here does not widen the risk;
    - It starts the service when there is a desired state. When the service is already running: if the program changed (after an upgrade), it restarts the service so that it uses the new copy; if only the desired state changed, it has the service reload through the local interface (the same request as `nett reload`, status.md section 4.1) without restarting or interrupting connections, and shows whether it was accepted; if neither changed, it does nothing. When there is no desired state yet, it only installs and explains the next step;
  - First installation: `sudo nett install` → on the computer that holds the site, `nett site add <name> --keys "<the printed line>"` (site.md section 4) → run `sudo nett install` again. After the desired state is updated, run the same command;
  - Joining the Hub: `sudo nett install <token>` (hub.md sections 3.5 and 7) additionally writes `io.gotry.nett.node.plist`, which runs `nett node` from the same copy; from then on the desired state is received from the Hub by it, and `sudo nett install` no longer imports from the site directory and does not accept `--config`;
  - Upgrade: run `sudo nett install` after `brew upgrade nett` (or after running the install script again). After joining the Hub, nett-node's signed automatic upgrade takes over (ADR 0020, hub.md section 9 H3);
  - `sudo nett uninstall`: stops the service and deletes the copy and the configuration; keys, desired state, the trust store (`state/`, mesh.md section 4.2) and the Hub configuration are kept;
  - Starting and stopping the service calls `/bin/launchctl`, with arguments passed as an array and a timeout (hard rules 9, 14);
- Installation and each upgrade need one sudo each. The way without sudo is an app with a Network Extension, which needs signing with an Apple developer account (the M3 client in ADR 0018).

## 5. Linux

Servers install `nett` with the install script (section 6), or download the matching archive, verify the signature and extract it; `sudo nett install` places it in `/usr/local/bin` (it does not copy when it is already there), writes the systemd unit and starts it (hub.md section 7): the unit is a file in `packaging/systemd/`, embedded at compile time; calls to `systemctl` pass arguments as an array and have a timeout. The image for container members is built with the `aarch64` or `x86_64` static version (`packaging/container/`). The Hub runs only on Linux: `nett-hub-<version>-<target>.tar.gz` is published together with the `nett` archives and signed the same way, and the image and the Compose example are in `packaging/hub/`.

## 6. Install script and project website

The one-line command on a new machine (hub.md section 3.3) begins with `curl -fsSL https://nett.gotry.io/install.sh | sh`.

- **Website**: `nett.gotry.io` is the project home page, hosted on Cloudflare: a Worker with only static files is attached to this custom domain, and the DNS records and certificate are managed by Cloudflare. Its content is deployed only by the release workflow (section 3): the home page, `install.sh` and the archives of the latest version (`dl/nett-<version>-<target>.tar.gz`). The website is neither on the user's own machines nor on the Hub;
- **The script installs only `nett`**: it detects the system (Linux, macOS) and architecture (x86_64, aarch64/arm64), downloads the matching archive, verifies it against the SHA-256 written in the script (`sha256sum` or `shasum -a 256`), extracts it to a temporary directory, and places it at `/usr/local/bin/nett` (owned by root, `0755`; uses `sudo` when not root). When `/usr/local/bin/nett` is a Homebrew link, it stops and says to use `brew upgrade`. The script does not read a token, connect to the Hub or write configuration; enrollment and the service are completed by the following `sudo nett install`;
- **Trust**: the first installation trusts the project website (over HTTPS) and the code hosting and CI behind it, the same as Homebrew trusting the formula and the install scripts of other mesh products (ADR 0020). The hash in the script prevents the archive from being replaced alone, in transit or on the website; if the website itself is tampered with, newly installed machines can be taken over, while machines already installed are not affected, and upgrades still verify the release signature;
- The script is written in POSIX `sh` and uses only `uname`, `curl`, `tar`, `mktemp`, `install` and hash commands; on error it says which step failed and why, and exits non-zero.
