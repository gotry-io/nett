# 0006. Identity model and passkey signing authorization

- Status: accepted; the passkey part is deferred, signing is first done by the signing tool on the user's computer, see 0024
- Date: 2026-10-12

## Context

The Hub manages all nodes. If the Hub could decide on its own to enable a high-risk capability (such as the mesh) on any node, then once the Hub is compromised, every machine falls. At the same time, the system must let external programs such as scripts (including AI) call the API.

## Decision

**Identity types**

| Identity | Authentication |
|---|---|
| User | passkey (WebAuthn) + recovery key; short-lived session cookie (HttpOnly, SameSite=Strict) |
| API token | permission scope + expiry + revocable; fixed prefix to ease leak scanning; the server stores only the hash, and the plaintext is shown once |
| node | one-time enrollment token -> X25519 identity key; inner Noise mutual authentication and end-to-end encryption within the WebSocket |
| Phone device | device credentials |

**Authorization**: every request is attributed to an identity, checked against permission scopes and policy before execution, and written to the audit log.

**Signing authorization**: changes that raise privileges (enabling a module, adding a device, high-risk operations) must be signed by the user with a passkey: the hash of the change content is used as the WebAuthn challenge. The Hub only forwards the signed policy, and the node applies it only after verifying the signature. Lowering privileges can be issued by the Hub directly. Policies carry an increasing version number to prevent replay. A node can also set local hard prohibitions that neither the Hub nor a signature can override. The mesh member table (member public keys, advertised routes, access rules) likewise consists of signed artifacts, see ADR 0014.

**A token can only propose high-risk changes, not approve them.**

## Rationale

- When the Hub is compromised, the attacker cannot forge the user's signature and cannot exceed their authority (the precondition is in the note on console pages under "Consequences");
- A passkey can sign in the browser, without depending on a dedicated mobile app or command-line tool;
- The same mechanism serves both people and external programs such as scripts (including AI).

## Alternatives considered

- **Hub issues privileges directly**: the most convenient, but the Hub becomes a single point of failure.
- **A node-local configuration file as the sole upper bound**: secure, but every change requires logging in to the machine.
- **A dedicated mobile Secure Enclave key**: slightly more secure, but unusable until the mobile app is done.

## Consequences

- The private key of a synced passkey (such as iCloud Keychain) lives on more than one device, which is an acceptable trade-off for a single-user setting;
- **Console pages are served by the Hub** (ADR 0005), and what the passkey signs is the payload hash computed by the page, so the content cannot be shown to the user. A compromised Hub can display one operation and actually request a signature for another. So "a compromised Hub cannot exceed authority" holds on the precondition that the user did not complete a signature on a compromised console. Mitigation: nodes keep every signed artifact they have accepted, and `nett trust log` lists them locally without going through the Hub; an approval tool independent of the Hub is listed as a future enhancement (auth.md section 2);
- A recovery path must be provided: at initialization an offline recovery key is generated, and registering a second passkey is recommended, so that losing a device does not make authorization impossible.
