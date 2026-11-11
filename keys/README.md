# Release signing keys

Official nett release packages are signed with minisign (Ed25519) ([ADR 0020](../docs/adr/0020-release-signing.md)). Official builds embed both public keys below: the primary key signs releases; the backup key is kept offline and is used only to replace the primary key.

| Key | Key ID | Public key |
|---|---|---|
| Primary | `16CDF76C9920EED7` | `RWTX7iCZbPfNFjZyatAd63Nn+oMFXVO4BG9Hy6FjCuu3+LgM3/A0RMLv` |
| Backup | `4185F09F2A568164` | `RWRkgVYqn/CFQXI7FbeOzPl+eFJ84JL+0MdMMLYYyho6z/Oji5Jt/Brn` |

To verify a release package by hand (the signature is the `.minisig` file with the same name):

```bash
minisign -V -p keys/nett-release-primary.pub -m <file>
```
