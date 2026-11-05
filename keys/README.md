# 发布签名公钥 · Release signing keys

中文 · [English](#english)

nett 的官方发布包用 minisign（Ed25519）签名（[ADR 0020](../docs/adr/0020-release-signing.md)）。官方构建嵌入下面两把公钥：主钥匙用于日常签名；备用钥匙离线保存，只在需要更换主钥匙时使用。

| 钥匙 | 钥匙 ID | 公钥 |
|---|---|---|
| 主钥匙 | `16CDF76C9920EED7` | `RWTX7iCZbPfNFjZyatAd63Nn+oMFXVO4BG9Hy6FjCuu3+LgM3/A0RMLv` |
| 备用钥匙 | `4185F09F2A568164` | `RWRkgVYqn/CFQXI7FbeOzPl+eFJ84JL+0MdMMLYYyho6z/Oji5Jt/Brn` |

手动核对一个发布包（签名文件为同名的 `.minisig`）：

```bash
minisign -V -p keys/nett-release-primary.pub -m <文件>
```

## English

Official nett release packages are signed with minisign (Ed25519). Official builds embed the two public keys above: the primary key signs releases; the backup key is kept offline and is used only to replace the primary key.

To verify a release package by hand (the signature is the `.minisig` file with the same name):

```bash
minisign -V -p keys/nett-release-primary.pub -m <file>
```
