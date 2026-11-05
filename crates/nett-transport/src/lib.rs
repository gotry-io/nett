//! 传输适配进程 `nett transport`：UDP 不可用时把 WireGuard 数据包转成 TLS 传输，只经手密文（design/mesh.md 第 5.3 节）。
