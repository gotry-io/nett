# 容器内成员（ADR 0016，design/local-signing.md 第 6 节）：镜像中只有一个静态链接的 nett（musl）。
# 构建：把对应架构的正式构建放在本目录，命名为 nett，然后 `docker build -t nett .`
FROM scratch
COPY nett /nett
ENTRYPOINT ["/nett"]
CMD ["mesh", "--config", "/etc/nett/desired.json", "--key", "/etc/nett/mesh.key"]
