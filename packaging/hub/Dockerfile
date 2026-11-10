# Hub（design/hub.md 第 8 节）：镜像中只有一个静态链接的 nett-hub（musl）。
# 构建：把对应架构的正式构建放在本目录，命名为 nett-hub，然后 `docker build -t nett-hub .`
# Hub 不需要任何权限：Compose 中去掉全部能力、根文件系统只读，数据在 /data 卷中。
FROM scratch
COPY nett-hub /nett-hub
VOLUME /data
ENTRYPOINT ["/nett-hub"]
# 在容器网络中监听，由同一个 Compose 中的 Caddy 转发；不发布到宿主
CMD ["serve", "--data", "/data", "--listen", "0.0.0.0:8480"]
