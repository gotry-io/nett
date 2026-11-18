# The Hub's image, ghcr.io/gotry-io/nett-hub: the statically linked nett-hub of a release and the CA
# certificates it uses to fetch releases, nothing else. The release workflow builds it for
# linux/amd64 and linux/arm64 from the signed programs, placed next to this file as nett-hub-amd64
# and nett-hub-arm64 with ca-certificates.crt. The Hub needs no privileges: the Compose example
# drops all capabilities and mounts the root file system read-only; data lives in the /data volume,
# where the Hub also keeps the versions it upgrades to.
FROM scratch
ARG TARGETARCH
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --chmod=0755 nett-hub-${TARGETARCH} /usr/local/bin/nett-hub
VOLUME /data
ENTRYPOINT ["/usr/local/bin/nett-hub"]
# Listens on the container network behind Caddy from the same Compose file; not published on the host
CMD ["serve", "--data", "/data", "--listen", "0.0.0.0:8480"]
