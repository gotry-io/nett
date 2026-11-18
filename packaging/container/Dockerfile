# nett's image, ghcr.io/gotry-io/nett: the statically linked nett of a release and the CA
# certificates it uses to fetch new versions, nothing else. The release workflow builds it for
# linux/amd64 and linux/arm64 from the signed programs, placed next to this file as nett-amd64 and
# nett-arm64 with ca-certificates.crt.
FROM scratch
ARG TARGETARCH
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --chmod=0755 nett-${TARGETARCH} /usr/local/bin/nett
# The member's keys, configuration and the versions it upgrades to live in this volume
ENV NETT_STATE_DIR=/var/lib/nett
VOLUME /var/lib/nett
ENTRYPOINT ["/usr/local/bin/nett", "container"]
