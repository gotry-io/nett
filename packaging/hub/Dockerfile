# nett-hub: the image holds only the statically linked nett-hub (musl).
# To build: put the release build for your architecture here as `nett-hub`, then
# `docker build -t nett-hub .`. The Hub needs no privileges: the Compose example drops all
# capabilities and mounts the root file system read-only; data lives in the /data volume.
FROM scratch
COPY nett-hub /nett-hub
VOLUME /data
ENTRYPOINT ["/nett-hub"]
# Listens on the container network behind Caddy from the same Compose file; not published on the host
CMD ["serve", "--data", "/data", "--listen", "0.0.0.0:8480"]
