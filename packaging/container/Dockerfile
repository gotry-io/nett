# A mesh member inside a container: the image holds only the statically linked nett (musl).
# To build: put the release build for your architecture here as `nett`, then `docker build -t nett .`
FROM scratch
COPY nett /nett
ENTRYPOINT ["/nett"]
CMD ["mesh", "--config", "/etc/nett/desired.json", "--key", "/etc/nett/mesh.key", "--state", "/etc/nett/state"]
