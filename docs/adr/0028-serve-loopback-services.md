# 0028. Serve: mesh ports forwarded to services on loopback

- Status: accepted
- Date: 2026-11-22

## Context

Some services listen only on `127.0.0.1` and refuse any other address: a web app whose public mode binds loopback so that only a reverse proxy on the same machine reaches it, an admin console, a development server. To reach such a service from the mesh (for example from the Edge on another machine), the user runs a forwarder of their own on the machine: a small program that listens on the mesh address and copies each connection to `127.0.0.1`. It is one more service per port to install, keep running and secure, and it decides by itself who may connect.

How comparable products do it:

- **Tailscale** (v1.104.7, commit cbc74fe48ef1) has `tailscale serve`. Its configuration is kept on the node and set through the local API by root or the operator user; the control plane does not set it. With a kernel TUN, netstack takes over only packets to served ports (`shouldProcessInbound`, `ShouldInterceptTCPPort` in `wgengine/netstack` and `ipn/ipnlocal`), terminates the TCP connection in gVisor and dials the backend with the system dialer (`tcpHandlerForServeTCP`, a 10-second dial timeout); a bare port expands to `127.0.0.1:<port>` (`ExpandProxyTargetValue` in `ipn/serve.go`). The backend therefore sees connections from `127.0.0.1`; a PROXY protocol header can be added per port, and the HTTP modes add `X-Forwarded-For` and `Tailscale-User-*` identity headers. Who may connect is decided by the tailnet policy, as for any port. In userspace networking mode every port the policy allows reaches loopback.
- **NetBird** (v0.83.2): `netbird expose` publishes a service through NetBird's public reverse proxy to the peer's NetBird address; forwarding mesh traffic to the peer's loopback in netstack mode is off by default and described as a security risk.
- **Nebula** (v1.12.0) has no such forwarding: a service reached over Nebula listens on the Nebula address or on all addresses.

## Decision

1. **Declared in the signed node policy**: a machine's node policy lists the TCP ports it serves (`serve`, at most 16). The user sets them with `nett site serve <machine> <port>/tcp...`, and `--none` removes them (site.md section 5.3). Adding a port widens what the mesh can reach on that machine, so it is signed like every other change to the node policy; the Hub only forwards it.
2. **The mesh forwards**: for each served port it listens on this machine's mesh addresses, bound to the mesh interface (`SO_BINDTODEVICE` on Linux, `IP_BOUND_IF` on macOS), and accepts only connections whose peer address is in the mesh prefixes. Each accepted connection is copied unchanged to `127.0.0.1` on the same port: plain TCP, with no PROXY protocol header and no HTTP headers.
3. **Access rules decide who connects**, as for every other port on the machine (mesh.md section 12): the filter runs before the connection reaches the listener, members need a rule, and the user's devices reach it by default (ADR 0023).
4. **The service sees `127.0.0.1`**: it cannot tell connections from the mesh apart from local ones. A service that grants local connections extra trust, such as skipping authentication for `127.0.0.1`, is not to be served; `nett site serve` says so when a port is added.
5. **Bounds** (hard rule 14): 256 forwarded connections per machine, beyond which a new connection is closed at once; 8 KiB of buffer in each direction of a connection; 10 seconds to connect to the service, as in Tailscale; TCP keepalive on both sides closes a connection whose peer has gone (60 seconds idle, then 10-second probes, 3 lost). An idle connection whose peers are still there stays open: a WebSocket may be idle for hours.

## Rationale

- **The mesh already listens on mesh addresses** (DNS and probes, hard rule 2), and it alone sees both the access rules and the mesh interface. A forwarder there needs no new service, account or system setting (release.md section 8 is unchanged) and works the same on every platform: kernel WireGuard and the userspace data plane on Linux, macOS, Synology DSM and the container (whose loopback is that of the container).
- **Bound to the mesh interface and checked by peer address**: the mesh address is a local address, and a host on the LAN can send a packet to it through another interface. Linux accepts such a packet by default (weak host model), and macOS drops it only while IP forwarding is off (`ip_input_check_interface` in XNU xnu-12377.121.6, whose default hybrid check covers utun addresses only when not forwarding); proxy and virtual machine apps turn forwarding on. `SO_BINDTODEVICE` keeps such connections away from the listener on Linux. On every platform a peer outside the mesh prefixes is refused, and a forged mesh source cannot complete the TCP handshake, because the reply to a mesh address is routed into the mesh interface and encrypted to the member that owns it.
- **Signed instead of local**: Tailscale keeps serve on the node because a tailnet's administrator and a node's owner can be different people. In nett one user signs the whole site, and `nett site` is the one place that shows what each machine exposes. A compromised Hub cannot add a served port, and nett-node needs no new local interface to change what the mesh listens on.
- **Same port only**: the service and the forwarder bind different addresses, so they share the port number without conflict, and the access rule names the port the service has. A different local port, PROXY protocol and HTTP modes can be added when a service needs them; HTTP headers are application work, which nett leaves to the Edge (ADR 0019).

## Alternatives considered

- **Destination NAT to `127.0.0.1`** (nftables on Linux, a `pf` anchor on macOS): the service would see the real mesh source. On Linux it needs `route_localnet=1`, which makes the machine's whole loopback range reachable from every interface unless further rules close it (the class of CVE-2020-8558); on macOS it needs `pf` rules shared with other apps. Both are system settings to place and remove, and differ by platform.
- **Configuration on the machine, as in Tailscale**: needs a local way to change what the mesh listens on and a file to keep it in, and the site would not show it.
- **A separate low-privilege forwarder process**: one more service on every machine that serves, for a listener that is reachable only from the mesh, as DNS is.
- **Bind the service to the mesh address instead**: not possible for the services in question, which refuse any address but loopback.

## Consequences

- Hard rules 2 and 7 name serve: the mesh listens on mesh addresses for DNS, probes and served ports, and a served port is the one way mesh traffic reaches a service from a loopback address.
- The node policy gains the `serve` field (auth.md section 10.5, api-resources.md section 5.2); `nett site serve` sets it (site.md section 5.3); the mesh forwards (mesh.md section 12.1).
- A served port that cannot be bound (another program holds it on all addresses) is retried like the DNS responder and listed as a problem in `nett status`; the rest of the mesh is unaffected.
- The lab has a `serve` scenario: a served loopback service is reachable from a member a rule allows and not from one it does not.
