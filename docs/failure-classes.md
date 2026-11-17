# Failure classes

Every problem fixed in nett belongs to a class: a rule that must hold, which the same mechanism can break in more than one place. This page is the one list of those classes. Each one says what must hold, how it breaks, where the design holds it, and which tests guard it. Fixing one place and leaving the others leaves the class open, so a fix starts from its class (CLAUDE.md, "Handling problems").

- **Adding**: a fixed problem gets a test that reproduces it, and the test is listed under the problem's class. A problem whose mechanism no class covers starts a new class. Where the problem was found and when goes in the CHANGELOG and the commit, not here;
- **Converging**: when a fix adds a place to a class, check whether one general mechanism can replace the class's places. Before each minor version (0.4.0, 0.5.0, ...) every class is reviewed: two classes that share a mechanism become one, a rule enforced case by case moves to one mechanism, a guard that a broader one covers goes, and each "Not yet guarded" item gets a test or a reason;
- **Checked**: CI checks that every test named here exists and that every lab scenario and CI step named here runs in CI (`scripts/check-failure-classes.sh`). A guard that does not run does not guard.

Guards are written as `<crate>:<test function>`, `lab:<scenario>` (a `nett-lab run` scenario, design/prototype.md section 6), or `ci:<step name>` (a step of a CI workflow).

## 1. A measurement takes the path of what it judges

**Holds**: every measurement that chooses a path is taken on the port, transport and route the traffic it judges uses, and a reply counts only when it comes back the way its probe went. A path's state shown to the user is the measurement of that path as it carries traffic.

**Breaks when** a probe leaves from another socket than the tunnel (a network can treat ports differently, mesh.md section 7.1); when one end's probes stand in for a leg only the other end sees (the leg from a relay to the peer); when a value measured before a switch is shown after it.

**Where it holds**

- Probes of direct candidates and of UDP relays leave from the WireGuard port, and replies come back to it; probes of TLS relays travel inside the connection the tunnel uses (mesh.md section 7.1);
- A path through a relay that failed while the relay still answered is broken beyond the relay; the relay counts as recovered only when the peer reports its leg without loss in a report covering the time since, and a relay the peer never reached is reported lost (mesh.md section 8.2);
- The current candidate shows the tunnel's measurement (status.md section 6).

**Guards**

- `nett-mesh:a_relay_the_followers_wireguard_port_cannot_reach_is_not_used`
- `nett-mesh:a_break_beyond_a_relay_moves_to_another_relay`
- `nett-mesh:a_relay_that_never_answered_is_reported_lost`
- `nett-mesh:the_current_candidate_shows_the_tunnels_measurement`
- `lab:wgport`, `lab:relay-far-leg`, `lab:relay-port-block`

## 2. What is derived from a source follows it when it changes

**Holds**: whatever is computed, bound, opened or started from configuration or from the program is redone when that source changes, while running and across restarts, and redone until it succeeds when setting it up failed: what made it fail, such as a device the system provides later, can pass with no source changing. A saved or learned copy never outranks a newer source.

**Breaks when** something is set up once at startup and the configuration changes later; saved state is restored over an assignment that changed while it was saved; a learned value is preferred to a configured one that has since changed, and the event that would teach the new value never comes; a helper process or a service manager keeps running the program or the unit it started with; a counter goes away with the artifact that carried it.

**Where it holds**

- A relay binds a `public` member where a changed assignment puts it, and restores a saved binding only while the assignment still gives the address it gave when saved; the relay's own machine stays on loopback over saved and learned bindings (mesh.md sections 5.1 and 5.2);
- On Linux, the probes on the WireGuard port move with the port when it changes (mesh.md section 5.5);
- A desired state whose application hit a data plane failure is applied again, after 1 second and then twice as long each time up to 30 seconds, until it succeeds; the probe sockets and the DNS responder follow an interface that comes up later, and are retried the same way (mesh.md section 15);
- After an upgrade settles, and after `sudo nett install` brings a new program, the relay and the transport adapter restart on it; a changed launchd configuration is unloaded and loaded again (release.md sections 4 and 7);
- A transport's loopback port that failed to open is opened again with backoff, without waiting for a configuration change (mesh.md section 5.3);
- The version of a machine's advertised routes keeps counting after all of them are removed (site.md section 5.2).

**Guards**

- `nett-relay:a_member_whose_assigned_address_changed_is_bound_there`
- `nett-relay:a_saved_binding_yields_to_a_changed_assignment`
- `nett-relay:the_relays_own_machine_stays_on_loopback`
- `nett-node:a_new_node_that_keeps_exiting_is_rolled_back` (the helpers restart once per settled upgrade)
- `nett-transport:a_port_held_by_another_process_is_opened_once_free`
- `nett-mesh:a_failed_interface_comes_up_on_a_retry`
- `nett-mesh:a_new_desired_state_replaces_a_pending_retry`
- `nett-site:advertised_routes_keep_counting_after_they_are_removed`
- `lab:port-change`, `lab:relay-restart`

**Not yet guarded**: the restart of the helpers by `sudo nett install` with a new program; the unload and load of a changed launchd configuration.

## 3. A switch acts on evidence that covers its reason

**Holds**: a pair leaves a path only for a failure that another path can help, and returns only on evidence that covers the condition it left for. A hold waits on the improvement, not on one candidate. A re-handshake counts as done only when WireGuard confirms it.

**Breaks when** queueing is read as loss (every path shares the bottleneck); a lossy path answers a few probes and looks recovered; two equal candidates take turns at being the best and each turn starts a hold again; a late packet on the old path or a peer under load makes a re-handshake miss, and the miss is read as a failure.

**Where it holds**

- Late replies are queueing, not loss, and a path whose peer's packets still arrive has not failed (mesh.md sections 7 and 8.2);
- A path left while losing packets returns only once at most 2 of its last 60 probes are lost (mesh.md section 8.2);
- The 30-second holds last while some candidate qualifies, and the switch goes to the best one when they end (mesh.md section 8.2);
- After a re-handshake, completion is confirmed and the handshake repeated once on the same relay; a peer under load gets the time WireGuard's cookie retry needs (mesh.md section 8.4).

**Guards**

- `nett-mesh:stays_on_a_congested_relay_path`
- `nett-mesh:stays_on_a_congested_direct_path`
- `nett-mesh:tail_drops_while_queueing_do_not_switch`
- `nett-mesh:fails_over_when_only_the_peers_packets_arrive`
- `nett-mesh:late_tunnel_replies_keep_a_congested_path`
- `nett-mesh:a_path_left_for_loss_returns_once_its_loss_is_low`
- `nett-mesh:a_path_left_for_a_faster_relay_while_lossy_is_held_too`
- `nett-mesh:two_equally_fast_relays_do_not_restart_the_hold`
- `nett-mesh:two_equally_better_paths_do_not_restart_the_hold`
- `nett-mesh:retries_a_rehandshake_that_did_not_complete`
- `nett-mesh:retries_an_incomplete_rehandshake_only_once`
- `nett-mesh:a_completed_or_idle_rehandshake_is_not_repeated`
- `nett-mesh:only_a_handshake_after_the_rehandshake_confirms_it`
- `nett-mesh:waits_for_the_cookie_retry_when_the_peer_is_under_load`
- `nett-mesh:waits_for_at_most_two_cookie_rounds`
- `lab:congestion`, `lab:lossy-direct`, `lab:faster-relay`, `lab:wg-cookie`, `lab:wg-rehandshake`

## 4. Waits are bounded and nothing slow holds up a loop that must keep going

**Holds**: every wait has a total time limit, and a backoff starts over once things work again. A slow disk, a slow client or a flood never stalls forwarding or a server: costly work runs off the loop, and floods are capped per source before it. A process that stops lets its sessions finish and record their end.

**Breaks when** disk writes run in the forwarding loop; a time limit applies to each read instead of the whole request; every handshake is handled before any limit; a reconnect wait only grows; a command reports done while the service is still exiting; a server exits under its long-lived connections.

**Where it holds**

- nett-relay saves its state on a blocking thread, one save at a time (mesh.md section 5.2);
- The local socket gives each request and the input after it a total time limit (status.md section 4);
- The userspace data plane caps handshake messages per source and in total before the session layer (userspace.md section 4.1);
- nett-node's reconnect wait starts over after a session that outlasted the longest wait (protocol.md section 8);
- `sudo nett uninstall` waits until launchd no longer has the service;
- The Hub says goodbye to each session and waits for it to record its end before exiting (hub.md section 8).

**Guards**

- `nett-relay:a_stuck_state_write_does_not_hold_up_forwarding`
- `nett-mesh:a_slow_client_cannot_hold_the_socket_past_the_time_limit`
- `nett-mesh:handshake_floods_are_capped_per_source_and_in_total`
- `nett-mesh:over_budget_handshakes_get_no_response`
- `nett-node:reconnecting_starts_over_after_a_lasting_session`
- `nett-hub:a_stopping_hub_says_goodbye_and_records_the_disconnection`
- `nett-lab:a_sender_connects_once_its_receiver_appears`
- `ci:Full flow of sudo nett install (needs root)`

**Not yet guarded**: the wait for the site directory lock.

## 5. Platform behavior is tested on the platform

**Holds**: what nett assumes about an operating system (where a packet to the machine's own address goes, which checksums it fills, which socket options apply, how a service manager hands over credentials, what a peer in another PID namespace looks like) is tested on that system, as root where it needs root.

**Breaks when** behavior is reasoned from another platform or from documentation, and only the real system shows the difference.

**Where it holds**

- On macOS, a packet to the machine's own mesh address goes back into the utun with its checksum filled in, and a DNS query to that address is answered in the data plane (userspace.md section 4);
- On macOS, a dual-stack underlay socket sets only `IPV6_BOUND_IF`, which also binds its IPv4 traffic (userspace.md section 6.2);
- A key in the service's systemd credentials directory is accepted when others cannot enter that directory;
- The peer of a local socket in another PID namespace, which the kernel reports with PID 0, is identified by its user ID.

**Guards**

- `nett-mesh:a_packet_to_this_machines_own_address_goes_back_with_its_checksum`
- `nett-mesh:this_machines_own_dns_query_is_answered_in_the_data_plane`
- `nett-mesh:fills_in_a_checksum_the_system_left_out`
- `nett-mesh:underlay_follows_the_physical_interface_for_ipv4_too`
- `nett-mesh:a_group_readable_key_passes_only_in_the_services_credentials_directory`
- `nett-mesh:a_peer_in_another_pid_namespace_is_identified`
- `ci:utun, addresses and routes (needs root)`
- `ci:Full flow of sudo nett install (needs root)`

## 6. A mechanism some roles skip is not what all roles rely on

**Holds**: when a behavior depends on a side effect of a mechanism (probing, upgrading), every role that skips the mechanism gets the side effect another way.

**Breaks when** a role is added or changed (a follower that does not probe, a container member without an upgrader) and keeps relying on what the skipped mechanism did.

**Where it holds**

- A `dial-only` follower probes its TLS relays every 5 seconds, which keeps the standby connections authenticated (mesh.md section 5.3);
- A machine without an upgrader, such as a container member, applies a release it already runs and reports a newer one as available.

**Guards**

- `nett-mesh:the_dial_only_follower_keeps_its_tls_relays_authenticated`
- `nett-node:a_machine_without_an_upgrader_reports_only_a_newer_release`
- `lab:dial-only-switch`

## 7. Input is checked where it enters

**Holds**: configuration and files are validated at the boundary, against what the machine itself uses, before anything acts on them.

**Breaks when** a value is valid on its own but collides with something nett uses (a port), or a file is checked and then opened, so what is opened is not what was checked.

**Where it holds**

- A WireGuard port that nett uses itself on the machine (the probe port, the TLS loopback ports) is rejected when the desired state is built and when it is applied (site.md section 4);
- `sudo nett install`, running as root, opens the desired state from the user's directory without following links or blocking, and checks the file it opened.

**Guards**

- `nett-mesh:listen_port_avoids_the_ports_nett_uses_itself`
- `nett-cli:reads_only_regular_files_without_following_links_or_blocking`

## 8. Output says what happened and what to do

**Holds**: machine-readable output stays machine-readable; an error names what was being done and the likely cause; a diagnostic tests the component itself, not a proxy for it; output shows what the reader needs at that point (architecture.md section 14.3).

**Breaks when** a report goes to standard output beside JSON; an error is wrapped as a generic one; a check asks a different component than the one it judges; output repeats what was needed only once.

**Where it holds**

- With `--json`, reports go to standard error;
- `nett doctor` asks the DNS responder for this machine's own name and tells apart the ways a resolver can bypass it (names-and-diagnostics.md section 6);
- A download over the upgrade limit names the URL and the limit;
- `sudo nett install` prints the machine's keys only while it has no desired state;
- A data plane failure stays listed while its retries fail, also after the 5 minutes a single failure is listed, and goes once a retry succeeds (status.md section 6).

**Guards**

- `nett-cli:a_responder_that_does_not_answer_its_own_name_is_a_problem`
- `nett-cli:a_resolv_conf_past_systemd_resolved_is_named`
- `nett-mesh:a_data_plane_failure_is_listed_until_a_retry_succeeds`
- `ci:Full flow of sudo nett install (needs root)`

**Not yet guarded**: JSON output of `nett site status --json` while a command records what happened on the Hub; the error for a download over the size limit.
