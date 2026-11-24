# Failure classes

Every problem fixed in nett belongs to a class: a rule that must hold, which the same mechanism can break in more than one place. This page is the one list of those classes. Each one says what must hold, how it breaks, where the design holds it, and which tests guard it. Fixing one place and leaving the others leaves the class open, so a fix starts from its class (CLAUDE.md, "Handling problems").

- **Adding**: a fixed problem gets a test that reproduces it, and the test is listed under the problem's class. A problem whose mechanism no class covers starts a new class. Where the problem was found and when goes in the CHANGELOG and the commit, not here;
- **Converging**: when a fix adds a place to a class, check whether one general mechanism can replace the class's places. Before each minor version (0.4.0, 0.5.0, ...) every class is reviewed: two classes that share a mechanism become one, a rule enforced case by case moves to one mechanism, a guard that a broader one covers goes, and each "Not yet guarded" item gets a test or a reason;
- **Checked**: CI checks that every test named here exists and that every lab scenario and CI step named here runs in CI (`scripts/check-failure-classes.sh`). A guard that does not run does not guard.

Guards are written as `<crate>:<test function>`, `lab:<scenario>` (a `nett-lab run` scenario, design/prototype.md section 6), or `ci:<step name>` (a step of a CI workflow).

## 1. A measurement takes the path of what it judges

**Holds**: every measurement that chooses a path is taken on the port, transport and route the traffic it judges uses, and a reply counts only when it comes back the way its probe went. A path's state shown to the user is the measurement of that path as it carries traffic.

**Breaks when** a probe leaves from another socket than the tunnel (a network can treat ports differently, mesh.md section 7.1); when one end's probes stand in for a leg only the other end sees (the leg from a relay to the peer); when a value measured before a switch is shown after it; when what the Hub sees of two machines stands in for whether a path between them works (the address each reaches it from says nothing once the Hub is on their network).

**Where it holds**

- Probes of direct candidates and of UDP relays leave from the WireGuard port, and replies come back to it; probes of TLS relays travel inside the connection the tunnel uses (mesh.md section 7.1), and probes of obfuscated relays travel wrapped on the socket the tunnel uses, the relay's reply coming back to the port that sent the probe (obfuscation.md section 6);
- A path through a relay that failed while the relay still answered is broken beyond the relay; the relay counts as recovered only when the peer reports its leg without loss in a report covering the time since, and a relay the peer never reached is reported lost (mesh.md section 8.2);
- The current candidate shows the tunnel's measurement (status.md section 6);
- A path through a relay is measured end to end once a through probe has come back through that relay: the relay forwards it to the peer's WireGuard address and the peer answers, so neither the relay answering for its own leg nor a report of the peer's leg made before it broke makes the path look good; 30 seconds without a through reply while the relay answers, the path is judged from its segments again and held off as broken beyond the relay until the peer reports its leg working (mesh.md section 7.2, ADR 0029);
- Judged from its segments, a path through a relay has a round trip only with the peer's leg: until the peer reports it, this end's probes show only that the relay answers, so the path is no better path to move to, and a failover takes it after the paths whose whole round trip is known, the relay on the peer's own machine among them (mesh.md section 7.2);
- Whether a LAN path works is found by probing it: every LAN address a peer reports is a candidate whatever the Hub sees of the two, an authenticated probe is answered from any address, the address the peer's probes come from is learned when another NAT sits inside the LAN, and both `dial-only` ends probe their LAN paths (mesh.md sections 6 and 7);
- A peer's obfuscated port is probed the way the tunnel reaches it, wrapped from the WireGuard port on the userspace data plane and through the obfuscated transport's loopback port on kernel WireGuard, and a reply counts only when it comes back that way; a probe on this machine's obfuscated port is answered through that port, so a peer that probes both of its ports measures each (obfuscation.md section 6).

**Guards**

- `nett-transport:packets_cross_wrapped_and_only_the_relay_is_heard`
- `nett-relay:the_obfuscated_port_routes_between_plain_and_obfuscated_members`
- `nett-relay:a_member_with_its_own_obfuscated_port_is_reached_there_with_its_key`
- `nett-site:machines_the_hub_sees_on_their_own_lan_connect_over_it`
- `nett-site:every_lan_address_a_peer_reports_is_a_candidate`
- `nett-mesh:an_authenticated_probe_is_answered_from_any_address`
- `nett-mesh:a_lan_address_the_peers_probes_come_from_becomes_a_candidate`
- `nett-mesh:the_follower_takes_the_lan_path_that_answers`
- `nett-mesh:a_relay_that_failed_while_its_peer_restarted_is_taken_back_once_it_works`
- `nett-mesh:a_relay_whose_leg_to_the_peer_broke_is_not_taken_on_the_relays_answers`
- `nett-mesh:a_relay_whose_through_probes_stop_is_measured_from_its_segments_again`
- `nett-relay:through_probes_reach_the_peers_bound_address_and_one_reply_comes_back`
- `nett-relay:through_probes_need_the_senders_token_an_assigned_link_and_a_bound_receiver`
- `nett-mesh:idle_tls_ports_are_dropped` (a through reply from an idle TLS port still reaches the mesh on the userspace data plane, as the kernel's copy rule takes it before its guard)
- `nett-mesh:a_relay_the_followers_wireguard_port_cannot_reach_is_not_used`
- `nett-mesh:a_break_beyond_a_relay_moves_to_another_relay`
- `nett-mesh:a_relay_that_never_answered_is_reported_lost`
- `nett-mesh:the_current_candidate_shows_the_tunnels_measurement`
- `nett-mesh:a_peers_obfuscated_port_is_probed_the_way_the_tunnel_reaches_it`
- `nett-mesh:a_probe_on_the_obfuscated_port_is_answered_through_it`
- `nett-mesh:probes_go_back_through_the_port_they_came_in_on`
- `lab:wgport`, `lab:relay-far-leg`, `lab:relay-port-block`

## 2. What is derived from a source follows it when it changes

**Holds**: whatever is computed, bound, opened or started from configuration or from the program is redone when that source changes, while running and across restarts, and redone until it succeeds when setting it up failed: what made it fail, such as a device the system provides later, can pass with no source changing. A saved or learned copy never outranks a newer source.

**Breaks when** something is set up once at startup and the configuration changes later; saved state is restored over an assignment that changed while it was saved; a learned value is preferred to a configured one that has since changed, and the event that would teach the new value never comes; a helper process or a service manager keeps running the program or the unit it started with; a counter goes away with the artifact that carried it.

**Where it holds**

- A relay binds a `public` member where a changed assignment puts it, and restores a saved binding only while the assignment still gives the address it gave when saved; the relay's own machine stays on loopback over saved and learned bindings (mesh.md sections 5.1 and 5.2);
- On Linux, the probes on the WireGuard port move with the port when it changes (mesh.md section 5.5);
- A desired state whose application hit a data plane failure is applied again, after 1 second and then twice as long each time up to 30 seconds, until it succeeds; the probe sockets and the DNS responder follow an interface that comes up later, and are retried the same way, as is a failure the mobile gateway's periodic check of its forwarding finds (mesh.md section 15, devices.md section 6);
- After an upgrade settles, and after `sudo nett install` brings a new program, the relay restarts on it; after an upgrade the nett service rewrites a unit or launchd configuration that differs from its program's, starts again with its own changed unit on Linux, and launchd reads the rewritten configuration when it next loads the service (release.md sections 4 and 7);
- A transport's loopback port that failed to open is opened again with backoff, without waiting for a configuration change, on the TLS and the obfuscated transport alike (mesh.md section 5.3);
- A record of a blocked endpoint ends once no candidate leads to that endpoint, so a peer that moved to another address or port is tried there (obfuscation.md section 5);
- The program of a release that could not be fetched is fetched again later, by nodes and by the Hub, after 1 minute and then twice as long each time up to an hour; a version is marked failed only when fetching again cannot change the outcome (release.md section 7);
- The version of a machine's advertised routes keeps counting after all of them are removed (site.md section 5.2);
- A new desired state that changes a pair's candidates keeps the pair on the path it uses, with what was measured and reported of it, instead of starting the pair over: one end of a two-ended pair starting from the first relay while the other stays split the pair until it met again (mesh.md section 8.4);
- A candidate a new desired state adds is probed every second for its first minute, as one at startup, also while the direct path in use is within 5 ms, where a candidate tried and never answered is left alone: a peer's new obfuscated port is taken without a restart (mesh.md section 7);
- `nett site status` lists the problems of a machine that applied the latest push from the status it reports every 15 seconds, not from the reason it gave when applying, which describes that moment only (hub.md section 3.4);
- launchd keeps the configuration it loaded: `sudo nett install` compares the fingerprint the loaded service carries with the current configuration, not the file, which the service itself rewrites after an upgrade (release.md section 7);
- On Linux the data plane follows the desired state: the daemon starts on the userspace data plane when the desired state it starts from gives the machine an obfuscated port and on kernel WireGuard otherwise, and an accepted desired state that needs the other one is saved and the daemon exits to start on it; the userspace data plane takes over the interface and probe copy rules kernel WireGuard left (userspace.md section 4.2).

**Guards**

- `nett-relay:a_member_whose_assigned_address_changed_is_bound_there`
- `nett-relay:a_saved_binding_yields_to_a_changed_assignment`
- `nett-relay:the_relays_own_machine_stays_on_loopback`
- `nett-node:a_new_version_that_keeps_exiting_is_rolled_back` (the relay restarts once per settled upgrade)
- `nett-transport:a_port_held_by_another_process_is_opened_once_free`
- `nett-mesh:a_failed_interface_comes_up_on_a_retry`
- `nett-mesh:a_new_desired_state_replaces_a_pending_retry`
- `nett-mesh:a_gateway_whose_forwarding_breaks_lists_it_until_a_retry_succeeds`
- `nett-node:a_program_not_fetched_yet_is_fetched_again_later`
- `nett-node:a_program_whose_signature_does_not_hold_is_marked_failed`
- `nett-node:a_transfer_from_the_hub_that_breaks_off_is_fetched_from_the_hub_again`
- `nett-hub:only_verified_programs_are_served`
- `nett-site:advertised_routes_keep_counting_after_they_are_removed`
- `nett-cli:problems_after_applying_follow_the_reported_status`
- `nett-mesh:dial_only_pair_stays_together_when_one_ends_candidates_change`
- `nett-mesh:a_new_candidate_list_keeps_the_path_in_use`
- `nett-mesh:a_better_candidate_added_while_direct_is_fast_is_tried`
- `nett-mesh:a_blocked_record_ends_when_its_endpoint_changes`
- `ci:sudo nett install <token> (join the Hub, needs root)` (the service rewrites a launchd configuration that differs)
- `nett-node:the_loaded_service_shows_the_fingerprint_of_its_configuration`
- `ci:Full flow of sudo nett install (needs root)` (an older configuration loaded with the file current is loaded again)
- `nett-mesh:a_desired_state_for_the_other_data_plane_is_saved_and_asks_for_a_restart`
- `lab:port-change`, `lab:relay-restart`, `lab:machine-obfs`

**Not yet guarded**: the restart of the relay by `sudo nett install` with a new program. It needs a second, different build of nett installed as root in one CI job, which the install flow does not build; until it does, it is watched when each release is installed on real machines.

## 3. A switch acts on evidence that covers its reason

**Holds**: a pair leaves a path only for a failure that another path can help, and returns only on evidence that covers the condition it left for. A hold waits on the improvement, not on one candidate. A re-handshake counts as done only when WireGuard confirms it.

**Breaks when** queueing is read as loss (every path shares the bottleneck); a loss at one end of the pair, or on a link every path shares, is read as the current path's, a candidate's few probes look clean by chance, and the pair leaves for it and a better score brings it back; a candidate's sparse probes keep a loss it had by chance, which holds a much faster path back; a peer that restarts makes plain UDP fail twice within the hour while obfuscated UDP fails too, and the plain endpoint is recorded as blocked; a peer that restarts loses its sessions, its paths answer their probes again, and the pair moves between its direct paths with the dead session until WireGuard handshakes again by itself; a restart notice is judged against when it was sent, or against what WireGuard showed before the restarted machine handshook, and the session it made as soon as it sent again is taken for a dead one; a lossy path answers a few probes and looks recovered; two equal candidates take turns at being the best and each turn starts a hold again; a late packet on the old path or a peer under load makes a re-handshake miss, and the miss is read as a failure; a failover target is chosen on replies from before the failure, so the relay that stopped with the current path is taken again over its other transport; a two-ended switch is proposed through a tunnel that has not answered on the current path, and the decider switches alone; an outage the follower measured on the path it is leaving is acted on after it carried out the decider's proposal, and it waits for another proposal and then rotates away on its own.

**Where it holds**

- Late replies are queueing, not loss, and a path whose peer's packets still arrive has not failed (mesh.md sections 7 and 8.2);
- Before a candidate's score decides a switch, a check of 40 probes measures the candidates and the current path alike, and a candidate's score counts the loss it showed there: the pair leaves for loss only for a candidate measured clean, and compares one that loses alike without the loss, so a loss every path shares moves nothing, a much faster path is still taken, and a loss a candidate had by chance does not hold it back (mesh.md section 8.2);
- A path left while losing packets returns, by whichever rule, only once at most 2 of its last 60 probes are lost (mesh.md section 8.2);
- The 30-second holds last while some candidate qualifies, and the switch goes to the best one when they end (mesh.md section 8.2);
- A path that answers its probes while its tunnel does not has lost its session, not its way: the handshake is redone once on it, as soon as it answers, before any switch, and at once when the peer says through the Hub that it restarted, only for a session from before its start, placed on this machine's clock (mesh.md sections 8.2 and 8.4);
- After a re-handshake, completion is confirmed and the handshake repeated once on the same relay; a peer under load gets the time WireGuard's cookie retry needs (mesh.md section 8.4);
- A failover, and the relay a `dial-only` decider proposes through the Hub, take only a path that answered since the failure was suspected, and the earlier replies of the paths that did not answer no longer make them a better path (mesh.md sections 8.2 and 8.4);
- A `dial-only` decider whose pair has traffic proposes a better path through the tunnel only once the tunnel has answered since the pair moved onto the current path (mesh.md section 8.4);
- A `dial-only` end carries out a switch both ends agreed on before it measures in the same step, so what it measures is about the path the pair is on (mesh.md section 8.4);
- When several better types answer, the switch goes to the best of them, not through each in turn (mesh.md section 8.2);
- A plain endpoint is recorded as blocked, and avoided from then on, only once its failure lasts: 5 minutes without an answer while obfuscated UDP carries the pair, or a second failure within the hour; one failure it recovers from, such as a first handshake lost at start-up, records nothing, and a failure of obfuscated UDP to the same peer ends the suspicion, as the peer or the network was down (obfuscation.md section 5);
- A pair on the obfuscated path to the peer's own port moves to a much faster relay only over obfuscated UDP: being faster never gives up obfuscation (mesh.md section 8.2, obfuscation.md section 5).

**Guards**

- `nett-mesh:stays_on_a_congested_relay_path`
- `nett-mesh:stays_on_a_congested_direct_path`
- `nett-mesh:tail_drops_while_queueing_do_not_switch`
- `nett-mesh:fails_over_when_only_the_peers_packets_arrive`
- `nett-mesh:late_tunnel_replies_keep_a_congested_path`
- `nett-mesh:a_loss_every_path_shares_does_not_move_the_pair`
- `nett-mesh:a_loss_every_path_shares_leaves_the_comparison_to_latency`
- `nett-mesh:a_chance_loss_on_a_sparsely_probed_relay_does_not_hold_it_back`
- `nett-mesh:a_faster_relay_that_loses_is_measured_once_a_minute`
- `nett-mesh:a_path_left_for_loss_returns_once_its_loss_is_low`
- `nett-mesh:a_relay_left_for_loss_returns_only_once_its_loss_is_low`
- `nett-mesh:a_path_left_for_a_faster_relay_while_lossy_is_held_too`
- `nett-mesh:a_faster_relay_from_the_obfuscated_direct_path_is_an_obfuscated_one`
- `nett-mesh:two_equally_fast_relays_do_not_restart_the_hold`
- `nett-mesh:two_equally_better_paths_do_not_restart_the_hold`
- `nett-mesh:retries_a_rehandshake_that_did_not_complete`
- `nett-mesh:retries_an_incomplete_rehandshake_only_once`
- `nett-mesh:a_completed_or_idle_rehandshake_is_not_repeated`
- `nett-mesh:only_a_handshake_after_the_rehandshake_confirms_it`
- `nett-mesh:waits_for_the_cookie_retry_when_the_peer_is_under_load`
- `nett-mesh:waits_for_at_most_two_cookie_rounds`
- `nett-mesh:a_lost_pair_moves_to_a_relay_that_answered_since_the_failure`
- `nett-mesh:a_lost_pair_does_not_return_to_a_path_that_went_down_with_it`
- `nett-mesh:a_pair_proposes_through_the_tunnel_only_once_it_answers`
- `nett-mesh:a_proposal_carried_out_with_an_outage_of_the_path_left_is_not_undone`
- `nett-mesh:a_recovery_goes_to_the_best_type_that_answers`
- `nett-mesh:one_failure_that_recovers_records_no_block`
- `nett-mesh:a_second_failure_within_the_hour_records_the_block`
- `nett-mesh:a_peer_that_restarts_records_no_block`
- `nett-mesh:a_peer_that_restarts_is_handshaken_again_as_soon_as_it_answers`
- `nett-mesh:a_machine_that_started_tells_the_peers_it_has_no_session_with`
- `nett-mesh:a_peer_that_restarted_is_handshaken_again`
- `nett-mesh:a_restart_notice_authenticates_expires_and_is_no_switch_message`
- `nett-mesh:only_plain_udp_given_up_for_obfuscated_udp_counts_as_blocked`
- `lab:congestion`, `lab:lossy-direct`, `lab:faster-relay`, `lab:wg-cookie`, `lab:wg-rehandshake`, `lab:wireguard-block`, `lab:obfs-restart`, `lab:hub-restart`

## 4. Waits are bounded and nothing slow holds up a loop that must keep going

**Holds**: every wait has a total time limit, and a backoff starts over once things work again; a transfer whose length depends on the link instead stops when it makes no progress, and holds up nothing while it runs. A slow disk, a slow client or a flood never stalls forwarding or a server: costly work runs off the loop, and floods are capped per source before it. A process that stops lets its sessions finish and record their end.

**Breaks when** disk writes run in the forwarding loop; a join or another wait runs on the thread the relay forwards on; a time limit applies to each read instead of the whole request; every handshake is handled before any limit; a reconnect wait only grows; a command reports done while the service is still exiting; a server exits under its long-lived connections.

**Where it holds**

- The relay saves its state on a blocking thread, one save at a time (mesh.md section 5.2);
- The relay shares the nett daemon's runtime (ADR 0032): what the daemon does as it stops that waits (joining the local sockets' threads, which wait out their poll, and stopping the mesh's thread) runs on blocking threads, and the relay stops last, so a restart interrupts the connections through it only for the restart itself;
- The local socket gives each request and the input after it a total time limit (status.md section 4);
- The userspace data plane caps handshake messages per source and in total before the session layer (userspace.md section 4.1);
- nett-node's reconnect wait starts over after a session that outlasted the longest wait (protocol.md section 8);
- nett-node runs on a thread of its own in the nett daemon: a panic there ends that run only, the mesh keeps working, and nett-node starts again after 5 seconds; stopping the service ends it and the wait before its next run (ADR 0013);
- A program download is abandoned after 60 seconds without data, from the Hub or the website, and runs in its own task beside the session (release.md section 7);
- `sudo nett uninstall` waits until launchd no longer has the service;
- The Hub says goodbye to each session and waits for it to record its end before exiting (hub.md section 8);
- A `nett site` command waits at most 2 seconds for the site directory's lock, then says another command holds it.

**Guards**

- `nett-relay:a_stuck_state_write_does_not_hold_up_forwarding`
- `lab:relay-restart` (the pair stays on the restarted relay, and no gap within 3 s of the restart lasts more than 0.5 s)
- `nett-mesh:a_slow_client_cannot_hold_the_socket_past_the_time_limit`
- `nett-mesh:handshake_floods_are_capped_per_source_and_in_total`
- `nett-mesh:over_budget_handshakes_get_no_response`
- `nett-node:reconnecting_starts_over_after_a_lasting_session`
- `nett-node:a_panicking_run_starts_again`
- `nett-node:stopping_ends_a_run_and_the_wait_before_the_next`
- `nett-node:what_the_hub_does_not_deliver_is_unavailable`
- `nett-hub:a_stopping_hub_says_goodbye_and_records_the_disconnection`
- `nett-lab:a_sender_connects_once_its_receiver_appears`
- `nett-site:a_command_waits_for_the_site_lock_for_a_bounded_time`
- `ci:Full flow of sudo nett install (needs root)`

## 5. Platform behavior is tested on the platform

**Holds**: what nett assumes about an operating system (where a packet to the machine's own address goes, which checksums it fills, which socket options apply, how a service manager hands over credentials, what a peer in another PID namespace looks like) is tested on that system, as root where it needs root.

**Breaks when** behavior is reasoned from another platform or from documentation, or code is built only against another C library than the one releases link, and only the real system shows the difference.

**Where it holds**

- On macOS, a packet to the machine's own mesh address goes back into the utun with its checksum filled in, and a DNS query to that address is answered in the data plane (userspace.md section 4);
- On macOS, a dual-stack underlay socket sets only `IPV6_BOUND_IF`, which also binds its IPv4 traffic (userspace.md section 6.2);
- The peer of a local socket in another PID namespace, which the kernel reports with PID 0, is identified by its user ID;
- On Synology DSM the unit uses only directives its systemd 219 implements, taken from its source, because it accepts any other with a warning and does not apply it (dsm.md section 3);
- On Synology DSM, which loads the TUN driver only for packages that need it, `nett install` loads it before it starts the services (dsm.md section 6.2);
- A kernel without the WireGuard family gets the userspace data plane, and tearing down there leaves nftables alone: only the kernel data plane makes nett's tables, and a kernel without nftables may not answer at all (dsm.md section 5).
- On macOS a public certificate is verified by the system, and no root certificates are read into the nett service: reading them through the Security framework leaves several megabytes in the allocator at each connection, which Linux returns (hub.md section 4).
- Calls into the C library are built for musl, which releases link, as well as for glibc, which the tests and the lab run on: the two declare some arguments differently, such as the flags of `recvmmsg` (userspace.md section 4);
- On macOS the nett service runs without the allocator's nano zone, which keeps a page per size and CPU it has used and held megabytes for kilobytes of live objects; the running service is checked for it, since only the system shows which zones a process uses (architecture.md section 13.1).

**Guards**

- `nett-mesh:a_packet_to_this_machines_own_address_goes_back_with_its_checksum`
- `nett-mesh:this_machines_own_dns_query_is_answered_in_the_data_plane`
- `nett-mesh:fills_in_a_checksum_the_system_left_out`
- `nett-mesh:underlay_follows_the_physical_interface_for_ipv4_too`
- `nett-mesh:a_peer_in_another_pid_namespace_is_identified`
- `nett-node:the_dsm_unit_uses_only_what_systemd_219_implements`
- `nett-mesh:a_kernel_without_the_wireguard_family_means_userspace`
- `nett-mesh:teardown_leaves_nftables_alone_without_kernel_wireguard`
- `nett-cli:tun_is_prepared_before_the_services_start`
- `nett-node:a_connector_for_a_public_certificate_loads_no_root_store`
- `nett-node:the_plist_is_valid_and_runs_the_copy`
- `ci:utun, addresses and routes (needs root)`
- `ci:Build this version and 99.0.0 of nett and nett-hub, statically linked`
- `ci:Full flow of sudo nett install (needs root)`

## 6. A mechanism some roles skip is not what all roles rely on

**Holds**: when a behavior depends on a side effect of a mechanism (probing, upgrading), every role that skips the mechanism gets the side effect another way.

**Breaks when** a role is added or changed (a follower that does not probe, a program that cannot replace itself) and keeps relying on what the skipped mechanism did.

**Where it holds**

- A `dial-only` follower probes its TLS relays every 5 seconds, which keeps the standby connections authenticated (mesh.md section 5.3);
- A machine without an upgrader (set up with `nett join` under another service manager) applies a release it already runs and reports a newer one as available;
- The Hub and the container cannot replace the program they are started from, and upgrade through their state directory instead, with the same verification and rollback as machines (ADR 0026);
- On Linux the userspace data plane applies the kernel data plane's nftables rules on its TUN, so a machine on it keeps its filter, Edge and forwarding, and hands the kernel what it decrypts only once those rules are in place (userspace.md section 4.2).

**Guards**

- `nett-mesh:the_dial_only_follower_keeps_its_tls_relays_authenticated`
- `nett-mesh:with_netfilter_the_kernel_decides_what_comes_in`
- `lab:access`, `lab:devices` (each also on the userspace data plane)
- `nett-node:a_machine_without_an_upgrader_reports_only_a_newer_release`
- `nett-node:a_new_version_that_does_not_settle_goes_back_to_the_one_before`
- `nett-hub:the_hub_relays_and_upgrades_only_as_approved`
- `ci:Join, reach a service beside a container over the LAN, upgrade in place, roll back (needs Docker)`
- `lab:dial-only-switch`

## 7. Input is checked where it enters

**Holds**: configuration and files are validated at the boundary, against what the machine itself uses, before anything acts on them.

**Breaks when** a value is valid on its own but collides with something nett uses (a port); a release starts reserving a port a site already gives a machine, and the machine then rejects the desired state it saved and starts without its mesh; or a file is checked and then opened, so what is opened is not what was checked.

**Where it holds**

- The probe port, the one port nett binds that a WireGuard or relay port may not be, is rejected when the desired state is built and when it is applied; the transports' loopback ports go around the machine's own WireGuard and relay ports instead of forbidding them, and a WireGuard port the system assigns avoids them (site.md section 4, mesh.md sections 5.3 and 5.5);
- `sudo nett install`, running as root, opens the desired state from the user's directory without following links or blocking, and checks the file it opened;
- The target names of a release manifest are checked before the Hub names files after them, and the version and target a node asks for are only compared with what the Hub holds, never used as a path (release.md section 7);
- A TLS connection nett-relay hands to the relay in the daemon gets nothing forwarded and no answer until an authenticated probe identifies its member, and nett-relay closes one the relay has not answered within 30 seconds (mesh.md section 5.3);
- Every datagram on a machine's obfuscated port is opened with its key before WireGuard or the mesh reads it, and what does not open, a replay among it, gets no answer; which port a peer is answered through is learned only from a packet WireGuard authenticated, so a forged source address moves no peer's replies between the ports (userspace.md section 4.1).

**Guards**

- `nett-mesh:listen_port_avoids_the_ports_nett_uses_itself`
- `nett-mesh:loopback_ports_go_around_the_machines_own_ports`
- `nett-mesh:automatic_port_skips_the_ports_nett_uses_itself`
- `nett-cli:reads_only_regular_files_without_following_links_or_blocking`
- `nett-trust:manifests_and_versions_from_the_network_are_checked`
- `nett-hub:nodes_fetch_the_program_of_a_release_from_the_hub`
- `nett-relay:a_handed_over_tls_connection_authenticates_and_carries_its_member`
- `nett-mesh:an_obfuscated_port_carries_the_tunnel_wrapped_both_ways`
- `nett-mesh:an_obfuscated_port_carries_the_tunnel_and_the_probes`

## 8. Output says what happened and what to do

**Holds**: machine-readable output stays machine-readable; an error names what was being done and the likely cause; a diagnostic tests the component itself, not a proxy for it; output shows what the reader needs at that point (architecture.md section 14.3).

**Breaks when** a report goes to standard output beside JSON; a write to a reader that has gone panics; an error is wrapped as a generic one; a check asks a different component than the one it judges; output repeats what was needed only once.

**Where it holds**

- With `--json`, reports go to standard error;
- `nett doctor` asks the DNS responder for this machine's own name and tells apart the ways a resolver can bypass it (names-and-diagnostics.md section 6);
- A download over the upgrade limit names the URL and the limit;
- `sudo nett install` prints the machine's keys only while it has no desired state;
- A data plane failure stays listed while its retries fail, also after the 5 minutes a single failure is listed, and goes once a retry succeeds (status.md section 6);
- Logs are plain text: the log formatter is built without color support, so no program writes terminal color codes into the journal or a log file;
- The change listing says that two `dial-only` machines without a relay connect only over a LAN, and gives the command that adds one (site.md section 6);
- The change listing names what the Hub learned about a machine that its reachability line does not show (its WireGuard port, LAN addresses, relay certificate), so that a change fetched from the Hub is never an empty report (site.md section 7);
- The change listing names a relay's obfuscated port, which the user opens in the machine's firewall, and `nett site relay --obfs` names the Hub and the machines on a release too old for it (site.md section 4.1, obfuscation.md section 5);
- `nett site status` names a public machine whose WireGuard port answers no probe from machines that reach it otherwise, with those machines and what to do, rather than leaving each machine's view to be read one by one (hub.md section 3.4);
- A command whose reader has gone ends quietly with success, a message that cannot be written leaves the exit status alone, and any other failure to write the output says why: the programs write through `nett_core::output`, and the workspace lints deny `println!` and its kin, which panic instead (architecture.md section 14.3).

**Guards**

- `nett-cli:a_responder_that_does_not_answer_its_own_name_is_a_problem`
- `nett-cli:a_resolv_conf_past_systemd_resolved_is_named`
- `nett-mesh:a_data_plane_failure_is_listed_until_a_retry_succeeds`
- `nett-hub:logs_carry_no_terminal_color_codes`
- `nett-site:every_lan_address_a_peer_reports_is_a_candidate`
- `nett-site:what_the_hub_learns_about_a_machine_is_listed`
- `nett-site:relay_changes_are_listed_with_the_paths_they_change`
- `nett-cli:the_hub_and_machines_on_an_older_release_are_named`
- `nett-cli:a_wireguard_port_others_cannot_reach_is_named`
- `nett-cli:a_closed_output_ends_the_command_quietly`
- `nett-cli:a_closed_error_output_keeps_the_failure`
- `nett-cli:a_full_output_says_why_and_fails`
- `nett-hub:a_closed_output_ends_the_command_quietly`
- `ci:Full flow of sudo nett install (needs root)`

**Not yet guarded**: JSON output of `nett site status --json` while a command records what happened on the Hub, which needs a Hub that serves those updates to the command line in a test; the error for a download over the size limit, since the client fetches only `https://` URLs verified by the operating system, which a test cannot serve (the limit itself is guarded by `nett-node:a_program_larger_than_any_release_is_refused`, and the error is one message naming the URL and the limit).

## 9. What a tunnel carries goes out as it arrives

**Holds**: every TCP connection that carries a tunnel's packets or a forwarded stream sends each write at once: as the UDP path would for a tunnel, and as the two ends would see it without a forwarder in between. Every UDP socket that carries a tunnel's packets holds a burst, so a short delay in reading it drops nothing.

**Breaks when** a socket keeps Nagle's algorithm: a small packet waits until the one before it is acknowledged, and with probes and keepalives sharing the connection most requests through it wait a round trip and the peer's delayed acknowledgement more; or a UDP socket keeps the system's default receive buffer, which holds less than 2 ms at gigabit rates, and TCP inside the tunnel reads the drops as congestion; or WireGuard is pointed at a loopback port its transport has not opened yet, and the first handshake is refused and waits for WireGuard's retry 5 seconds later; or a change to some transport targets starts every target again and drops their connections.

**Where it holds**

- Both ends of a TLS relay connection turn Nagle's algorithm off: the TLS transport when it connects, nett-relay when it accepts (mesh.md section 5.3);
- A served port's forwarder turns it off on both of its connections (mesh.md section 12.1);
- A TLS relay connection that falls behind sends its newest packets: each end's send queue keeps 32 and drops the oldest, and the probe that opens the connection goes first and is never dropped (mesh.md section 5.3);
- Every socket that carries tunnel traffic asks for a 1 MiB receive buffer: the WireGuard port socket, the relay's sockets, and the transports' loopback ports and the obfuscated transport's socket to its relay (userspace.md section 4);
- The mesh opens each new loopback port of the transports before it points WireGuard at it, and the transports take it from there; targets that stay keep their task and connection when others change (mesh.md section 5.3);
- On Linux the userspace data plane takes up to 64 datagrams per `recvmmsg` and sends what each wakeup produced with `sendmmsg`, in order per socket, so a burst costs a system call per batch; a datagram longer than its 2048-byte slot is not a tunnel's and is dropped (userspace.md section 4).

**Guards**

- `nett-relay:both_ends_of_a_tls_relay_connection_send_each_packet_at_once`
- `nett-transport:a_full_send_queue_drops_its_oldest_packet`
- `nett-transport:the_opening_message_goes_first_and_is_never_dropped`
- `nett-mesh:the_buffer_never_shrinks`
- `nett-mesh:a_new_port_is_open_before_its_transport_takes_it`
- `nett-mesh:loopback_ports_are_opened_before_wireguard_is_pointed_at_them`
- `nett-transport:a_packet_sent_before_the_transport_starts_is_not_lost`
- `nett-transport:a_target_that_stays_keeps_its_task_when_others_change`
- `nett-mesh:a_batch_takes_what_is_queued_and_leaves_out_what_is_too_long`
- `nett-mesh:datagrams_go_out_in_order_batch_after_batch`

**Not yet guarded**: the served port's forwarder. Its two sockets live inside the task that copies one to the other, and a test sees only their far ends, whose setting says nothing about the forwarder's; the setting sits beside the copy, in one place. The same holds for each transport's request for a larger receive buffer, one call beside the socket it opens; the throughput scenario (design/obfuscation.md section 9) shows a missing one as retransmissions, and runs before releases that change a transport rather than in CI, since its numbers need a quiet machine.

## 10. A secret is readable only where it is meant to go

**Holds**: private keys, tokens, obfuscation keys and the site's relay key are written out only where they are meant to go: the files that keep them (`0600`), and the messages that deliver them to the process that uses them. Everywhere else, a log line, an error, an event file or a `Debug` print, they read as redacted (hard rule 10).

**Breaks when** a type that holds a secret derives `Debug` or `Serialize`, and a structure that contains it is logged or written to an event file whole.

**Where it holds**

- Each key type prints as redacted: the mesh's private key, probe tokens, obfuscation keys, the relay key and the backup key;
- The transport configuration, which the lab's event file writes whole, serializes its obfuscation keys as redacted; it goes to the transport in memory only.

**Guards**

- `nett-core:a_serialized_configuration_carries_no_key`

**Not yet guarded**: the redacted `Debug` of each key type; each is one implementation next to its type.
