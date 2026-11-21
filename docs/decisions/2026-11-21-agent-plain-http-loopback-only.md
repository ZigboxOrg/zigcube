# The agent speaks plain HTTP to a loopback `--server` only

*Decided 2026-11-21, by the supervisor (option A of finding 1 in
`2026-11-17-0.5.2-known-issues-to-0.6.0.md`); implemented in the 0.6.0 lane `060-b-agent-tls`.*

## Why

Without `--ca`, `zcube-agent` spoke plain HTTP to whatever address `--server` named, though
`zcube-server` serves plain HTTP on loopback only (`--insecure-listen`, ZC-E0106). A node
configured that way would take its assignments and post `relay.pub` over an unauthenticated,
unencrypted connection, to anything that answered at that address (release review 5927120432 of
Cube 0.5.2, `src/agent_config.zig`).

## The rule

- With no `--ca` (and no `.ca` in the ZON file), the agent refuses at start-up a `--server` that
  is not a loopback address: ZC-E0505, the code of every other unusable agent setting, with the
  one-line cause `--server ADDR is not a loopback address, and without --ca the agent would talk
  plain HTTP to it` and the fix `give --ca, --cert and --key (or .ca, .cert and .key in the file)
  to reach the server's --listen over TLS; plain HTTP goes to 127.0.0.1 or [::1] only`. The agent
  starts nothing and changes nothing, as for any E0505 (the state directory is not even made).
- Loopback is the server's own rule, `server_config.is_loopback`: 127.0.0.0/8 and `::1`. An
  IPv4-mapped address (`::ffff:127.0.0.1`) is not loopback here either. `--server` takes no names,
  so `localhost` never reaches the check (it is refused as "not an IP address", as before).
- A loopback `--server` without `--ca` still works: `zcube local`, `agent-smoke`, `local-smoke`,
  the FakeRuntime demos on one host and the in-process tests all use it, against
  `--insecure-listen`.
- With `--ca`, any address is allowed, as before.

## What moved

- `demo-b5` was the one harness whose agent spoke plain HTTP across a network (the QEMU guest to
  the host's `10.0.2.2`, through the slirp forward to the server's loopback). It now runs as
  demo-b3, demo-b4 and demo-c2 do since B7 slices 6 and 7: the server serves `--listen` only
  (`Config.tls_only`), the demo checks that plain HTTP gets no answer (`check_tls_only`), and the
  guest's agent gets a node certificate (`ca issue-node`, `steps.put_tls`) and `--ca`, `--cert`
  and `--key`; `ops/demo-b5/guest.sh agent` now requires the TLS directory.
- Checked and unchanged (all name `127.0.0.1` or pass TLS): agent-smoke, local-smoke, swarm-smoke,
  demo-c0, demo-c1 (node1's fault proxy listens on loopback), demo-b1, demo-b3, demo-b4, demo-b6,
  demo-b7, demo-c2, zigbox-smoke (agent and server inside one guest), the Jepsen recipe
  (`ops/jepsen/zigcube.sh agent` always writes `.ca`).

## Upgrade note

Only the agent changes. An agent that ran without `--ca` against a server on another host never
worked against a 0.5 or later server (which serves plain HTTP on loopback only), so no working
setup is refused; one that pointed at a plain-HTTP forwarder (an SSH tunnel's far end, a proxy)
must now use the forwarder's loopback end, or TLS.

Where: `docs/agent.md` (the agent's settings), `docs/mtls.md` ("Clients"), the ZC-E0505
explanation (`src/diag/codes.zig`, `site/errors/E0505.html`), `docs/demos/b5.md`.
