# demo-c3's guests talk TLS to the server

*Decided 2026-11-21, by the slice (C3, after #11 merged into the C3 branch).*

Since docs/decisions/2026-11-21-agent-plain-http-loopback-only.md, an agent refuses plain HTTP to
a `--server` that is not on loopback (ZC-E0505). demo-c3's three QEMU guests reached the host's
`10.0.2.2` without TLS, so its CI run failed at step 0, at the first `guest.sh agent`. It now runs
as demo-c2 (whose rig it uses) and demo-b5 do:

- The server serves `--listen` (TLS) only, with no `--insecure-listen` (`Config.tls_only`), and
  step 0 checks that a plain-HTTP `GET /v1/status` gets no answer and the same request with the
  operator's certificate gets 200 (`Host.check_tls_only`).
- The host's `zcube` commands present `ca issue-client operator --scope admin`.
- Each guest's agent gets a node certificate (`ca issue-node nodeN`), its key and the CA in
  `/root/tls`, each read back as 0600, and `--ca`, `--cert` and `--key`;
  `ops/demo-c3/guest.sh agent <node> <server> <tls dir>` requires the directory.
- The body of demo-c2's `put_tls` is now `put_guest_tls(host, guests, index)` in
  `src/demo_c2_steps.zig`, which demo-c3 calls without running demo-c2's steps. demo-c3 therefore
  imports `demo_c2_steps.zig` (and `demo_c2_check.zig`), and `.github/ci-changes.sh` picks
  `demo_c3` for both (table-test rows updated).
- c3-smoke runs on one host and keeps plain HTTP on loopback.

This adds a row to the harness table of docs/decisions/2026-11-14-b7-slice6-console-over-tls.md
and a harness to the "What moved" list of
docs/decisions/2026-11-21-agent-plain-http-loopback-only.md;
neither file is edited.

| Harness | Over `--listen` now | Notes |
| --- | --- | --- |
| `demo-c3` | yes (C3, on 0.6.0's agent rule) | TLS only, as `demo-c2`: CA, `node.crt` and `node.key` in each guest's `/root/tls` (0600) |

Where: `docs/demos/c3.md` ("TLS"), `docs/mtls.md` (the harness list), `src/demo_c3.zig`,
`ops/demo-c3/guest.sh`.
