#!/usr/bin/env bash
# Tests of .github/ci-changes.sh: a table of changed paths and the verdict each must get. The
# changes job runs it before it classifies, so a broken rule fails CI instead of skipping a job.
# Each row: EVENT|HEAD_REF|LABELS|paths (space separated)|expected
# `code store c0 c1 b1 smoke c2 mtls b3 c3smoke c3 b7 b5 b6 b4 jepsen release` as T/F.
# `check` leaves the macos output out; `check_macos` rows judge it alone.
set -uo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
failed=0
n=0

check() {
  local event=$1 ref=$2 labels=$3 paths=$4 want=$5 got out
  # GITHUB_OUTPUT is set on a runner; unset, the script writes to stdout.
  out=$(printf '%s\n' ${paths} | env -u GITHUB_OUTPUT EVENT="$event" HEAD_REF="$ref" \
    LABELS="$labels" "$dir/ci-changes.sh" | grep -v '^macos=' | tr '\n' ' ')
  got=$(echo "$out" | sed -E 's/code=true/T/; s/code=false/F/; s/store=true/T/; s/store=false/F/;
    s/demo_c0=true/T/; s/demo_c0=false/F/; s/demo_c1=true/T/; s/demo_c1=false/F/;
    s/demo_b1=true/T/; s/demo_b1=false/F/;
    s/zigbox_smoke=true/T/; s/zigbox_smoke=false/F/; s/demo_c2=true/T/; s/demo_c2=false/F/;
    s/mtls_interop=true/T/; s/mtls_interop=false/F/; s/demo_b3=true/T/; s/demo_b3=false/F/;
    s/c3_smoke=true/T/; s/c3_smoke=false/F/; s/demo_c3=true/T/; s/demo_c3=false/F/;
    s/demo_b7=true/T/; s/demo_b7=false/F/;
    s/demo_b5=true/T/; s/demo_b5=false/F/;
    s/demo_b6=true/T/; s/demo_b6=false/F/;
    s/demo_b4=true/T/; s/demo_b4=false/F/; s/jepsen=true/T/; s/jepsen=false/F/;
    s/release=true/T/; s/release=false/F/; s/ //g')
  n=$((n + 1))
  if [ "$got" != "$want" ]; then
    echo "FAIL: $event ${ref:+[$ref] }${labels:+[$labels] }${paths:-<no paths>}: want $want, got $got"
    failed=$((failed + 1))
  fi
}

# The macOS job: its own verdict, T or F.
check_macos() {
  local event=$1 ref=$2 labels=$3 paths=$4 want=$5 got
  got=$(printf '%s\n' ${paths} | env -u GITHUB_OUTPUT EVENT="$event" HEAD_REF="$ref" \
    LABELS="$labels" "$dir/ci-changes.sh" | sed -n 's/^macos=true$/T/p; s/^macos=false$/F/p')
  n=$((n + 1))
  if [ "$got" != "$want" ]; then
    echo "FAIL: macos: $event ${ref:+[$ref] }${labels:+[$labels] }${paths:-<no paths>}: want $want, got $got"
    failed=$((failed + 1))
  fi
}

# Verdict order: code store demo_c0 demo_c1 demo_b1 zigbox_smoke demo_c2 mtls_interop demo_b3
# c3_smoke demo_c3 demo_b7 demo_b5 demo_b6 demo_b4 jepsen release.
PR=pull_request
# Documentation only: nothing runs.
check $PR x "" "README.md docs/core.md site/index.html" FFFFFFFFFFFFFFFFF
check $PR x "" "docs/demos/c1.md" FFFFFFFFFFFFFFFFF
# ...except src/ and web/ markdown, site/errors, and any code file.
check $PR x "" "src/README.md" TTTTTTTTTTTTTTTTT
check $PR x "" "web/README.md" TFFFFFFFFFFFFFFFF
check $PR x "" "site/errors/ZC-E0001.html" TFFFFFFFFFFFFFFFF
check $PR x "" "README.md ops/sim-fleet/run.sh" TFFFFFFFFFFFFFFFF
check $PR x "" "ops/sim-fleet/test-canary.sh ops/sim-fleet/test-crash-record.sh" TFFFFFFFFFFFFFFFF
# Docs only, but asked for in full.
check $PR x "full-ci" "README.md" TTTTTTTTTTTTTTTTT
check $PR claude/release-0.4 "" "README.md" TTTTTTTTTTTTTTTTT
# Narrow: tests, simulations, the web console, the tools, the gate's own runner.
check $PR x "" "src/scheduler_test.zig" TFFFFFFFFFFFFFFFF
check $PR x "" "src/sim_cluster.zig src/sim_swarm_main.zig" TFFFFFFFFFFFFFFFF
check $PR x "" "web/app.js web/mock/c1.js tools/wasm_check.mjs" TFFFFFFFFFFFFFFFF
check $PR x "" "src/tidy.zig src/testing/check.zig" TFFFFFFFFFFFFFFFF
check $PR x "" "src/console_wasm.zig src/web_embed.zig" TFFFFFFFFFFFFFFFF
check $PR x "" "src/mac_release.zig packaging/homebrew/zcube-resource.rb" TFFFFFFFFFFFFFFFF
# The relay teeth's agent roots run only in the check job (`zig build relay-teeth`).
check $PR x "" "src/zcube_agent_relay_teeth_outlive.zig src/zcube_agent_relay_teeth_unrelayed.zig" TFFFFFFFFFFFFFFFF
# One demo, one smoke, the store suites' own files.
check $PR x "" "src/demo_c0_steps.zig" TFTFFFFFFFFFFFFFF
check $PR x "" "src/demo_c1_fleet.zig docs/demos/c1.md" TFFTTFFFTTFTTTTFF
check $PR x "" "src/demo_c1_state.zig" TFFTTFFFTFFTTTTFF
check $PR x "" "src/demo_c0_state.zig" TFTTTFFFTFFTTTTFF
check $PR x "" "src/demo_c1_partition.zig" TFFTFFFFFFFFFFFFF
check $PR x "" "src/zigbox_runtime.zig" TFFFFTTFTFTFTFTFF
check $PR x "" "ops/zigbox-smoke/guest.sh" TFFFFTFFFFFFFFFFF
check $PR x "" "src/store_faults.zig src/store_failover.zig" TTFFFFFFFFFFFFFFF
check $PR x "" "src/mtls_interop.zig" TFFFFFFTFFFFFFFFF
check $PR x "" "ops/mtls-interop/InteropServer.java" TFFFFFFTFFFFFFFFF
check $PR x "" "src/demo_c0.zig src/demo_c1.zig" TFTTFFFFFFFFFFFFF
# The TLS server sits behind zcube-server's listener since B7 slice 3: it runs everything.
check $PR x "" "src/tls_server.zig src/tls_server_test.zig src/tls_testclient.zig" TTTTTTTTTTTTTTTTT
# Everything: the build, CI itself, the shared demo driver, the server, the agent, the store
# backends, the core, and any path no rule names (also a new directory).
check $PR x "" "build.zig" TTTTTTTTTTTTTTTTT
check $PR x "" "build.zig.zon" TTTTTTTTTTTTTTTTT
check $PR x "" ".github/workflows/ci.yml" TTTTTTTTTTTTTTTTT
check $PR x "" ".github/ci-changes.sh" TTTTTTTTTTTTTTTTT
check $PR x "" "src/demo_host.zig" TTTTTTTTTTTTTTTTT
check $PR x "" "src/server.zig" TTTTTTTTTTTTTTTTT
check $PR x "" "src/agent_loop.zig" TTTTTTTTTTTTTTTTT
check $PR x "" "src/store_postgres.zig" TTTTTTTTTTTTTTTTT
check $PR x "" "src/store.zig" TTTTTTTTTTTTTTTTT
check $PR x "" "src/core.zig" TTTTTTTTTTTTTTTTT
check $PR x "" "src/c1_teeth.zig" TTTTTTTTTTTTTTTTT
check $PR x "" "src/harness_tls.zig" TTTTTTTTTTTTTTTTT
# The sim job (which runs sim-fencing-teeth) runs on `code`: a change to the fencing arithmetic
# runs everything, one to the simulator alone runs the code jobs.
check $PR x "" "src/fencing.zig" TTTTTTTTTTTTTTTTT
check $PR x "" "src/sim_cluster.zig src/sim_c1_teeth_oldrule_main.zig" TFFFFFFFFFFFFFFFF
check $PR x "" "src/testing/fault_proxy.zig" TTTTTTTTTTTTTTTTT
check $PR x "" "src/brand_new_file.zig" TTTTTTTTTTTTTTTTT
check $PR x "" "newdir/file.txt" TTTTTTTTTTTTTTTTT
check $PR x "" "fixtures/images.zon" TTTTTTTTTTTTTTTTT
check $PR x "" "demo/up.sh" TTTTTTTTTTTTTTTTT
# B5 slice 3: the trust world and its tooth are simulator files.
check $PR x "" "src/sim_trust.zig src/sim_c1_teeth_job_untrusted_main.zig" TFFFFFFFFFFFFFFFF
# demo-c2: its own files, its docs (off), an unknown path (on), the label and a release branch (on).
check $PR x "" "src/demo_c2_steps.zig ops/demo-c2/run.sh" TFFFFFTFTFFFTFTFF
check $PR x "" "docs/demos/c2.md" FFFFFFFFFFFFFFFFF
check $PR x "" "src/never_heard_of_it.zig" TTTTTTTTTTTTTTTTT
check $PR x "full-ci" "src/demo_c2.zig" TTTTTTTTTTTTTTTTT
check $PR claude/release-0.5 "" "src/demo_c2.zig" TTTTTTTTTTTTTTTTT
check $PR x "" "src/scheduler_test.zig src/demo_c2.zig" TFFFFFTFFFFFFFFFF
# demo-b3: its own files, the files it shares (demo-b1's state, demo-c2's rig), the relay.
check $PR x "" "src/demo_b3_script.zig ops/demo-b3/guest.sh" TFFFFFFFTFFFFFTFF
check $PR x "" "src/demo_c2_vms.zig" TFFFFFTFTFTFTFTFF
check $PR x "" "src/demo_b1_state.zig" TFFFTFFFTFFTTTTFF
check $PR x "" "src/relay.zig" TFFFFTTTTFTFTFTFF
check $PR x "" "docs/demos/b3.md" FFFFFFFFFFFFFFFFF
# demo-b5: its own files, and the rig and state it shares with demo-b3; its docs (off).
check $PR x "" "src/demo_b5.zig src/demo_b5_script.zig ops/demo-b5/guest.sh" TFFFFFFFFFFFTFFFF
check $PR x "" "docs/demos/b5.md" FFFFFFFFFFFFFFFFF
check $PR x "" "src/demo_c2_check.zig" TFFFFFTFTFFFTFTFF
# A narrow path next to an unknown one runs everything; two narrow paths run the union.
check $PR x "" "src/scheduler_test.zig src/server.zig" TTTTTTTTTTTTTTTTT
check $PR x "" "src/zigbox_map.zig src/demo_c1_steps.zig" TFFTFTTFTFTFTFTFF
# Full: the label, a release branch, a push to main, an unlisted change.
check $PR x "full-ci" "src/scheduler_test.zig" TTTTTTTTTTTTTTTTT
check $PR x "bug full-ci" "src/scheduler_test.zig" TTTTTTTTTTTTTTTTT
check $PR x "full-cipher" "src/scheduler_test.zig" TFFFFFFFFFFFFFFFF
check $PR claude/release-0.4 "" "src/scheduler_test.zig" TTTTTTTTTTTTTTTTT
check $PR claude/ci-speed "" "src/scheduler_test.zig" TFFFFFFFFFFFFFFFF
check push main "" "src/scheduler_test.zig" TTTTTTTTTTTTTTTTT
check push main "" "web/app.js" TTTTTTTTTTTTTTTTT
check push main "" "README.md" FFFFFFFFFFFFFFFFF
check $PR x "" "" TTTTTTTTTTTTTTTTT
check push main "" "" TTTTTTTTTTTTTTTTT
# demo-b7's own files run demo-b7 only; docs/demos/b7.md is documentation.
check $PR x "" "src/demo_b7.zig src/demo_b7_steps.zig docs/demos/b7.md" TFFFFFFFFFFTFFFFF
# The interop harness, its server rows and the Java client run mtls-interop only.
check $PR x "" "src/mtls_interop_server.zig ops/mtls-interop/InteropClient.java" TFFFFFFTFFFFFFFFF
# demo-b1's own files run demo-b1 only; docs/demos/b1.md is documentation.
check $PR x "" "src/demo_b1_nodes.zig docs/demos/b1.md" TFFFTFFFFFFFFFFFF
check $PR x "" "src/demo_b1.zig src/demo_c1.zig" TFFTTFFFFFFFFFFFF
# demo-b6's own files run demo-b6 only; it shares demo-b1's state and fleet, so they run it too.
check $PR x "" "src/demo_b6_steps.zig docs/demos/b6.md" TFFFFFFFFFFFFTFFF
check $PR x "" "src/demo_b1_fleet.zig" TFFFTFFFTFFTTTTFF
# c3-smoke's steps and witness run c3-smoke and demo-c3; docs/demos/c3.md is documentation.
check $PR x "" "src/c3_smoke_steps.zig src/c3_witness.zig docs/demos/c3.md" TFFFFFFFFTTFFFFFF
# demo-c3: its own files; the smoke's driver is c3-smoke's alone; the rig and the adapter reach it.
check $PR x "" "src/demo_c3.zig ops/demo-c3/guest.sh" TFFFFFFFFFTFFFFFF
check $PR x "" "src/c3_smoke.zig" TFFFFFFFFTFFFFFFF
check $PR x "" "src/c3_smoke_steps.zig" TFFFFFFFFTTFFFFFF
check $PR x "" "src/demo_c2_steps.zig" TFFFFFTFTFFFTFTFF
check $PR x "" "src/c3_smoke.zig src/demo_c1_state.zig" TFFTTFFFTTFTTTTFF
check $PR x "" "docs/demos/c3.md" FFFFFFFFFFFFFFFFF

# The macOS job: zcube's own files, the build and CI run it; a server file, an unknown path and
# documentation do not; a full run does.
PR=pull_request
check_macos $PR x "" "src/cli_local.zig" T
check_macos $PR x "" "src/zcube.zig src/server.zig" T
check_macos $PR x "" "src/mac_release.zig" T
check_macos $PR x "" "packaging/homebrew/zcube-resource.rb" T
check_macos $PR x "" "build.zig" T
check_macos $PR x "" ".github/actions/setup-zig-macos/action.yml" T
check_macos $PR x "" ".github/workflows/ci.yml" T
check_macos $PR x "" "src/server.zig" F
check_macos $PR x "" "src/brand_new_file.zig" F
check_macos $PR x "" "src/diag/codes.zig" F
check_macos $PR x "" "docs/macos.md" F
check_macos $PR x "" "README.md src/cli_local.zig" T
check_macos $PR x "full-ci" "src/server.zig" T
check_macos $PR claude/release-0.6 "" "src/server.zig" T
check_macos push main "" "src/server.zig" T
check_macos push main "" "README.md" F
check_macos $PR x "" "" T
# C5 slice 1: the public path shares the TLS server with B7's listeners, so its files run
# everything; its browser check runs in the mtls-interop job, and its fixture recorder runs the
# code job only.
check $PR x "" "src/edge_host.zig src/tls_server_public_test.zig src/public_tls_listener.zig" TTTTTTTTTTTTTTTTT
check $PR x "" "tools/public_tls_check.mjs" TFFFFFFTFFFFFFFFF
check $PR x "" "tools/record_client_hello.mjs" TFFFFFFFFFFFFFFFF
check $PR x "" ".github/actions/zig-cache/action.yml" TTTTTTTTTTTTTTTTT
# The Jepsen client and recipe run the code job and the jepsen job only; the tarball tool
# (src/dist.zig) also packs the release, so it runs the release job too.
check $PR x "" "src/jepsen_client.zig src/jepsen_history.zig src/zcube_jepsen_client.zig" TFFFFFFFFFFFFFFTF
check $PR x "" "ops/jepsen/zigcube.sh ops/jepsen/test-recipe.sh src/dist.zig" TFFFFFFFFFFFFFFTT
check $PR x "" "ops/jepsen/postgres.sh ops/jepsen/test-postgres.sh" TFFFFFFFFFFFFFFTF
check $PR x "" "src/dist.zig" TFFFFFFFFFFFFFFTT
check $PR x "" "ops/jepsen/fault.sh src/scheduler_test.zig" TFFFFFFFFFFFFFFTF
# ops/jepsen/README.md is a .md outside src/ and web/: documentation, nothing runs.
check $PR x "" "ops/jepsen/README.md" FFFFFFFFFFFFFFFFF
# B4 slice 4: the relay's TLS half and the supervisor that secures it also run mtls-interop
# (relay) and demo-b4 (with demo-b3); demo-b4's own script runs it alone; the TLS upstream runs both.
check $PR x "" "src/relay_secure.zig" TFFFFTTTTFTFTFTFF
check $PR x "" "src/zigbox_supervisor.zig" TFFFFTTFTFTFTFTFF
check $PR x "" "src/demo_b4_script.zig" TFFFFFFFFFFFFFTFF
check $PR x "" "src/demo_relay_tls.zig" TFFFFFFFTFFFFFTFF
check $PR x "" "docs/demos/b4.md" FFFFFFFFFFFFFFFFF
# The release workflow, its scripts and actions run the release job only; src/dist.zig packs
# both the Jepsen tarball and the release; build.zig and the rest of .github still run all.
check $PR x "" ".github/workflows/release.yml" TFFFFFFFFFFFFFFFT
check $PR x "" ".github/release-libs.sh .github/release-check.sh" TFFFFFFFFFFFFFFFT
check $PR x "" ".github/actions/setup-gh/action.yml .github/actions/find-draft/action.yml" TFFFFFFFFFFFFFFFT
check $PR x "" "ops/jepsen/zigcube.sh" TFFFFFFFFFFFFFFTF
check $PR x "" ".github/actions/setup-zig/action.yml" TTTTTTTTTTTTTTTTT
check $PR x "" "docs/releases/automation.md" FFFFFFFFFFFFFFFFF
# A release's notes are not documentation only: they run everything, on a pull request and on main.
check $PR x "" "docs/releases/0.6.0.md" TTTTTTTTTTTTTTTTT
check $PR x "" "docs/releases/0.6.0.md README.md site/index.html" TTTTTTTTTTTTTTTTT
check push main "" "docs/releases/0.6.0.md" TTTTTTTTTTTTTTTTT

if [ "$failed" -ne 0 ]; then
  echo "ci-changes-test: $failed of $n failed"
  exit 1
fi
echo "ci-changes-test: $n cases passed"
