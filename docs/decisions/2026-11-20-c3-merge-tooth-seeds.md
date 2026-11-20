# Two sparse teeth move to new seeds after C3's merge onto main

Date: 2026-11-20. Status: implementer's decision (0.6.0 plan item B3, branch
`claude/060-b-c3-demo`); no check weakened.

Bringing C3 (`origin/old/claude/c3-demo`) onto main merges its simulator changes (rollouts,
`--health`, the C3 job and apply paths) with old/main's #237 registration order and #243 reuse
hold. That shifts the simulated world, as #205, #225 and #237 did
(`2026-11-18-job-evicted-tooth-seed-284.md`). `zig build check` then failed `sim-c1-teeth` on
two fixed seeds; every other tooth fired.

## `job_reuse_assigned`: also-seed 40 becomes 141

At 300 operations, `--c1`, the tooth's seed 40 passed (0 of 1). Searched with the fault on,
seeds 1 to 200: 28 fail, all J2 ("a run id was started a second time") but seeds 141 and 200,
which fail J4 ("one job ending was reported with two ended_at_ms values"). The range 30..60
still fails (seed 33, J2). The also-seed, which keeps a J4 hit in CI, moves to 141. With the
fault off (`sim_c1_reuse_world`) seed 141 passes, and so do seeds 1 to 60 (`sim-c1-reuse`'s
range), 0 of 60.

## `job_evicted`: seed 284 becomes 359

At 300 operations, `--c1`, the tooth's seed 284 passed (0 of 1). Searched with the fault on, upward
from 285 to the first hit as the earlier moves did (two processes, 285..364 and 365..444, each
stopping at its first hit): seeds 285 to 358 miss, seed 359 fails "J8: a run that no node started
was still open long after its start_by_ms" (seed 369 does too). With the fault off
(`sim_c1_evict_world_main 359 300 1 --c1 --strong --heal-at=177`) seed 359 passes, and
`sim-c1-worlds`' fix-on seeds 1 to 5 and 225 pass. The tooth's range, its canary (`359+1@300`) and
the fleet README row move to 359; the tooth stays sparse.
