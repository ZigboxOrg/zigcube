# A halted rollout's stale replica on a node registered exclusive is removed (P1)

Status: implemented on `claude/060-b-c3-demo` (PR #6).

## The failure

CI's sim job, seed 44892876942 (`sim_cluster 44892876942 150 0 --c1 --strong --profile=mixed
--tenants --health`): "P1: a service replica held on an exclusive node past the bound". At the
failure, alpha's rollout to generation 3 had failed and kept its stale replica alpha-4
(generation 2) on node2, which an operator reinstall had made `tenant=a, exclusive=tenant`. The
same seed without `--health` passes only because rollouts finish before a relabel lands; with
health checks a rollout stays failed or paused long enough.

## Root cause (product)

`replica_controller.classify` judged only `live` and `held` replicas against their node's labels
(`refused_placement`). A stale replica is kept while its rollout is halted (failed or paused),
so one on a node registered exclusive stayed there for good. The lost-node path already treated
stale replicas as dead; the refused path did not.

## Fix

Every replica that is not already dead is judged against its node's labels; a refused one is
dead, removed and replaced. While the rollout starts nothing, the replacement runs the removed
replica's generation (`replace`'s templates, R4). No P1 bound changed.

## Replacing a forced removal while halted is repair (supervisor, 2026-11-21)

The first version of the fix left a gap the PR #6 review found: a halted rollout that removed
two or more replicas it was forced to remove (on lost nodes, or on nodes that now refuse them) in
one pass replaced none of them. Exactly 2 is enough: `replace` capped its creations at
`batch_replicas_max - removed`, which is 0 once two are removed, and the next pass went to
`scale_up`, which a pause stops; the service ran short until the resume. When the rollout had
failed instead (its rollback refused, ZC-E0128), `scale_up` was not stopped and created replicas
at the service's generation, the failed one.

The rule now:

- Replacing a forced-removed replica is repair, not rollout progress. While a service has stale
  replicas or its rollout is halted (paused or failed), each removal the service's count needs
  back is replaced in the same transaction, one for one, at the removed replica's generation.
  A transaction removes only as many dead replicas as it can also replace (`removals_max`: one,
  with `batch_replicas_max` at 2), so no replacement is ever owed to a later pass. The
  replacements are not limited by the rollout's budget or step; `batch_replicas_max` still
  bounds the rollout's own steps (new-generation creations and voluntary retirements) and the
  size of one transaction, so a node that loses many replicas is repaired over several passes.
- While a rollout has failed, nothing creates a replica of the failed generation while an
  older one can be copied. A removed replica of it is not replaced by `replace`; `scale_up`
  fills the service's count from the newest older generation a stale replica runs (its spec
  copied, as a replacement's is).
- **When no older replica is left to copy, the count wins (supervisor's decision, PR #6
  re-review).** A rollout that has failed with no older-generation replica remaining (a failed
  first generation, `from` 0, or a failed rollout whose old replicas were all lost) returns to
  its count through `scale_up`, which creates replicas of the failed generation. No record keeps
  an older generation's spec (`Rollout` holds only `from`), so there is nothing else to create,
  and leaving the service short failed the existing convergence checks: sim_c0's
  `halted_converged` (fuzz seed 1003, a failed first generation) and sim_cluster's convergence
  step (`--c1 --strong --tenants --health` seeds 28 and 33). The code is `newest_older`'s null
  in `scale_up`; its comment says the same. Since the second re-review (below) the rollout's
  `from` spec in `/history` is tried before the count wins, and the same `scale_up` repairs a
  paused rollout too.
- The surge bound (R2, `room`) applies to every replacement, and every replica whose container
  may still run counts toward it (re-review MUST, below).

### A refused replica still runs: R2 counts it (PR #6 re-review)

The first version of this rule broke R2: `roll_of` counted toward `live` only replicas that were
not dead, but a replica refused on a node registered exclusive is dead while its container still
runs, until its removal commits and its node stops it (then `stopping_orphans` counts it). Its
replacement, and a paired replacement of another dead replica, went past `replicas + max_surge`
(seed 17 of `--c3 --tenants`, among others). Now every replica `rollout_controller.live_report`
calls live counts, whatever its class (`roll_of`), as R2's checker counts it.

That leaves a conflict for a paused service at full surge: a refused replica's container fills
the room its paired replacement needs. The re-review's fix (`paused_unreplaced_max`) waited for
a removed container that was still stopping before it removed a dead replica the count needed
back. The second re-review found that wait unbounded (below); it is gone.

### P1 does not wait for room (PR #6 second re-review)

MUST: `paused_unreplaced_max` returned 0 while any removed container of the service was still
stopping (`Roll.stopping`). A container that never stops (its node partitioned, or its stop
failing) kept every refused replica of a paused service on its exclusive node for good, past
P1's bound: seed 90 (`sim_cluster 90 355 2 --c3 --strong --tenants --lease-ttl-ms=8496
--replicas-pct=100 --heal-at=309`), now in `c1_regressions`. SHOULD: with `max_surge` 0 the
refused replica's own container fills the room, so it was removed unreplaced and a paused
service stayed short until the resume. Both are fixed; no issue was filed.

The rule now:

- With no room (`room` 0), dead replicas are removed unreplaced, up to a batch, at once
  (`removals_max(0)`); no removal waits on a stopping container. P1 and R2 win in the moment.
  Dead replicas whose container may still run go first (`dead_to_remove`).
- The count is made up later by `scale_up`, which a halted rollout (paused or failed) now runs,
  once room frees. Its replicas run an older generation, never the new one while one can be
  copied: the newest older generation a stale replica runs (`newest_older`), else the rollout's
  `from` generation as `/history/<service>/<from>` holds it (`history_template`, read through
  `history.usable`; a history record is never changed, and an apply that trims one moves the
  service key the batch expects). Only with neither (a first generation, or its history
  trimmed) does the count win at the service's generation, as the supervisor decided for the
  failed case. The `from` fallback applies to a failed rollout too, so the failed generation is
  now created only when `/history` has no `from` record either.
- Behaviour change: a user's scale-up of a paused service now creates replicas (at the older
  generation) instead of waiting for the resume. The seam-b test "a pause between the read and
  the commit fails a scale-up of a failed rollout" still sees the interleaved commit fail; its
  end state now has the count made up at generation 1.

R4's checker (`sim_c3.step_problem`) accepts a paused transaction that creates more than it
removes only as such a scale-up (`paused_scale_up`): a `scale_up` decision on the service, no
dead replica removed and none retired, and the service, counted as `scaled_down` counts it,
no higher than `replicas` after it. A creation at the new generation is accepted in it only
when no replica of an older spec is left (`has_older`).

Unit tests (`rollout_controller_test.zig`), each red before the fix: "a refused replica leaves
its exclusive node while a removed container is still stopping" (an orphan report on node2 that
never stops; node1 must be empty within the passes, R2 checked after each, and the count comes
back with nothing of the new generation started) and "a paused service with max_surge 0 gets
back a replica moved off an exclusive node" (every old replica was on node1, so the replacement
comes from `/history`).

Unit test: "a refused replica still running holds its place in the surge bound (R2)" (a paused
rollout at its surge, one replica stopped on node2 and node1 registered exclusive, R2's count
checked after every pass with the removed replicas' reports kept); it fails on the per-pass R2
check without the `roll_of` change. Seed 17 (`17 150 0 --c3 --tenants --heal-at=108`) is in
`c1_regressions`: it passes on e149625 (the parent), fails on 3bb7952, passes with the fix.

Unit tests (`rollout_controller_test.zig`): the paused relabel test now asserts that the count is
restored at both generations; a paused service with every replica on the relabelled node is
repaired one per pass; a failed rollout's replicas moved off a node come back at generation 1,
none at generation 2; and a failed rollout's service scaled from 3 to 5 gets one more generation
1 replica and no generation 2 one.

## The C3 checker (`sim_c3.zig`)

R1 and R4 count a removed old replica as a retirement unless it stopped or its node is lost. The
removal of a replica on a node with an `exclusive` label is forced by P1 as a lost node's is, so
`step_of` now counts it as dead, not retired; otherwise a paused rollout whose stale replica is
moved off an exclusive node would fail R4 ("a paused rollout retired a replica"). This does not
weaken R1 or R4 for any replica on a node that takes it.

## Evidence

- The seed passes with the fix (`refused holds=0`) and is in `c1_regressions`.
- `--seeds 1..60 150 --c1 --strong --tenants --health`: 0 of 60 failed. `--seeds 1..40 150
  --c3`: 0 of 40 failed.
- Unit test (`rollout_controller_test.zig`): an old replica of a paused rollout on a node
  registered exclusive is moved off it; it fails without the fix.

## Sweeps (PR #6 re-review, ReleaseSafe `sim_cluster`)

Failing seeds of each sweep on the parent (e149625), the re-reviewed head (3bb7952) and the
fix. Commands: `sim_cluster --seeds 1..40 150 --c3 --tenants`, the same with `--health`,
`--seeds 1..60 auto --c3`, `--seeds 1..40 150 --c3` and `--seeds 1..40 150 --c3 --health`.

| Sweep | e149625 | 3bb7952 | fix |
|---|---|---|---|
| `--c3 --tenants` | R2: 4 8 15 24 30 33 | R2: 8 15 17 24 30 31 33 34 37 38 40 | none |
| `--c3 --tenants --health` | R2: 4 8 33 38 | R2: 8 9 15 17 31 33 38 | none |
| `auto --c3` (1..60) | R2: 4 6 8 12 16 19 30 33 37 39 44 48 54 56 57 | R2: 4 6 8 9 11 12 16 17 19 23 27 33 37 43 44 45 46 48 53 54 56 57 58 | none |
| `--c3` | none | none | none |
| `--c3 --health` | R1: 4 24 34 | R1: 4 24 | R1: 4 24 |

Every R2 failure, on the parent too, had the same cause: a dead replica whose container still
ran was left out of the surge count. `--seeds 1..60 150 --c1 --strong --tenants --health` still
passes all 60.

## Sweeps (PR #6 second re-review, ReleaseSafe `sim_cluster`)

With the fix: `--seeds 1..40 150 --c3`, the same with `--tenants`, and with `--tenants --health`:
0 of 40 failed each. `--seeds 61..140 auto --c3`: 0 of 80. `--seeds 1..60 auto --c3`: 1 of 60,
seed 19, R4 (below). Seed 90 fails P1 on d5a2650 and passes with the fix; seed 216 of
`--seeds 141..260 auto --c3` fails P1 on d5a2650 too and passes with the fix.

## Found, not fixed (pre-existing, outside this fix)

- R4, "a paused rollout started a replica of the new generation": seed 162 of `--seeds
  141..260 auto --c3` on d5a2650 and with the fix (`sim_cluster 162 389 10 --c3 --strong
  --tenants --lease-ttl-ms=8053 --replicas-pct=200 --heal-at=266`), and seed 19 with the fix
  (`sim_cluster 19 695 3 --c3 --strong --tenants --lease-ttl-ms=10000 --replicas-pct=200
  --heal-at=486`; it passes on d5a2650 only because the world diverges earlier). Seed 19's
  transaction: alpha was deleted and applied again (generation 1, its first rollout paused)
  while alpha-104, a replica of the deleted incarnation at generation 13, was left; its node
  was lost and `replace` replaced it one for one at the service's spec, since
  `replacement_templates` copies only a removed replica of a lower generation. The checker
  counts alpha-104 as old (`is_new` is false: another spec) and the replacement as a start.
  Whether a replica of a deleted incarnation is the service's at all (the controller never
  compares the service key's `create_revision` for replicas) is for the supervisor.

- `--c3 --health` fails R1 at seeds 4 and 24 at 150 operations, on the parent (with 34) and on
  3bb7952 alike. Replays: `sim_cluster 4 150 0 --c3 --health --heal-at=146` and
  `sim_cluster 24 150 0 --c3 --health --heal-at=97`.
