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
  in `scale_up`; its comment says the same. A paused rollout's `scale_up` still creates nothing
  (R4); its count comes back through the one-for-one replacements.
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
the room its paired replacement needs, and a removal without its replacement leaves the count
owed to a later pass that a paused rollout does not make (R4 forbids its `scale_up`). The rule
(`paused_unreplaced_max`), when the surge leaves no room (`room` 0) and something is missing:

- Dead replicas the count does not need back (beyond `replicas` against the live, held and
  stale ones kept) are removed unreplaced, up to a batch.
- A dead replica the count needs back waits while a removed replica's container is stopping
  (`Roll.stopping`): the stop frees the room, and the next pass replaces it one for one.
- With none stopping, waiting frees nothing, and one is removed unreplaced: P1 and R2 win over
  the paused count. Without stopping containers this happens only with `max_surge` 0 (dead
  replicas alone fill the room only then); the service is then short until the rollout resumes.

Dead replicas whose container may still run go first (`dead_to_remove`), so their places in the
surge bound are freed soonest. A paused service now ends at `replicas`, not at its surge: the
two paused relabel tests assert that. `removals_max(0)` still returns a whole batch; that is
right when nothing is missing, and the no-room case no longer reaches it for a paused service.
For a failed rollout the unreplaced removals are made up by `scale_up`, and for an active one by
its starts; both wait for room.

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

## Found, not fixed (pre-existing, outside this fix)

- `--c3 --health` fails R1 at seeds 4 and 24 at 150 operations, on the parent (with 34) and on
  3bb7952 alike. Replays: `sim_cluster 4 150 0 --c3 --health --heal-at=146` and
  `sim_cluster 24 150 0 --c3 --health --heal-at=97`.
