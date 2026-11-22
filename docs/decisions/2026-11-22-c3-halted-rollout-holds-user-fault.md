# A halted rollout holds an old replica whose start failed through the user's fault

Status: implemented on `claude/060-b-c3-demo` (PR #6).

## The failure

CI's `simulations (sim-c0, sim-c1)` job on d5a2650 (run 44959403353) failed `zig build sim-c0
-Dseed=44959403353 -Dops=200`: "there are more decisions than the check reads" (49,745
decisions, past the check's 64 pages of 500). It still failed on 19fcee1 merged with `main`.

## Root cause (product)

Service `beta` was applied with a digest no node holds (generation 10); its rollout failed
(ZC-E0304) and rolled back to generation 2's spec as generation 11, whose digest was missing
too, so that rollout failed as well, `from` 10. Generation 10's replicas were now stale and
stopped (`start_failed`, blame `user`), so `classify_one` called them dead: only a current
replica is held for the user's fault. A halted rollout replaces a dead old replica with a copy
of its own spec (R4, `replacement_templates`), so each replacement ran generation 10 again and
failed the same way, pass after pass, until the next apply: four decisions per replica, without
end. The hold decisions of the generation-11 replicas were rewritten too, because the churn
pushed them out of `already_held`'s scan.

## Fix

`hold_stale` (`src/replica_controller.zig`), after `roll_of`: while the rollout is halted
(paused or failed), a dead stale replica whose start failed through the user's fault is held,
as a current one is, with a `hold_failed_replica` decision, and counts toward the service's
count. An active rollout still replaces it, at the service's generation, so there it stays dead.
`hold_pass` now runs after `roll_of` (it reads, writes nothing); a rollout record that does not
decode still halts the service after the holds.

A stopped replica is already dead in `classify_one`, and `classify` judges the node only of
replicas that are not dead, so `hold_stale` judges the node itself before it holds one
(PR #6 review MUST; the first version skipped on `item.refused` and `item.lost`, which were never
set for such a replica, so a held old replica on a node registered `exclusive` stayed there for
good, against P1):

- `refused_placement`: on a node whose labels refuse a service replica, it stays dead and is
  removed through that node (`remove_refused`, P1), and replaced as any other refused replica.
- `lost_placement`: a report without a tenure (C0) from a node judged lost past its grace leaves
  it dead (`remove_lost`). A C1 report is admissible only while its node's status is `ready`
  (`admissible_in`), so a C1 replica on a lost node has no observed record and is never held;
  the check is real only for tenure-less reports, and costs one lookup.

Held stale replicas count as stale for the surge a halted rollout keeps (`ServicePlan.held_stale`,
`halted` in `reconcile_service`). Without that, a rollout paused at its surge whose every
remaining old replica is held had `plan.stale == 0`, so `wanted` fell to `replicas` and
`scale_down` removed one replica with a decision no one asked for. That was not harmless: the
victim order takes a replica that is not running first, which can be the surged new one not yet
reported running, so the pause undid the step it paused at.

`hold_stale` keys on the rollout being paused or failed, not on `!roll.starts`: a complete
rollout starts nothing either, but a stale replica left beside it is no step a rollout paused
at. Keyed on `!roll.starts`, with held stale replicas keeping the surge, sim-cluster seed 385
(`385 98 2 --c3 --strong --tenants --lease-ttl-ms=8082 --replicas-pct=100 --heal-at=94`, now in
`c1_regressions`) kept service `beta`, scaled to 0 under a complete rollout, at its broken old
replica for good ("a service lacks replicas" at rest).

Behaviour change: an old replica of a paused or failed rollout whose start fails through the
user's fault is no longer replaced until the rollout resumes or a new apply starts one.

Unit tests (`rollout_controller_test.zig`), each red before its fix: "an old replica of a failed
rollout whose start fails by the user's fault is held"; "a held old replica of a failed rollout
leaves a node registered exclusive (P1)" (fails `expected 0, found 1` replicas on node1 without
the node check); "a rollout paused at its surge keeps it while it holds every old replica left"
(fails `expected 1, found 0` new replicas without `held_stale`).

## Evidence

Seed 44959403353 at 200 operations passes (1,167 transactions). `sim_c0 <seed> fuzz 200` for
seeds 1..400 (ReleaseSafe): all pass.
