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

`hold_stale` (`src/replica_controller.zig`), after `roll_of`: while the rollout starts nothing
(paused or failed), a dead stale replica whose start failed through the user's fault is held,
as a current one is, with a `hold_failed_replica` decision, and counts toward the service's
count. Refused (P1) and lost replicas stay dead. An active rollout still replaces it, at the
service's generation, so there it stays dead. `hold_pass` now runs after `roll_of` (it reads,
writes nothing); a rollout record that does not decode still halts the service after the holds.

Behaviour change: an old replica of a paused or failed rollout whose start fails through the
user's fault is no longer replaced until the rollout resumes or a new apply starts one.

Unit test (`rollout_controller_test.zig`), red before the fix: "an old replica of a failed
rollout whose start fails by the user's fault is held".

## Evidence

Seed 44959403353 at 200 operations passes (1,167 transactions). `sim_c0 <seed> fuzz 200` for
seeds 1..400 (ReleaseSafe): all pass.
