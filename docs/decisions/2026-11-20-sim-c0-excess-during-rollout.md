# sim-c0's excess check allows a rollout's surge for as long as the rollout runs

Date: 2026-11-20. Lane B, C3 brought onto main.

## What failed

`zig build check` on f8f98f34 failed `sim-c0` at seed 14626139123688608174 (`sim_c0 <seed>
fuzz 200`): "more containers run than desired". The same seed passes on main, which has no
rollouts.

At the failure, service `gamma` wants 5 replicas at generation 11. It runs 4 new replicas and 2
old ones: 6, its `max_surge` of 1 over. Its rollout had been under way, with that surge, for 34 s
of store-up time when an automatic rollback (generation 11, reason `rollback`) began. The fuzz's
`Excess` check fails any excess that lasts more than `excess_ms_max` (30 s). `desired_total`
counted the surge only for a rollout that was halted (paused or failed, `rollout_controller.halted`),
not for one still in progress or rolling back.

## The decision

The check is wrong, and the controllers are right. A rollout keeps up to `max_surge` extra
replicas for as long as it runs: one new replica at a time, each ready for `min_ready_ms`, under
faults and store outages. That can last longer than any fixed time short of its deadline. When the
deadline passes, the rollout fails, and a failed rollout is halted, so the surge stays allowed.
R1 in `sim_c3.zig` (sim-c3) already bounds the surge at every revision.

`desired_total` now adds `max_surge` while the service's rollout of its current generation has not
completed (`rollout_controller.surging`: progressing, paused, rolling back or failed). That is the
same single read of the rollout key that `halted` made, so the simulated world is unchanged.
`converged` still uses `halted`: after the heal, a rollout that can finish must have finished.

The check keeps its teeth for any excess beyond the surge, and for any excess in a service with
no rollout under way.

## Checked

- The seed passes with the change.
- `sim_c0 N fuzz 200` passes for seeds 1 to 400.
