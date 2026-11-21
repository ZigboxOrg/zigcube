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

## Found, not fixed (pre-existing on 6f53b36, outside this fix)

- `--c3 --tenants` (with or without `--health`), an ungated combination, fails R2 on seeds 4, 8
  and 33 at 150 operations, the same on 6f53b36 without this fix; with `--health` seed 38 too.
  `--c3 --health` fails R1 on seed 4, also on 6f53b36.
- A paused service that loses more than `batch_replicas_max` (2) replicas in one pass (lost or
  refused) removes them all but replaces none past the batch: the next pass goes to `scale_up`,
  which a pause stops, so the service runs short until the resume.
