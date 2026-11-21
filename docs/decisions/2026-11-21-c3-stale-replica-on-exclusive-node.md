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
- While a rollout has failed, nothing creates a replica of the failed generation. A removed
  replica of it is not replaced by `replace`; `scale_up` fills the service's count from the
  newest older generation a stale replica runs (its spec copied, as a replacement's is), and
  falls back to the failed generation only when no older replica is left to copy. No record
  keeps an older generation's spec (`Rollout` holds only `from`), so a failed first generation
  (`from` 0), or a failed rollout whose old replicas were all lost, can return to its count only
  at the failed generation. The two requirements conflict there, and the count wins: the halted
  convergence checks (sim_c0's `halted_converged`, sim_cluster's convergence step) require it,
  and creating nothing failed sim_c0's fuzz seed 1003 (a failed first generation) and
  `--c1 --strong --tenants --health` seeds 28 and 33. The supervisor may choose otherwise; the
  fallback is `newest_older`'s null in `scale_up`. A paused rollout's `scale_up` still creates
  nothing (R4); its count comes back through the one-for-one replacements.
- The surge bound (R2, `room`) applies to every replacement as before.

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

## Found, not fixed (pre-existing on 6f53b36, outside this fix)

- `--c3 --tenants` (with or without `--health`), an ungated combination, fails R2 on seeds 4, 8
  and 33 at 150 operations, the same on 6f53b36 without this fix; with `--health` seed 38 too.
  `--c3 --health` fails R1 on seed 4, also on 6f53b36. With the one-for-one replacements,
  `--c3 --tenants` fails R2 on seeds 8, 33 and 38 and passes seed 4; with `--health`, R2 on
  8, 33 and 38; `--c3 --health` still fails R1 on seed 4.
