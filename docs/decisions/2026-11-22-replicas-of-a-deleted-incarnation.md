# A replica of a deleted incarnation is removed, never counted, replaced nor copied (#16)

*Decided 2026-11-22, by the supervisor (the rule, and the sign-off below); implemented in the
slice on `claude/060-b-i16`.*

Issue: ZigboxOrg/zigcube#16, a blocker of 0.6.0 RC1.

## The failure

ReleaseSafe `sim_cluster --seeds 341..480 auto --c3` failed seed 357 (`sim_cluster 357 119 14
--c3 --strong --tenants --lease-ttl-ms=10000 --replicas-pct=300 --heal-at=88`), "R4: a paused
rollout started a replica of the new generation". Seeds 162 (`162 389 10 --c3 --strong --tenants
--lease-ttl-ms=8053 --replicas-pct=200 --heal-at=266`) and 19 (`19 695 3 --c3 --strong --tenants
--lease-ttl-ms=10000 --replicas-pct=200 --heal-at=486`) fail the same way.

## Root cause

A service deleted and applied again before the replica controller's orphan pass ran keeps the
earlier incarnation's `/replicas/<service>/*` keys. The controller matched replicas to the service
by name only, so it took them for the new incarnation's: it counted them toward `replicas`,
replaced a dead one one for one, rolled out a stale one and copied one as a halted rollout's
template. In seed 357 an old replica on a lost node was replaced, at the new spec, while the new
incarnation's rollout was paused (R4); seed 19 is the same failure.

Seed 162 is the second defect, below: its paused scale-up copied a stale replica of a generation
above the rollout's `from`. With the fix it passes with no incarnation removal (`foreign=0`).

## Decision

A replica whose key's `create_revision` is older than the service key's `create_revision` belongs
to an earlier incarnation (`earlier_incarnation` in `src/replica_controller.zig`). The controller
creates a replica only in a transaction that compares the service's revision, so every replica of
the current incarnation has a newer key. Such a replica is:

- removed first, before anything else is done for the service (`remove_foreign`): a `scale_down`
  decision on the service, "service S was deleted and applied again; stopping A, B, which belong
  to its earlier incarnation", and a `stop_replica` for each, at most `batch_replicas_max` per
  transaction. The existing action is reused: no new decision action and no new code;
- never counted toward `replicas`, replaced, rolled out nor copied as a template. While one is
  left the service gets nothing else, so every count the controller makes is of the current
  incarnation. Its container still counts toward the surge bound (R2) until it stops.

This is the job rule of `docs/decisions/2026-11-18-job-incarnation.md` applied to replicas.

## The rollout controller (PR #18 review SHOULD 1)

The first version of this slice left the rollout controller matching replicas by name, and said
the window until the old replicas are removed was harmless. It was not: `view`, `count_deaths` and
`observe` took an old replica whose generation is at least the new one's and whose spec is the
same as new (`is_new`), which is the normal case when the same manifest is deleted and applied
again. Old replicas of another spec counted as the new incarnation's old records, so a rollout of
the new incarnation began over replicas it does not own, could step or complete on the old ready
ones, and counted old deaths against `rollout_restarts_max`. Removal takes one pass per
`batch_replicas_max` replicas, and a conflicted batch takes more.

The rollout controller now uses the same test (`replica_controller.earlier_incarnation`, exported;
no second copy): `observe` and `count_deaths` take no old-incarnation replica as new, and `view`
counts one only as live and stopping (`old_live`, `old_stopping`) while its report says it runs,
as it counts a stopping orphan, so the surge bound (R2) still covers its container. It is never an
old record (it starts no rollout), never new, never ready. The unit test "replicas of a deleted
incarnation start no rollout of the new one, nor count in it (#16)"
(`src/rollout_controller_test.zig`) deletes `web` halfway through a rollout, applies the same
manifest again and runs the rollout controller alone: before the fix it began a rollout of the
new incarnation. The `sim-c3-teeth-incarnation` fault blinds both controllers.

## The template of a halted scale-up (PR review SHOULD 1)

`scale_up` under a paused or failed rollout picked its template by generation number
(`newest_older`). A rollback's rollout has the failed release among its stale replicas at a
generation above its `from`, so a paused rollback recreated the release it was rolling back from.
The template is now chosen by role: the rollout's `from` as a stale replica runs it (the lowest
number, `from_replica`), else as `/history` holds it for this incarnation (`history_template`),
else the newest older stale replica, else the service's generation (a first generation). A
replacement of a removed replica under a halted rollout still copies that replica's own spec
(`replacement_templates`). The unit test "a paused rollout's scale-up runs its from generation,
never a newer stale one (#16)" (`src/rollout_controller_test.zig`) fails with the old choice.

## Behaviour change (SHOULD 3), signed off

A paused service's scale-up now creates replicas at an older generation, the rollout's `from`,
not at the paused new one. The supervisor signed off on 2026-11-22: "I accept this change. It
keeps the count and R2/P1 without advancing a paused rollout." `docs/core.md` ("sim-c3") says so.

## Checks and teeth

- R4 (`src/sim_c3.zig`) counts a removed replica of an earlier incarnation apart from dead and
  retired ones, and fails a transaction that removes one and creates a replica of the service:
  "R4: a replica of an earlier incarnation was replaced". Old-incarnation replicas are left out of
  `counted` and `has_older`. The report shows `foreign=`.
- SHOULD 2: R4 accepts a paused scale-up at the new generation only when no replica of an older
  spec is left and `/history/<service>/<from>` of this incarnation is absent (`has_from`). The
  report counts those as `first=`.
- `sim-c3-teeth-incarnation` (`c1_teeth_rollout_incarnation`: the controller ignores
  incarnation) must fail "R4: a replica of an earlier incarnation";
  `sim-c3-teeth-template` (`c1_teeth_rollout_template`: `history_template` returns null) must
  fail "R4: a paused rollout started a replica of the new generation". `sim-c3-teeth` runs both,
  and CI's `sim` job runs `sim-c3-teeth`. Both are sparse at the default 100 operations, so they
  run drawn worlds (`auto`; `auto_shape` in `c1_teeth_roots`, measured 2026-11-22):
  `rollout_incarnation` seed 357, and seed 19 (the only hit in 1..80) as an `also_seeds` run;
  `rollout_template` seeds 1 to 10 (caught at 4), and seed 12. The fixed runner passes all of them.
  `also_seeds` runs of a sim-c3 tooth now pass `--c3` (they passed `--c1` only, and no sim-c3
  tooth had one).
- Seeds 357, 162 and 19 are in `c1_regressions`. Each fails before the fix.
- Merging main (C4 slices 1 to 5) changed the drawn worlds: `auto` now turns the mesh on, and
  the `--strong` world changed with C4 slice 3. None of the seeds above reaches either fault any
  more (each tooth's runner passes them). Re-measured on the merge, 2026-11-22:
  `rollout_incarnation` fails at seeds 127 and 160 of 1..240, `rollout_template` at 11 and 12 of
  1..12, and the fixed runner passes all of them; the teeth run those seeds now. Their concrete
  replay lines (with `--mesh`) are added to `c1_regressions`, the first two failing with the
  incarnation tooth and the last two with the template tooth; the three older lines stay.

## A correction to an earlier decision

`docs/decisions/2026-11-22-c3-halted-rollout-holds-user-fault.md` says "An active rollout still
replaces it, at the service's generation, so there it stays dead." That sentence is corrected
here, and this file supersedes it on that point only: an active **or complete** rollout still
replaces it, at the service's generation, so there it stays dead; only a halted (paused or failed)
rollout holds it. The code never matched the narrower statement. The earlier file is left as
merged (`docs/decisions/README.md`: a decision is never edited once merged).

Where: `src/replica_controller.zig`, `src/rollout_controller.zig`, `src/sim_c3.zig`,
`docs/core.md` ("sim-c3"), `build.zig` (`c1_teeth_roots`, `c1_regressions`).
