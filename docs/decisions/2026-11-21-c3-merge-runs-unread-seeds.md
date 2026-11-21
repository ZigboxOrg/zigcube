# `sim-c1-runs-unread` moves to new seeds after C3's merge

Date: 2026-11-21. Status: implementer's decision (0.6.0 plan item B3, branch
`claude/060-b-c3-demo`); no check weakened.

CI's `simulations (sim-c1 worlds, burst)` job failed at a0cb607 on `sim_c1_runs_unread --seeds
2..2 100 --c1`: "a container runs that no replica assigns to its node" (step: healed), not J6.
C3's merge shifts the simulated world (as in `2026-11-20-c3-merge-tooth-seeds.md`), and the pinned
seeds 2, 18 and 30 (picked on 2026-11-15 as seeds that failed J6 before the job fence) no longer
fit: seed 2 now falls into the world's known artefact, and seeds 18 and 30 no longer fail J6 with
the fence off.

## The artefact

The tooth fails a node's whole runs read while any of its runs has a stop asked. The job pass then
fails and the step's later stages (`Agent.stages`: orphan containers, orphan records, the flush)
do not run, so a replica container that rollouts or deletes left behind is never stopped and
`track_unassigned` fires at the heal. C3's rollouts replace more replica containers, so more seeds
hit it. Seed 2's failure is that agent bug, not an accepted property of the world: `Agent.stages`
skips the orphan stop after a failed job pass though the loading succeeded, and a follow-up fixes it. Every seed of 1 to 40 that fails in this world (2, 4, 7, 12, 13, 14, 22, 23, 25, 31, 33,
38) passes in the plain `sim_cluster <seed> 100 0 --c1`.

## The search

Seeds 1 to 120, 100 operations, `--c1`, with the job fence switched off (`job_fence_at_ms`
returning null, a local edit, not committed) and with it on:

- J6 with the fence off: 2, 4, 7, 14, 22, 23, 25, 32, 34, 41, 43, 51, 53, 55, 56, 64, 67, 70,
  71, 80, 83, 89, 97, 102, 106, 111, 112, 117.
- Of those, passing every check with the fence on: 32, 34, 43, 56, 67, 71, 80, 83, 89, 97, 102,
  106, 111.
- With the fence on, no seed of 1 to 120 fails J6 (33 fail: J8, "a service lacks replicas",
  "a running replica was never reported", or an unassigned container).

The step's seeds become 32 (kept), 34, 43 and 56.
