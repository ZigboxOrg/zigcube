# J12 after a lost disk: a claimed run the policy refuses ends `refused`

*Decided 2026-11-19, by the fix session for the `sim-c1 -Dtenants` gate failure.*

## What failed

`zig build check`'s fresh-seed `sim-c1 -Dtenants` gate failed on `main` 6f52fcb:

```
sim_cluster 7485507574660471565 100 0 --c1 --strong --profile=mixed --signed --tenants
FAILED: J12: a run its node's policy refuses ended otherwise (seed 7485507574660471565, at 367779 ms)
```

`--shrink` brings it to 15 operations
(`sim_cluster 7485507574660471565 15 0 --c1 --strong --signed --tenants --heal-at=84`). It
reproduced with Zigbox at d7515ea and f333434; the pin is not the cause.

## What happened

One node, whose policy requires a signature that job `jb-1` does not carry. The node committed
its claim of `jb-1` (`/job-observed/node1/jb-1` = `claimed`). Before the next pass reached
`begin`, which judges the policy before anything is fetched or started, the tenant world's
operator relabel (`Cluster.relabel_node`: a host crash that loses the disk, state directory and
containers, as a reinstall does) hit node1. The restarted agent found its own `claimed`
observation, no start record and no container, took `Work.unknown`, and reported the run `lost`
with ZC-E0522; the server ended it `failed unknown`. J12's at-rest half (a terminal run on a
refusing node, with no stop cause, ended `refused`) caught it.

It needs all three flags only because they make the window likely: `--signed` gives the refusing
policy, `--tenants` adds the disk-losing reinstalls (`--strong` alone wipes on every other host
crash, rarely in that window), and `--c1` adds the per-revision taps that move the schedule.

## Decision

It is an agent defect, not a false J12. The verdict is a function of the run and the node's
policy alone, and `begin` judges it before the `claimed` start record is written and anything
starts. So a run the policy refuses, of which the store holds only a `claimed` report (no
`running`), was never started by this node, and `lost` (which reads as "it may have run") is
wrong for it. `not_started` already applies the same rule to a refusal whose report was lost.

`Work.refused_unstarted` (`src/agent_jobs.zig`): in `unknown`, with no container, a `claimed`
observation, the run still served and the policy refusing it, the run is reported `refused`
under its current assignment. A `running` report proves a start under the policy that held then,
so that run stays `lost` whatever the policy says now; a container on the node is still stopped
as before. A policy changed at the reinstall could in principle make a run that was admitted
and started (but never reported `running`) read `refused`; nothing of it is left on the node,
and the refusal is what the node will do with it from now on, so `refused` is the truer ending.

## Guards

- Unit test "a claim whose start record and container were lost is refused when the policy
  refuses it" (`src/agent_jobs_test.zig`): fails without the fix (`expected .refused, found
  .lost`); its second half keeps a trusted run `lost` with ZC-E0522.
- Both replay lines in `c1_regressions` (`build.zig`, `zig build sim-c1-regressions`); both fail
  without the fix.

Where: `docs/agent.md` ("Runs", rule 2), `docs/core.md` ("Signed jobs").
