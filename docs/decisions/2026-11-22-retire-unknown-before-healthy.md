# A running stale replica whose health is unknown is retired before a healthy one

Date: 2026-11-22. Context: demo-c3 on PR #18 (head fabd921e), step 4d, "An apply during a
rollback wins": `witness, revision 210: R1: a retirement left fewer ready replicas than replicas -
max_unavailable`, with the rollout 5 → 7 at "0 new ready, 1 old retired".

## What happened

`zcube rollback app` (5 → 6) started its surge replica `app-14`; `zcube apply` (6 → 7) came
140 ms later, before `app-14` was ever probed healthy. To the rollout to 7, `app-14` is an old
replica: running, health `unknown`. By the health gate rule
(docs/decisions/2026-11-15-c3-rollout-health-gate.md) both controllers count a stale `unknown`
replica running, so `min_ready_ms` after it started the rollout controller counted four old
replicas ready and stored `budget.retire = 1` (four ready, floor three). The replica controller's
`choose_retired` took running stale replicas in number order and retired a healthy generation-5
replica, leaving two healthy and `app-14` still `unknown`: the witness, which counts healthy
replicas, saw R1 broken.

The rule and `choose_retired` are unchanged by PR #18, so this race is on `main` too; the demo hit
it when the apply landed inside the window between the surge replica's start and its first
healthy probe (about 2 s in the demo). sim-c3 cannot see it: its R1 counts running replicas, not
healthy ones (as the health gate decision says).

## Decision

`choose_retired` orders running stale replicas by health: those whose report says `unknown`
(with a health check) go before healthy ones. The budget a never-healthy `unknown` replica adds to
`budget.retire` is then spent on that replica, and the healthy replicas the floor rests on stay:
with `U` such replicas counted ready, the rollout controller allows at most `healthy + U - floor`
retirements, and retiring the `U` first loses at most `healthy - floor` healthy ones.

The health gate's counting rule is kept: a stale `unknown` replica still runs to both
controllers, so a rollback over checks that never settle still ends, and an agent restart's
`unknown` still keeps old replicas from being retired as unready.

## Consequences

- After an agent restart (every old replica `unknown`), the old replicas still retired first are
  the `unknown` ones, in number order as before; once some report healthy again, the rest go
  first.
- Test: `src/rollout_controller_test.zig`, "an apply over a rollout retires its never-healthy
  replica before a healthy old one (R1)" (fails without the change: a generation-1 replica is
  retired and generation 2's stays).
- No simulation tooth, for the reason above.
