# CI's sim-c3 and sim-c4 steps move to a job of their own

*Decided 2026-11-22, by the supervisor.*

The `sim` job ("simulations (sim-c0, sim-c1)") now exceeds its `timeout-minutes: 25`. Before C4
(PR #17) added the sim-c4 steps it took about 19 minutes (run 45028918367); with them, run
45037541586 (`main`) and run 45047029341 (PR #21) were both cancelled at 25 minutes during the
last step, `zig build sim-c4-teeth`. That left `main`'s CI red for every pull request.

The sim-c3 steps (sweep, negative tests) and the sim-c4 steps (seed 1, seed of the run, negative
tests) move, unchanged, to a new job `sim-mesh` ("simulations (sim-c3, sim-c4)"), with the same
`needs`, `if`, runner and 25-minute timeout, and its own cache entry (`sim-mesh`).
`.github/ci-changes.sh` is unchanged: `sim-mesh` runs on `code`, as `sim` does. `sim` is not a
matrix job, so the `sim-shards` aggregate is unchanged.

Where: `.github/workflows/ci.yml`; `docs/decisions/2026-11-09-sim-job-split.md` (the earlier split).
