# A run the job fence stops after its cancel was asked is reported cancelled

*Decided 2026-11-21, by the 0.6.0 carry-over session (lane B5), on finding 2 of
`2026-11-17-0.5.2-known-issues-to-0.6.0.md` (review 5927352205, item 4).*

When the runs read fails long enough for the job fence (#270) to stop a run, the start record
says `unreachable`. The cancel is judged from the runs read the agent makes after the heal, when
it reports the ending: if the server has committed a stop with cause `cancel` by then, the agent
reports the ending with cause `cancel`, so the job ends `cancelled`, not `failed`, cause
`unreachable`. (A read before the fence that carried the cancel would have had the agent stop the
run with cause `cancel` itself, so the fence never records `unreachable` for it.)

This includes a cancel committed after the fence had already killed the run: the user saw the job
still `running`, since its ending was not yet reported, and asked for the stop. The run is
stopped, so `cancelled` is a true answer to what was asked, and the rule does not try to tell
which of the two came first.

The rule is on the agent (`reported_cause` in `src/agent_jobs.zig`), on both ways a stopped run is
reported: `stopped` (the container's exit) and `lost` (the container is gone by the heal). It only
ever turns a recorded `unreachable` into `cancel`, and only when the server asked for the cancel; a
deadline, `not_started` or a fence with no cancel asked are reported as recorded. The record is
not rewritten. No new code, cause or bound.
