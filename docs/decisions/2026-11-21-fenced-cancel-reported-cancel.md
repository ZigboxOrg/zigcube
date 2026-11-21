# A run the job fence stops after its cancel was asked is reported cancelled

*Decided 2026-11-21, by the 0.6.0 carry-over session (lane B5), on finding 2 of
`2026-11-17-0.5.2-known-issues-to-0.6.0.md` (review 5927352205, item 4).*

When the runs read fails long enough for the job fence (#270) to stop a run, the start record
says `unreachable`. If the agent's last good read of that run already carried the server's stop
with cause `cancel`, the agent reports the ending with cause `cancel`, so the job ends
`cancelled` as asked, not `failed`, cause `unreachable`. The rule is on the agent
(`reported_cause` in `src/agent_jobs.zig`): it only ever turns a recorded `unreachable` into
`cancel`, and only when the server asked for the cancel; a deadline, `not_started` or a fence with
no cancel asked are reported as recorded. The record is not rewritten, so a later read cannot
change what the agent reports. No new code, cause or bound.
