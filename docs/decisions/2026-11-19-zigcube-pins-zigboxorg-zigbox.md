# Zigcube pins Zigbox from ZigboxOrg, at the release-evidence head

*Decided 2026-11-19, by the owner ("Ours", in the restore session).*

The GitHub organisation `Zigbox` is suspended, so the old pin
(`github.com/Zigbox/zigbox/archive/82132cf….tar.gz`, Zigbox 0.5.2) no longer downloads, and
`zig build` fails on a fresh cache. Both repositories were restarted in `ZigboxOrg` as single
squashed commits (Zigbox `d7515ea`, 0.5.3; Zigcube `6f52fcb`).

- **The pin** moves to `github.com/ZigboxOrg/zigbox/archive/f333434….tar.gz`, the head of Zigbox's
  branch `claude/stoic-carson-jnfdb1`: 0.5.3 plus the restored `.github`, the #186 release-evidence
  work and GitButler. The owner chose this head over `d7515ea` ("ours"). It is a branch commit, not
  a tag: when that branch merges, or 0.6.0 is tagged, the pin moves to the merge commit or the tag.
- **Links.** Every `github.com/Zigbox/` link outside `docs/` (code, error pages, the console,
  `ops/`, README, site) now names `ZigboxOrg`. Briefs, decisions, retros and other records keep
  the links they were written with.
- **Not changed:** `DIAGNOSTICS.md` is left as it is. It already differs from Zigbox's canonical
  copy (fix markers `needs_root` and `template`, codes `10xx` and `12xx`, `zbx doctor`'s JSON
  report), so it is synced in one change of its own, not here.

Where: `build.zig.zon`, AGENTS.md (the fetch workaround: `curl` of the tarball works again).
