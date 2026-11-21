# A trust policy's directories are checked as well as its file

*Decided 2026-11-21, by the 0.6.0 carry-over session (lane B5), on the fifth finding's NIT of
`2026-11-17-0.5.2-known-issues-to-0.6.0.md`.*

## Why

`src/trust_file.zig` refused a policy file that anyone but root or the process's own user could
write (ZC-E0106 at the server, ZC-E0505 at the agent), but not one in a directory others could
write. A file they write themselves is still refused (it is theirs), but whoever can write the
directory can rename the policy away, or put a link in its place to another file root owns that
parses as a policy (an older, weaker one), and the file check passes on it at the next start. A
policy others can replace gates no more than one they can rewrite.

## The rule

- The path is resolved (`realpath`) and every directory from the file's parent up to `/` must be
  owned by root or the process's effective user, and writable by neither group nor others, unless
  it is sticky (`/tmp`'s mode, 1777: only a file's owner may rename or remove it there).
- A directory that breaks this refuses the start with the same code the file check uses, with a
  cause naming the directory, its owner and its mode, and a fix that says to keep the policy in a
  directory such as `/etc/zcube` and `chmod go-w` the ones above it.
- No new code, bound or default: the codes are E0106 and E0505 as before, and their explanations
  (and `site/errors/`) now state the directory rule. A policy kept where the docs always said to
  keep one (`/etc/...`, a service user's own directory) is unaffected.
