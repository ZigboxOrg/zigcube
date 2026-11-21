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

- The path is walked as given (a relative one from the working directory), one component at a
  time, without following a symbolic link unseen: every directory that holds a component, from
  `/` down, must be owned by root or the process's effective user, and writable by neither group
  nor others, unless it is sticky (`/tmp`'s mode, 1777: only a file's owner may rename or remove
  it there). A link's own directory is judged, then its target is walked in its place, so the
  target's directories are judged too, and a directory reached through a link is judged where it
  is. At most `trust_policy_links_max` (40, Linux's own limit) links are followed.
- In a directory others may write (the sticky exception), whoever made an entry owns it and may
  point it anywhere: so every entry the walk passes there (a link, a directory, the policy file
  itself) must be owned by root or the process's effective user, the rule the kernel's
  `fs.protected_symlinks` applies to links (PR #10's re-review: the walk reads a link with
  `readlinkat`, which that rule does not cover, so a link uid 65534 planted in `/tmp` was
  followed). It is stricter than the kernel, which also accepts a link the directory's owner
  owns. The cause names the entry, what it is and its owner.
- In such a directory an entry must also live on the directory's own mount: one that is a mount
  root (`STATX_ATTR_MOUNT_ROOT`), or whose mount id (`stx_mnt_id`) differs from the directory's,
  is refused (PR #10's third review: a user may mount a FUSE filesystem over a name they made,
  and its root reports any owner and mode its daemon chooses, root's 0644 included). Where the
  kernel reports no mount id (before Linux 5.8), the device (`stx_dev`) is compared instead. The
  mount id decides when there is one, not the device: an overlay with layers on several
  filesystems, or a btrfs subvolume, can report another device for an entry on the directory's
  own mount, and refusing those would refuse a good policy in a container's `/tmp`. A directory
  only root or the process's own user can write may hold mount points as before (`/etc` on its
  own filesystem, say): whoever could mount there could rewrite the policy anyway.
  The flag is read as the kernel's bit 0x2000, not through the pinned std's `STATX_ATTR`,
  whose packed struct puts `MOUNT_ROOT` (and its other flags) at the wrong bits.
- A cause says why before it names a path, and names the policy's path last: a cause is cut at
  `diag_field_bytes_max` (200 bytes), and with the paths first an ordinary path cut the reason
  away (the same review). A lookup that fails says which name and why (`statx` ENOENT is "no
  such file or directory", EACCES "permission denied searching a directory above it").
- A component followed by a separator must be a directory (or a link to one), as `open(2)`
  requires (ENOTDIR): `trust.zon/` and `trust.zon/../trust.zon` are refused, not resolved
  textually. A path that cannot be resolved says why: the working directory unreadable, a link
  unreadable, the path past Linux's limit once its links are followed, or the opened file's own
  path unreadable (`/proc` not mounted).
- The walk ends on a file with no link left in its path. That path is opened without following a
  link, the file is judged again through its descriptor (`fstat`), the descriptor's own path
  (`File.realPath`) must be the walked one, and the policy is read from that descriptor
  (PR #10's review: resolving the whole path first judged only the target's directories, so a
  link put in a directory others may write passed).
- A directory that breaks this refuses the start with the same code the file check uses, with a
  cause naming the directory, its owner and its mode, and a fix that says to keep the policy in a
  directory such as `/etc/zcube` and `chmod go-w` the ones above it.
- No new code, bound or default: the codes are E0106 and E0505 as before, and their explanations
  (and `site/errors/`) now state the directory rule. A policy kept where the docs always said to
  keep one (`/etc/...`, a service user's own directory) is unaffected.
