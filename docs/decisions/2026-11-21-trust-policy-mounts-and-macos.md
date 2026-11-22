# The trust policy's walk: mounts in shared directories, reasons first, and macOS

*Decided 2026-11-21, by the slice (0.6.0 RC1 review follow-ups of PR #10).* It adds to
`2026-11-21-trust-policy-directories.md`, which stands; nothing there is replaced.

- In a directory others may write (sticky, as `/tmp`), an entry the walk passes must also live
  on the directory's own mount: one that is a mount root (`STATX_ATTR_MOUNT_ROOT`), or whose
  mount id (`stx_mnt_id`) differs from the directory's, is refused (PR #10's third review: a user
  may mount a FUSE filesystem over a name they made, and its root reports any owner and mode its
  daemon chooses, root's 0644 included). Where the kernel reports no mount id (before Linux
  5.8), the device (`stx_dev`) is compared instead. The mount id decides when there is one, not
  the device: an overlay with layers on several filesystems, or a btrfs subvolume, can report
  another device for an entry on the directory's own mount, and refusing those would refuse a
  good policy in a container's `/tmp`. A directory only root or the process's own user can write
  may hold mount points as before (`/etc` on its own filesystem, say): whoever could mount there
  could rewrite the policy anyway. The flag is read as the kernel's bit 0x2000, not through the
  pinned std's `STATX_ATTR`, whose packed struct puts `MOUNT_ROOT` (and its other flags) at the
  wrong bits.
- In a directory others may write, an entry that is not a directory must have exactly one name
  (`stx_nlink`, `st_nlink`, 1), else it is refused (PR #13's review): where
  `fs.protected_hardlinks` is off (the kernel's default without systemd's sysctl file, and macOS
  has no such setting), anyone may `ln /etc/zigbox/policy.zon /tmp/zcube-trust.zon` before the
  operator makes it, and that name then holds a root-owned 0644 file on the directory's own
  mount, which every other rule passes. A link count the kernel did not report counts as not 1.
  The refusal raises the caller's code, as the walk's others do. A good policy in `/tmp` that
  someone hard-links elsewhere is refused too: in a directory others may write, that cannot be
  told from a squat, and `/etc/zcube` is the place for it.
- A cause says why before it names a path, and names the policy's path last: a cause is cut at
  `diag_field_bytes_max` (200 bytes), and with the paths first an ordinary path cut the reason
  away (the same review). A lookup that fails says which name and why (`statx` ENOENT is "no
  such file or directory", EACCES "permission denied searching a directory above it"), naming
  the system call it made on that system (`statx` on Linux, `fstatat` or `fstat` on macOS); a
  failed open or read says which and why.
- The same rules hold on macOS, where `zcube` may be built and run (it reaches `trust_file.zig`
  through `server_config.zig`; a raw Linux system call there was killed by SIGSYS). No gate runs
  on a Mac: `zig build trust-macos` (in `zig build check` and CI's check job) compiles the tests of
  `trust_file.zig`, and so the macOS half of `trust_sys.zig`, for aarch64-macos and x86_64-macos
  without emitting a binary (as Zigbox's `fuzz-macos`), so a compile error there fails on Linux;
  the tests have not run on a Mac. `src/trust_sys.zig` makes the calls: raw on Linux, through libSystem on macOS
  (`fstatat`, `fstat`, `readlinkat`, `getcwd`, `geteuid`; the opened file's path from
  `fcntl(F_GETPATH)` through `std.Io.File.realPath`). macOS reports no mount id and no
  mount-root flag, so there an entry in a directory others may write is judged by its device
  (`st_dev`) alone (and its link count); a FUSE or other mount over it has a device of its own. The bind-mount test
  runs on Linux only, and where the kernel reports `STATX_ATTR_MOUNT_ROOT` (read there as the raw
  0x2000) it requires the "mount point" wording, so a walk that read the std's wrong bit fails
  it; the table tests of `entry_problem` and the hard-link test run on both.

Where: `src/trust_file.zig`, `src/trust_sys.zig`, `build.zig` (`trust-macos`), ZC-E0106 and ZC-E0505 in `src/diag/codes.zig`.
