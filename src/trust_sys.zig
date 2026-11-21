//! The system calls `trust_file.zig` makes, on Linux (raw, as the rest of the shell) and on
//! macOS (through libSystem, which every Darwin build links): `zcube` is built and tested on
//! macOS too, and it reaches `trust_file.zig` through `server_config.zig`. A raw Linux system
//! call there is killed by SIGSYS. The rules are the same on both: owner, mode, sticky bit and
//! mount. macOS has no mount id, so an entry there is judged by its device alone, and a mount
//! root is seen as a device that differs from its directory's.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const linux = std.os.linux;
const c = std.c;

pub const is_linux = builtin.os.tag == .linux;

/// The error numbers of the system calls below.
pub const E = if (is_linux) linux.E else c.E;

/// The file mode bits: POSIX fixes their values, and Darwin's are Linux's.
pub const S = linux.S;
comptime {
    if (!is_linux) {
        assert(c.S.IFMT == S.IFMT);
        assert(c.S.IFREG == S.IFREG);
        assert(c.S.IFDIR == S.IFDIR);
        assert(c.S.IFLNK == S.IFLNK);
        assert(c.S.ISVTX == S.ISVTX);
    }
}

/// What a lookup reports about a file: its owner, mode and where it lives.
pub const Owner = struct {
    uid: u32,
    mode: u32,
    /// `stx_dev` (major and minor) on Linux, `st_dev` on macOS.
    device: u64 = 0,
    /// `stx_mnt_id`; null when the kernel did not report it (before Linux 5.8, and on macOS).
    mount: ?u64 = null,
    /// `STATX_ATTR_MOUNT_ROOT`: something is mounted here (Linux 5.8 and later only).
    mount_root: bool = false,
};

pub const Looked = union(enum) {
    found: Owner,
    failed: E,
    /// The kernel answered without the mode or the owner.
    incomplete,
};

pub fn geteuid() u32 {
    return if (is_linux) linux.geteuid() else c.geteuid();
}

/// The working directory, in `buffer`; null when it can't be read.
pub fn getcwd(buffer: []u8) ?[]const u8 {
    if (is_linux) {
        const result = linux.getcwd(buffer.ptr, buffer.len);
        if (linux.errno(result) != .SUCCESS) return null;
    } else {
        _ = c.getcwd(buffer.ptr, buffer.len) orelse return null;
    }
    const length = std.mem.indexOfScalar(u8, buffer, 0) orelse return null;
    return buffer[0..length];
}

pub const Readlink = union(enum) {
    target: []const u8,
    failed: E,
};

/// The target of the symbolic link `link`, in `buffer` (it fills the buffer when cut).
pub fn readlink(link: [*:0]const u8, buffer: []u8) Readlink {
    assert(buffer.len > 0);
    const result = if (is_linux)
        linux.readlinkat(linux.AT.FDCWD, link, buffer.ptr, buffer.len)
    else
        c.readlinkat(c.AT.FDCWD, link, buffer.ptr, buffer.len);
    const errno = if (is_linux) linux.errno(result) else c.errno(result);
    if (errno != .SUCCESS) return .{ .failed = errno };
    const length: usize = @intCast(result);
    assert(length <= buffer.len);
    return .{ .target = buffer[0..length] };
}

/// `path` (absolute) not following a link at its end.
pub fn look_up(path: [*:0]const u8) Looked {
    assert(path[0] == '/');
    if (is_linux) return statx(linux.AT.FDCWD, path, linux.AT.SYMLINK_NOFOLLOW);
    var stat = std.mem.zeroes(c.Stat);
    const result = c.fstatat(c.AT.FDCWD, path, &stat, c.AT.SYMLINK_NOFOLLOW);
    const errno = c.errno(result);
    if (errno != .SUCCESS) return .{ .failed = errno };
    return .{ .found = from_stat(&stat) };
}

/// The open file `fd`.
pub fn look_up_open(fd: std.posix.fd_t) Looked {
    if (is_linux) return statx(fd, "", linux.AT.EMPTY_PATH);
    var stat = std.mem.zeroes(c.Stat);
    const errno = c.errno(c.fstat(fd, &stat));
    if (errno != .SUCCESS) return .{ .failed = errno };
    return .{ .found = from_stat(&stat) };
}

fn from_stat(stat: *const c.Stat) Owner {
    comptime assert(!is_linux);
    return .{
        .uid = stat.uid,
        .mode = stat.mode,
        .device = @as(u32, @bitCast(stat.dev)),
    };
}

fn statx(dir: linux.fd_t, path: [*:0]const u8, flags: u32) Looked {
    comptime assert(is_linux);
    var stat = std.mem.zeroes(linux.Statx);
    const mask: linux.STATX = .{ .TYPE = true, .MODE = true, .UID = true, .MNT_ID = true };
    const result = linux.statx(dir, path, flags, mask, &stat);
    const errno = linux.errno(result);
    if (errno != .SUCCESS) return .{ .failed = errno };
    if (!stat.mask.MODE or !stat.mask.UID) return .incomplete;
    return .{ .found = .{
        .uid = stat.uid,
        .mode = stat.mode,
        .device = (@as(u64, stat.dev_major) << 32) | stat.dev_minor,
        .mount = if (stat.mask.MNT_ID) stat.mnt_id else null,
        .mount_root = attribute(stat.attributes_mask, stat.attributes, statx_attr_mount_root),
    } };
}

/// `STATX_ATTR_MOUNT_ROOT` from linux/stat.h. Not the pinned std's `STATX_ATTR.MOUNT_ROOT`: that
/// packed struct puts it at bit 10, where the kernel's 0x2000 is bit 13 (its other fields are
/// off as well), so it never reads the kernel's flag.
const statx_attr_mount_root: u64 = 0x2000;

/// Whether the kernel reported `flag` (in `mask`) and set it (in `attributes`).
fn attribute(mask: linux.STATX_ATTR, attributes: linux.STATX_ATTR, flag: u64) bool {
    assert(@popCount(flag) == 1);
    const reported = @as(u64, @bitCast(mask)) & flag != 0;
    return reported and @as(u64, @bitCast(attributes)) & flag != 0;
}

// Test helpers: they make the trees the tests judge, on either system.

/// Fails the test unless `result` (a system call's) succeeded.
fn expect_done(result: anytype) !void {
    const errno = if (is_linux) linux.errno(result) else c.errno(result);
    try std.testing.expectEqual(E.SUCCESS, errno);
}

pub fn test_random(buffer: []u8) !void {
    if (is_linux) {
        const got = linux.getrandom(buffer.ptr, buffer.len, 0);
        try expect_done(got);
        try std.testing.expectEqual(buffer.len, got);
    } else {
        c.arc4random_buf(buffer.ptr, buffer.len);
    }
}

pub fn test_mkdir(path: [*:0]const u8, mode: u32) !void {
    if (is_linux) return expect_done(linux.mkdir(path, mode));
    return expect_done(c.mkdir(path, @intCast(mode)));
}

pub fn test_chmod(path: [*:0]const u8, mode: u32) !void {
    if (is_linux) return expect_done(linux.chmod(path, mode));
    return expect_done(c.chmod(path, @intCast(mode)));
}

pub fn test_symlink(target: [*:0]const u8, link: [*:0]const u8) !void {
    if (is_linux) return expect_done(linux.symlink(target, link));
    return expect_done(c.symlink(target, link));
}

pub fn test_rename(old: [*:0]const u8, new: [*:0]const u8) !void {
    if (is_linux) return expect_done(linux.rename(old, new));
    return expect_done(c.rename(old, new));
}

/// Gives `path` (a link itself, when it is one) to `uid`, group `uid`.
pub fn test_chown(path: [*:0]const u8, uid: u32) !void {
    if (is_linux) {
        const flags = linux.AT.SYMLINK_NOFOLLOW;
        return expect_done(linux.fchownat(linux.AT.FDCWD, path, uid, uid, flags));
    }
    return expect_done(c.fchownat(c.AT.FDCWD, path, uid, uid, c.AT.SYMLINK_NOFOLLOW));
}

extern "c" fn mkfifo(path: [*:0]const u8, mode: c.mode_t) c_int;

pub fn test_mkfifo(path: [*:0]const u8) !void {
    if (is_linux) return expect_done(linux.mknodat(linux.AT.FDCWD, path, S.IFIFO | 0o600, 0));
    return expect_done(mkfifo(path, 0o600));
}
