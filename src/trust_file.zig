//! A Zigbox trust policy file, read once at start (B5): by `zcube-server` for its `trust` entry
//! (ZC-E0106) and by `zcube-agent` for `--trust-policy` (ZC-E0505). Shell code: it reads a file.
//!
//! The path is walked as given, every directory on the way (a symbolic link's own directory too)
//! judged, and the file it ends on is judged and read through one descriptor, so it cannot be
//! swapped between the two.
//! It must be a regular file, owned by root or by the process's own user, and writable by neither
//! group nor others: Zigbox's rule for its system policy (`trust/gate.zig`, "the system policy
//! binds users who cannot write it"), carried over to a process that need not run as root
//! (docs/decisions/2026-11-13-b5-policy-file-ownership.md). A policy Zigbox refuses names its
//! line, column and kind.

const builtin = @import("builtin");
const std = @import("std");
const assert = std.debug.assert;
const zigbox = @import("zigbox");
const codes = @import("diag/codes.zig");
const constants = @import("constants.zig");
const diag_mod = @import("diag.zig");

const Allocator = std.mem.Allocator;
const Diag = diag_mod.Diag;

pub const Policy = zigbox.trust.policy.Policy;

pub const Error = error{ BadConfig, OutOfMemory };

/// A policy read and parsed, and the path it was read from (the refusals name it).
pub const Loaded = struct {
    path: []const u8,
    policy: *const Policy,
};

/// How the reader's refusals read for its caller.
pub const Options = struct {
    /// The code a refusal raises: the caller's bad-configuration code.
    code: codes.Code,
    /// The setting's name as the user wrote it, e.g. "trust.policy" or "--trust-policy".
    setting: []const u8,
    /// Whose own user may own the file: "the server's user", "the agent's user".
    user: []const u8,
    /// The fix of a path that cannot be read.
    fix: []const u8,
    /// The fix of a file others could rewrite.
    owner_fix: []const u8,
};

pub fn read(
    arena: Allocator,
    io: std.Io,
    path: []const u8,
    options: Options,
    diag: *Diag,
) Error!Loaded {
    if (path.len == 0 or path.len > constants.config_path_bytes_max) {
        return bad(diag, options, "{s} must be a path of 1 to {d} bytes", .{
            options.setting, constants.config_path_bytes_max,
        }, options.fix);
    }
    // The path is walked as given, a component at a time, and every directory that holds one (a
    // symbolic link's own directory too) is judged; the walk ends on the file the links lead to,
    // which is judged before it is opened: opening a FIFO for reading blocks until a writer
    // comes, so a FIFO must be refused unopened. The file is opened by the walked path, links
    // not followed, judged again through its descriptor, and read from that descriptor.
    var walked: Walk = .{};
    const reached = try walk(&walked, path, options, diag);
    try check_owner(reached, path, options, diag);
    const file = std.Io.Dir.cwd().openFile(io, walked.real(), .{
        .follow_symlinks = false,
    }) catch |err| return bad(diag, options, "can't open the trust policy: {s}: {s}", .{
        open_text(err), path,
    }, options.fix);
    defer file.close(io);
    try check_owner(try owner_of(file, path, options, diag), path, options, diag);
    try check_same(io, file, walked.real(), path, options, diag);
    // A file of exactly the bound is allowed: the limit refuses one that reaches it.
    const limit: std.Io.Limit = .limited(zigbox.trust.limits.policy_bytes_max + 1);
    var reader = file.reader(io, &.{});
    const source = reader.interface.allocRemaining(arena, limit) catch |err| {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.StreamTooLong => bad(diag, options, "the trust policy is larger than " ++
                "{d} bytes: {s}", .{ zigbox.trust.limits.policy_bytes_max, path }, "trim it"),
            error.ReadFailed => bad(diag, options, "can't read the trust policy: {s}: {s}", .{
                read_text(reader.err), path,
            }, options.fix),
        };
    };
    return parse(arena, source, path, options, diag);
}

/// Who owns a file on the policy's path, its mode bits, and where it lives: an entry in a
/// directory others may write must live on that directory's own mount (`entry_problem`).
pub const Owner = sys.Owner;

const sys = @import("trust_sys.zig");
const path_max = std.fs.max_path_bytes;
comptime {
    assert(path_max <= std.math.maxInt(u16));
}

/// A walk down a policy's path. Every directory that holds a component of the path, up to `/`,
/// must be one that only root or the process's own user can change: whoever may write a
/// directory on the way can rename the policy away, or put a symbolic link in its place, and the
/// next start reads what they chose (0.5.2 review 5927352205, item 8; PR #10's review;
/// docs/decisions/2026-11-21-trust-policy-directories.md). So the path is walked as given, a
/// component at a time and never through a link unseen: a link's own directory is judged, then
/// its target is walked in its place. In a directory others may write (sticky), every entry it
/// passes must be root's or the process's own user's (`check_entry`).
const Walk = struct {
    /// The directories reached so far, from `/`, with no link left in them.
    resolved: [path_max]u8 = undefined,
    resolved_len: u16 = 0,
    /// The components still to walk: `pending[pending_start..pending_len]`.
    pending: [path_max]u8 = undefined,
    pending_start: u16 = 0,
    pending_len: u16 = 0,
    links: u32 = 0,

    /// The path reached, absolute and free of links.
    fn real(w: *const Walk) []const u8 {
        assert(w.resolved_len >= 1);
        assert(w.resolved[0] == '/');
        return w.resolved[0..w.resolved_len];
    }
};

/// Walks `path` and returns the owner and mode of the file it ends on (not following it).
fn walk(w: *Walk, path: []const u8, options: Options, diag: *Diag) Error!Owner {
    assert(path.len > 0);
    w.resolved[0] = '/';
    w.resolved_len = 1;
    // A relative path is walked from the working directory, whose directories are judged too.
    var prefix_len: usize = 0;
    if (!std.fs.path.isAbsolute(path)) {
        const cwd = sys.getcwd(&w.pending) orelse return bad(diag, options, "can't read the " ++
            "working directory, from which the trust policy is a relative path: {s}", .{path}, //
            "name the policy by an absolute path");
        prefix_len = cwd.len;
        w.pending[prefix_len] = '/';
        prefix_len += 1;
    }
    if (prefix_len + path.len > w.pending.len) return too_long(path, options, diag);
    @memcpy(w.pending[prefix_len..][0..path.len], path);
    w.pending_len = @intCast(prefix_len + path.len);
    // Each step takes at least one byte of `pending`, except one that meets a link, which starts
    // `pending` again: the links are bounded, so the walk is.
    const steps_max = (constants.trust_policy_links_max + 1) * (path_max + 1);
    var steps: usize = 0;
    while (w.pending_start < w.pending_len) : (steps += 1) {
        assert(steps < steps_max);
        try walk_step(w, path, options, diag);
    }
    var buffer: [path_max:0]u8 = undefined;
    const reached = try look_up(terminated(&buffer, w.real()), path, options, diag);
    assert(reached.mode & sys.S.IFMT != sys.S.IFLNK);
    return reached;
}

/// Walks the next component of `pending`.
fn walk_step(w: *Walk, path: []const u8, options: Options, diag: *Diag) Error!void {
    const rest = w.pending[w.pending_start..w.pending_len];
    assert(rest.len > 0);
    const end = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const name = rest[0..end];
    // A separator after the name: what it names must be a directory (or a link to one).
    const separated = end < rest.len;
    w.pending_start += @intCast(@min(end + 1, rest.len));
    assert(w.pending_start <= w.pending_len);
    if (name.len == 0 or std.mem.eql(u8, name, ".")) return;
    if (std.mem.eql(u8, name, "..")) {
        // `resolved` holds no link, so its parent is its own dirname.
        const parent = std.fs.path.dirname(w.real()) orelse "/";
        w.resolved_len = @intCast(parent.len);
        return;
    }
    // Whoever may write the directory that holds this component could swap it.
    const holder = try check_directory(w.real(), path, options, diag);
    const parent_len = w.resolved_len;
    const separator: usize = if (parent_len == 1) 0 else 1;
    if (parent_len + separator + name.len >= path_max) return too_long(path, options, diag);
    w.resolved[parent_len] = '/';
    @memcpy(w.resolved[parent_len + separator ..][0..name.len], name);
    w.resolved_len = @intCast(parent_len + separator + name.len);
    var buffer: [path_max:0]u8 = undefined;
    const candidate = terminated(&buffer, w.real());
    const owner = try look_up(candidate, path, options, diag);
    try check_entry(holder, owner, candidate, path, options, diag);
    const kind = owner.mode & sys.S.IFMT;
    if (kind == sys.S.IFLNK) {
        w.resolved_len = parent_len;
        return walk_link(w, candidate, separated, path, options, diag);
    }
    // The kernel refuses a file followed by a separator (ENOTDIR), so `trust.zon/` and
    // `trust.zon/../trust.zon` are refused here too, not read by a textual `..`.
    if (separated and kind != sys.S.IFDIR) {
        const tail = on_the_way(candidate, path);
        return bad(diag, options, "the trust policy's path goes on past a file that is not a " ++
            "directory: {s}{s}{s}", .{ candidate, tail.join, tail.path }, options.fix);
    }
}

/// In a directory others may write (the sticky exception), whoever made an entry owns it and may
/// point it anywhere, so every entry the walk passes there, a link included, must be owned by
/// root or the process's own user: the rule of `fs.protected_symlinks`, which the walk's
/// `readlinkat` is not subject to (PR #10's re-review). And it must not be a mount point, nor
/// on another mount than its directory: a user may mount (FUSE) over a name they own, and the
/// mounted root then reports whatever owner and mode its daemon chooses (PR #10's third review;
/// docs/decisions/2026-11-21-trust-policy-mounts-and-macos.md). Nor may anything but a directory
/// have another name: a user may hard-link a root-owned file (another policy) to a name they
/// made, where `fs.protected_hardlinks` is off (PR #13's review).
fn check_entry(
    holder: Owner,
    entry: Owner,
    name: []const u8,
    path: []const u8,
    options: Options,
    diag: *Diag,
) Error!void {
    const problem = entry_problem(holder, entry, sys.geteuid()) orelse return;
    const what = switch (entry.mode & sys.S.IFMT) {
        sys.S.IFLNK => "a symbolic link",
        sys.S.IFDIR => "a directory",
        else => "a file",
    };
    // The reason comes before the paths: a cause is cut at `diag_field_bytes_max`.
    const mode = holder.mode & 0o7777;
    const tail = on_the_way(name, path);
    return switch (problem) {
        .foreign_owner => bad(diag, options, "{s} owned by uid {d}, in a directory others " ++
            "may write (mode {o:0>4}), is on the trust policy's path: {s}{s}{s}", .{
            what, entry.uid, mode, name, tail.join, tail.path,
        }, directory_fix),
        .mount_root, .other_mount => bad(diag, options, "{s} {s}, in a directory others " ++
            "may write (mode {o:0>4}), is on the trust policy's path: {s}{s}{s}", .{
            what, problem.text(), mode, name, tail.join, tail.path,
        }, mount_fix),
        .hard_link => bad(diag, options, "{s} with {d} hard links, in a directory others may " ++
            "write (mode {o:0>4}), is on the trust policy's path: {s}{s}{s}", .{
            what, entry.links, mode, name, tail.join, tail.path,
        }, hard_link_fix),
    };
}

/// What makes an entry unusable in a directory others may write.
pub const EntryProblem = enum {
    foreign_owner,
    mount_root,
    other_mount,
    hard_link,

    /// The cause's words, after what the entry is (`foreign_owner` and `hard_link` name their
    /// number themselves).
    pub fn text(problem: EntryProblem) []const u8 {
        return switch (problem) {
            .foreign_owner => "owned by another user",
            .mount_root => "that is a mount point",
            .other_mount => "on another mount than its directory",
            .hard_link => "with more than one name",
        };
    }
};

/// Null when `entry`, in the directory `holder`, may be passed; otherwise what is wrong. Only a
/// directory others may write (sticky, as `directory_problem` allows) constrains its entries.
/// The mount is compared by mount id where the kernel gives both, else by device: an overlay or
/// a btrfs subvolume can report another device for a file on the directory's own mount. Anything
/// but a directory must have exactly one name (a link count the kernel did not report, 0, too).
pub fn entry_problem(holder: Owner, entry: Owner, euid: u32) ?EntryProblem {
    if (holder.mode & 0o022 == 0) return null;
    assert(holder.mode & sys.S.ISVTX != 0);
    if (entry.uid != 0 and entry.uid != euid) return .foreign_owner;
    if (mount_problem(holder, entry)) |problem| return problem;
    if (entry.mode & sys.S.IFMT != sys.S.IFDIR and entry.links != 1) return .hard_link;
    return null;
}

fn mount_problem(holder: Owner, entry: Owner) ?EntryProblem {
    if (entry.mount_root) return .mount_root;
    if (holder.mount) |holder_mount| {
        if (entry.mount) |entry_mount| {
            if (entry_mount != holder_mount) return .other_mount;
            return null;
        }
    }
    if (entry.device != holder.device) return .other_mount;
    return null;
}

/// What follows a refusal's entry: `, on the way to <path>`, or nothing when the entry named is
/// the policy's own path.
const Tail = struct { join: []const u8, path: []const u8 };

fn on_the_way(name: []const u8, path: []const u8) Tail {
    assert(name.len > 0);
    assert(path.len > 0);
    if (std.mem.eql(u8, name, path)) return .{ .join = "", .path = "" };
    return .{ .join = ", on the way to ", .path = path };
}

/// Puts the target of the symbolic link `link` in front of the components still to walk.
fn walk_link(
    w: *Walk,
    link: [:0]const u8,
    separated: bool,
    path: []const u8,
    options: Options,
    diag: *Diag,
) Error!void {
    w.links += 1;
    if (w.links > constants.trust_policy_links_max) {
        return bad(diag, options, "the trust policy's path goes through more than {d} " ++
            "symbolic links: {s}", .{ constants.trust_policy_links_max, path }, options.fix);
    }
    var target: [path_max]u8 = undefined;
    const length = switch (sys.readlink(link, &target)) {
        .target => |text| text.len,
        .failed => |errno| return bad(diag, options, "can't read a symbolic link on the " ++
            "trust policy's path (readlinkat E{t}): {s}, on the way to {s}", .{
            errno, link, path,
        }, options.fix),
    };
    if (length == 0) {
        return bad(diag, options, "a symbolic link on the trust policy's path is empty: {s}, " ++
            "on the way to {s}", .{ link, path }, options.fix);
    }
    if (length == target.len) return too_long(path, options, diag);
    // The separator that followed the link, if one did, follows its target.
    const rest = w.pending[w.pending_start..w.pending_len];
    if (!separated) assert(rest.len == 0);
    const separator: usize = @intFromBool(separated);
    const total = length + separator + rest.len;
    if (total > path_max) return too_long(path, options, diag);
    var next: [path_max]u8 = undefined;
    @memcpy(next[0..length], target[0..length]);
    if (separated) next[length] = '/';
    @memcpy(next[length + separator ..][0..rest.len], rest);
    @memcpy(w.pending[0..total], next[0..total]);
    w.pending_start = 0;
    w.pending_len = @intCast(total);
    // An absolute target is walked from `/`; a relative one from the link's own directory.
    if (target[0] == '/') w.resolved_len = 1;
}

fn check_directory(
    directory: []const u8,
    path: []const u8,
    options: Options,
    diag: *Diag,
) Error!Owner {
    assert(directory.len > 0);
    assert(directory[0] == '/');
    var buffer: [path_max:0]u8 = undefined;
    const owner = try look_up(terminated(&buffer, directory), path, options, diag);
    const problem = directory_problem(owner, sys.geteuid()) orelse return owner;
    // The reason comes before the paths: a cause is cut at `diag_field_bytes_max`.
    return bad(diag, options, "a directory on the trust policy's path {s}{s} (owner uid {d}, " ++
        "mode {o:0>4}): {s}, on the way to {s}", .{
        problem.text(),
        if (problem == .foreign_owner) options.user else "",
        owner.uid,
        owner.mode & 0o7777,
        directory,
        path,
    }, directory_fix);
}

/// The file opened must be the one the walk judged: its descriptor names the walked path.
fn check_same(
    io: std.Io,
    file: std.Io.File,
    real: []const u8,
    path: []const u8,
    options: Options,
    diag: *Diag,
) Error!void {
    var buffer: [path_max]u8 = undefined;
    const length = file.realPath(io, &buffer) catch return bad(diag, options, "can't confirm " ++
        "which file was opened as the trust policy" ++ realpath_hint ++ ": {s}", .{path}, //
        if (sys.is_linux) "mount /proc where the process runs" else options.fix);
    if (std.mem.eql(u8, buffer[0..length], real)) return;
    return bad(diag, options, "the trust policy changed while it was read: {s} was judged, " ++
        "{s} was opened, for {s}", .{ real, buffer[0..length], path }, options.fix);
}

/// Linux names the opened file through /proc; macOS through `fcntl(F_GETPATH)`.
const realpath_hint = if (sys.is_linux) " (is /proc mounted?)" else "";

fn too_long(path: []const u8, options: Options, diag: *Diag) Error {
    return bad(diag, options, "the trust policy's path is longer than the system's path limit " ++
        "once made absolute and its links followed: {s}", .{path}, options.fix);
}

/// `text` with a terminating zero, in `buffer`.
fn terminated(buffer: *[path_max:0]u8, text: []const u8) [:0]const u8 {
    assert(text.len < path_max);
    @memcpy(buffer[0..text.len], text);
    buffer[text.len] = 0;
    return buffer[0..text.len :0];
}

const directory_fix = "keep the policy in a directory that only root or the process's own " ++
    "user can write, such as /etc/zcube, and chmod go-w every directory above it";

const mount_fix = "keep the policy out of directories others may write, such as /tmp, where " ++
    "anyone may mount over a name they made; /etc/zcube is the place for it";

const hard_link_fix = "keep the policy out of directories others may write, such as /tmp, " ++
    "where anyone may hard-link another file to a name they made; /etc/zcube is the place for it";

/// Null when a directory of this owner and mode keeps a policy file in it from being swapped by
/// anyone but root and `euid`; otherwise what is wrong (never `not_regular`). A directory others
/// may write is allowed only with the sticky bit (`/tmp`): there no one may rename or remove a
/// file they do not own.
pub fn directory_problem(owner: Owner, euid: u32) ?OwnerProblem {
    if (owner.uid != 0 and owner.uid != euid) return .foreign_owner;
    if (owner.mode & 0o022 != 0 and owner.mode & sys.S.ISVTX == 0) return .writable;
    return null;
}

fn check_owner(owner: Owner, path: []const u8, options: Options, diag: *Diag) Error!void {
    const problem = owner_problem(owner, sys.geteuid()) orelse return;
    return bad(diag, options, "the trust policy {s}{s} (owner uid {d}, mode {o:0>4}): {s}", .{
        problem.text(),
        if (problem == .foreign_owner) options.user else "",
        owner.uid,
        owner.mode & 0o7777,
        path,
    }, options.owner_fix);
}

/// The opened policy's owner and mode, from its descriptor.
fn owner_of(file: std.Io.File, path: []const u8, options: Options, diag: *Diag) Error!Owner {
    return switch (sys.look_up_open(file.handle)) {
        .found => |owner| owner,
        .failed => |errno| bad(diag, options, "can't stat the opened trust policy ({s} " ++
            "E{t}): {s}", .{ sys.look_up_open_call, errno, path }, options.fix),
        .incomplete => bad(diag, options, "the file system did not report the opened trust " ++
            "policy's owner and mode: {s}", .{path}, options.fix),
    };
}

/// `name`'s owner and mode, not following a link; a refusal says why it can't be looked up.
fn look_up(name: [:0]const u8, path: []const u8, options: Options, diag: *Diag) Error!Owner {
    assert(name.len > 0);
    assert(name[0] == '/');
    const tail = on_the_way(name, path);
    return switch (sys.look_up(name)) {
        .found => |owner| owner,
        .failed => |errno| bad(diag, options, "can't look up the trust policy: {s} ({s} " ++
            "E{t}): {s}{s}{s}", .{
            look_up_text(errno), sys.look_up_call, errno, name, tail.join, tail.path,
        }, options.fix),
        .incomplete => bad(diag, options, "can't look up the trust policy: the file system " ++
            "did not report an owner and mode: {s}{s}{s}", .{ name, tail.join, tail.path }, //
            options.fix),
    };
}

/// Why a lookup failed, in words; the errno follows them in the cause.
fn look_up_text(errno: sys.E) []const u8 {
    assert(errno != .SUCCESS);
    return switch (errno) {
        .NOENT => "no such file or directory",
        .ACCES => "permission denied searching a directory above it",
        .NOTDIR => "a component above it is not a directory",
        .LOOP => "too many symbolic links",
        .NAMETOOLONG => "a name on the path is too long",
        else => "the lookup failed",
    };
}

/// Why opening the walked policy failed, in words.
fn open_text(err: std.Io.File.OpenError) []const u8 {
    return switch (err) {
        error.FileNotFound => "it was removed after it was judged",
        error.AccessDenied, error.PermissionDenied => "permission denied",
        error.SymLinkLoop => "it was replaced by a symbolic link after it was judged",
        error.SystemFdQuotaExceeded, error.ProcessFdQuotaExceeded => "too many open files",
        else => "the system refused to open it",
    };
}

/// Why reading the opened policy failed, in words.
fn read_text(err: ?std.Io.File.Reader.Error) []const u8 {
    const known = err orelse return "the read failed";
    return switch (known) {
        error.InputOutput => "an I/O error",
        error.AccessDenied => "permission denied",
        error.IsDir => "it is a directory",
        else => "the read failed",
    };
}

/// What makes a policy file unusable.
pub const OwnerProblem = enum {
    not_regular,
    foreign_owner,
    writable,

    /// The cause's words; `foreign_owner` is followed by the caller's `user`.
    pub fn text(problem: OwnerProblem) []const u8 {
        return switch (problem) {
            .not_regular => "is not a regular file",
            .foreign_owner => "is owned by neither root nor ",
            .writable => "can be written by its group or by others",
        };
    }
};

/// Null when a file of this owner and mode may be used; otherwise what is wrong.
pub fn owner_problem(owner: Owner, euid: u32) ?OwnerProblem {
    if (owner.mode & sys.S.IFMT != sys.S.IFREG) return .not_regular;
    if (owner.uid != 0 and owner.uid != euid) return .foreign_owner;
    if (owner.mode & 0o022 != 0) return .writable;
    return null;
}

/// Parses `source`, the text of the policy file at `path`.
pub fn parse(
    arena: Allocator,
    source: []const u8,
    path: []const u8,
    options: Options,
    diag: *Diag,
) Error!Loaded {
    const policy = try arena.create(Policy);
    if (zigbox.trust.policy.parse(source, policy)) |problem| {
        const detail = problem.detail_text();
        return bad(diag, options, "the trust policy is not a policy zbx reads: {t} at " ++
            "{d}:{d}{s}{s}, in {s}", .{
            problem.kind,
            problem.line,
            problem.column,
            if (detail.len > 0) " near " else "",
            detail,
            path,
        }, "check it with zbx trust policy check, or fix the line it names");
    }
    return .{ .path = path, .policy = policy };
}

fn bad(
    diag: *Diag,
    options: Options,
    comptime cause: []const u8,
    args: anytype,
    fix: []const u8,
) Error {
    assert(diag.code == null);
    diag.raise(options.code);
    diag.cause(cause, args);
    diag.fix(.{ .sentence = fix });
    return error.BadConfig;
}

// ---- Tests -------------------------------------------------------------------------------------

const testing = std.testing;

const test_options: Options = .{
    .code = .E0505,
    .setting = "--trust-policy",
    .user = "the agent's user",
    .fix = "name a readable Zigbox policy file",
    .owner_fix = "chown it to root (or the agent's user) and chmod go-w it",
};

test "a policy file is used only when root or the process's own user alone can write it" {
    // Goal: Zigbox's rule for its system policy, for both callers. Method: each owner and mode.
    const euid: u32 = 1000;
    const regular: u32 = sys.S.IFREG;
    try testing.expect(owner_problem(.{ .uid = 0, .mode = regular | 0o644 }, euid) == null);
    try testing.expect(owner_problem(.{ .uid = euid, .mode = regular | 0o600 }, euid) == null);
    try testing.expect(owner_problem(.{ .uid = 0, .mode = regular | 0o4755 }, euid) == null);
    const refused = [_]struct { Owner, OwnerProblem }{
        .{ .{ .uid = 1001, .mode = regular | 0o644 }, .foreign_owner },
        .{ .{ .uid = 0, .mode = regular | 0o664 }, .writable },
        .{ .{ .uid = euid, .mode = regular | 0o646 }, .writable },
        .{ .{ .uid = 0, .mode = sys.S.IFDIR | 0o755 }, .not_regular },
    };
    for (refused) |case| try testing.expectEqual(case[1], owner_problem(case[0], euid).?);
}

test "a refusal raises the caller's code and names its setting" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // macOS TLS port, required before 0.6.0
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var diag: Diag = undefined;
    diag.reset();
    const missing = read(arena, testing.io, "/nonexistent/zcube-trust.zon", test_options, &diag);
    try testing.expectError(error.BadConfig, missing);
    try testing.expectEqual(@as(?codes.Code, .E0505), diag.code);
    diag.reset();
    try testing.expectError(error.BadConfig, read(arena, testing.io, "", test_options, &diag));
    const cause = diag.causes.slice()[0].slice();
    try testing.expect(std.mem.indexOf(u8, cause, "--trust-policy") != null);
    diag.reset();
    // A FIFO is refused without being opened, which would block until a writer came.
    const base = try test_directory(arena);
    defer std.Io.Dir.cwd().deleteTree(testing.io, base) catch {}; // Best effort: it is in /tmp.
    const fifo = try std.fmt.allocPrintSentinel(arena, "{s}/trust.zon", .{base}, 0);
    try sys.test_mkfifo(fifo);
    try testing.expectError(error.BadConfig, read(arena, testing.io, fifo, test_options, &diag));
    const fifo_cause = diag.causes.slice()[0].slice();
    try testing.expect(std.mem.indexOf(u8, fifo_cause, "is not a regular file") != null);
    diag.reset();
    const bad_policy = parse(arena, ".{ .keys = .{} }", "p.zon", test_options, &diag);
    try testing.expectError(error.BadConfig, bad_policy);
    try testing.expectEqual(@as(?codes.Code, .E0505), diag.code);
}

test "a policy file's directories must be ones only root or the process's own user can change" {
    // Goal: the 0.5.2 review 5927352205, item 8: a policy file owned and moded right, in a
    // directory others may write, could be renamed away and replaced before the next start.
    // Method: the rule on owners and modes; then a real policy read in its directory at 0755,
    // refused at 0775 and 0757 (the cause names the directory and its mode), and read at 1777.
    const euid: u32 = 1000;
    const directory: u32 = sys.S.IFDIR;
    try testing.expect(directory_problem(.{ .uid = 0, .mode = directory | 0o755 }, euid) == null);
    const own: Owner = .{ .uid = euid, .mode = directory | 0o700 };
    try testing.expect(directory_problem(own, euid) == null);
    try testing.expect(directory_problem(.{ .uid = 0, .mode = directory | 0o1777 }, euid) == null);
    const refused = [_]struct { Owner, OwnerProblem }{
        .{ .{ .uid = 1001, .mode = directory | 0o755 }, .foreign_owner },
        .{ .{ .uid = 1001, .mode = directory | 0o1777 }, .foreign_owner },
        .{ .{ .uid = 0, .mode = directory | 0o775 }, .writable },
        .{ .{ .uid = euid, .mode = directory | 0o757 }, .writable },
    };
    for (refused) |case| try testing.expectEqual(case[1], directory_problem(case[0], euid).?);

    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const base = try test_directory(arena);
    defer std.Io.Dir.cwd().deleteTree(io, base) catch {}; // Best effort: it is in /tmp.
    const held = try test_subdirectory(arena, base, "policy");
    const path = try write_test_policy(arena, held);
    var diag: Diag = undefined;
    for ([_]u32{ 0o755, 0o1777 }) |mode| {
        try chmod_directory(held, mode);
        diag.reset();
        _ = try read(arena, io, path, test_options, &diag);
    }
    for ([_]u32{ 0o775, 0o757 }) |mode| {
        try chmod_directory(held, mode);
        diag.reset();
        try testing.expectError(error.BadConfig, read(arena, io, path, test_options, &diag));
        try testing.expectEqual(@as(?codes.Code, .E0505), diag.code);
        const cause = diag.causes.slice()[0].slice();
        try testing.expect(std.mem.indexOf(u8, cause, "can be written by its group or") != null);
        try testing.expect(std.mem.indexOf(u8, cause, "/policy, on the way to") != null);
    }
    try chmod_directory(held, 0o755);
}

test "a symbolic link to a policy is judged in its own directory and along its target's" {
    // Goal: PR #10's review (MUST): a link to a good root-owned file, put in a directory others
    // may write, must not pass, since whoever put it there can point it anywhere. Method: a good
    // policy in `good` (0755); links to it, absolute and relative, in `links`, and a link to the
    // `good` directory itself; each read with `links` at 0755, each refused at 0775 naming
    // `links`; then refused through the links with `good` at 0775, naming `good`.
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const base = try test_directory(arena);
    defer std.Io.Dir.cwd().deleteTree(io, base) catch {}; // Best effort: it is in /tmp.
    const good = try test_subdirectory(arena, base, "good");
    const target = try write_test_policy(arena, good);
    const links = try test_subdirectory(arena, base, "links");
    const absolute = try std.fmt.allocPrintSentinel(arena, "{s}/absolute.zon", .{links}, 0);
    const relative = try std.fmt.allocPrintSentinel(arena, "{s}/relative.zon", .{links}, 0);
    const directory = try std.fmt.allocPrintSentinel(arena, "{s}/dir", .{links}, 0);
    const pairs = [_]struct { [:0]const u8, [:0]const u8 }{
        .{ try arena.dupeSentinel(u8, target, 0), absolute },
        .{ "../good/trust.zon", relative },
        .{ "../good", directory },
    };
    for (pairs) |pair| {
        try sys.test_symlink(pair[0], pair[1]);
    }
    const through_directory = try std.fmt.allocPrint(arena, "{s}/trust.zon", .{directory});
    const paths = [_][]const u8{ absolute, relative, through_directory };
    var diag: Diag = undefined;
    for (paths) |path| {
        diag.reset();
        const loaded = try read(arena, io, path, test_options, &diag);
        try testing.expectEqualStrings(path, loaded.path);
    }
    const cases = [_]struct { [:0]const u8, []const u8 }{
        .{ links, "/links, on the way to" },
        .{ good, "/good, on the way to" },
    };
    for (cases) |case| {
        try chmod_directory(case[0], 0o775);
        for (paths) |path| {
            diag.reset();
            try testing.expectError(error.BadConfig, read(arena, io, path, test_options, &diag));
            const cause = diag.causes.slice()[0].slice();
            try testing.expect(std.mem.indexOf(u8, cause, case[1]) != null);
            try testing.expect(std.mem.indexOf(u8, cause, "can be written by its group") != null);
        }
        try chmod_directory(case[0], 0o755);
    }
}

test "in a directory others may write, every entry the walk passes must be root's or its own" {
    // Goal: PR #10's re-review (MUST): in a sticky directory others may write, whoever made a
    // link owns it and may repoint it, so a link owned by another uid there must be refused,
    // as `fs.protected_symlinks` would, though its target is good. Method: a good policy in
    // `good` (0755); a link to it in `shared` (1777), read while owned by the process's own
    // user; then, as root only, the link and a copy of the policy chowned to uid 65534, each
    // refused with a cause naming it and its owner.
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const base = try test_directory(arena);
    defer std.Io.Dir.cwd().deleteTree(io, base) catch {}; // Best effort: it is in /tmp.
    const good = try test_subdirectory(arena, base, "good");
    const target = try arena.dupeSentinel(u8, try write_test_policy(arena, good), 0);
    const shared = try test_subdirectory(arena, base, "shared");
    try chmod_directory(shared, 0o1777);
    const link = try std.fmt.allocPrintSentinel(arena, "{s}/trust.zon", .{shared}, 0);
    try sys.test_symlink(target, link);
    var diag: Diag = undefined;
    diag.reset();
    _ = try read(arena, io, link, test_options, &diag);
    if (sys.geteuid() != 0) return error.SkipZigTest;
    const nobody: u32 = 65534;
    try sys.test_chown(link, nobody);
    diag.reset();
    try testing.expectError(error.BadConfig, read(arena, io, link, test_options, &diag));
    try testing.expectEqual(@as(?codes.Code, .E0505), diag.code);
    const expected = try std.fmt.allocPrint(arena, "a symbolic link owned by uid 65534, in a " ++
        "directory others may write (mode 1777), is on the trust policy's path: {s}", .{link});
    try expect_cause(expected, diag.causes.slice()[0].slice());
    // Through the link, it is named as the entry the walk passed.
    const through = try std.fmt.allocPrint(arena, "{s}/./trust.zon", .{shared});
    diag.reset();
    try testing.expectError(error.BadConfig, read(arena, io, through, test_options, &diag));
    const through_cause = diag.causes.slice()[0].slice();
    const named = try std.fmt.allocPrint(arena, "a symbolic link owned by uid 65534, in a " ++
        "directory others may write (mode 1777), is on the trust policy's path: {s}, on the " ++
        "way to {s}", .{ link, through });
    try expect_cause(named, through_cause);
    // A file planted there by another uid is refused the same way.
    const planted = try write_test_policy(arena, try test_subdirectory(arena, shared, "own"));
    const file = try std.fmt.allocPrintSentinel(arena, "{s}/file.zon", .{shared}, 0);
    try sys.test_rename(try arena.dupeSentinel(u8, planted, 0), file);
    try sys.test_chown(file, nobody);
    diag.reset();
    try testing.expectError(error.BadConfig, read(arena, io, file, test_options, &diag));
    const file_cause = diag.causes.slice()[0].slice();
    try testing.expect(std.mem.startsWith(u8, file_cause, "a file owned by uid 65534,"));
}

test "a path that goes on past a file is refused, as the kernel refuses it" {
    // Goal: PR #10's re-review (NIT): `trust.zon/` and `trust.zon/../trust.zon` were read,
    // their `..` and separator taken textually, though open(2) refuses both with ENOTDIR.
    // Method: the good path read; each of those, directly and through a link, refused.
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const base = try test_directory(arena);
    defer std.Io.Dir.cwd().deleteTree(io, base) catch {}; // Best effort: it is in /tmp.
    const good = try test_subdirectory(arena, base, "good");
    const path = try write_test_policy(arena, good);
    const link = try std.fmt.allocPrintSentinel(arena, "{s}/link.zon", .{good}, 0);
    try sys.test_symlink("trust.zon", link);
    var diag: Diag = undefined;
    diag.reset();
    _ = try read(arena, io, path, test_options, &diag);
    diag.reset();
    _ = try read(arena, io, link, test_options, &diag);
    const refused = [_][]const u8{
        try std.fmt.allocPrint(arena, "{s}/", .{path}),
        try std.fmt.allocPrint(arena, "{s}/../trust.zon", .{path}),
        try std.fmt.allocPrint(arena, "{s}/.", .{path}),
        try std.fmt.allocPrint(arena, "{s}/", .{link}),
        try std.fmt.allocPrint(arena, "{s}/../trust.zon", .{link}),
    };
    for (refused) |bad_path| {
        diag.reset();
        try testing.expectError(error.BadConfig, read(arena, io, bad_path, test_options, &diag));
        const cause = diag.causes.slice()[0].slice();
        const reason = "the trust policy's path goes on past a file that is not a directory: ";
        try testing.expect(std.mem.startsWith(u8, cause, reason));
    }
}

test "in a directory others may write, an entry must live on the directory's own mount" {
    // Goal: PR #10's third review (SHOULD): a user may mount (FUSE) over a name they own in a
    // sticky directory, and the mounted root reports any owner and mode. Method: the rule on
    // stat results: a mount root, another mount id, and (with no mount id) another device are
    // refused there; the same entries pass in a directory only root can write; the mount id,
    // where both have one, decides over the device (an overlay's files can report another).
    const euid: u32 = 1000;
    const shared: Owner = .{ .uid = 0, .mode = sys.S.IFDIR | 0o1777, .device = 7, .mount = 3 };
    const closed: Owner = .{ .uid = 0, .mode = sys.S.IFDIR | 0o755, .device = 7, .mount = 3 };
    const file = sys.S.IFREG | 0o644;
    const same: Owner = .{ .uid = 0, .mode = file, .device = 7, .mount = 3 };
    try testing.expect(entry_problem(shared, same, euid) == null);
    const own: Owner = .{ .uid = euid, .mode = file, .device = 9, .mount = 3 };
    try testing.expect(entry_problem(shared, own, euid) == null);
    var unmounted = shared;
    unmounted.mount = null;
    const mounted: Owner = .{ .uid = 0, .mode = file, .device = 7, .mount = 3, .mount_root = true };
    const refused = [_]struct { Owner, Owner, EntryProblem }{
        .{ shared, mounted, .mount_root },
        .{ shared, .{ .uid = 0, .mode = file, .device = 7, .mount = 4 }, .other_mount },
        .{ unmounted, .{ .uid = 0, .mode = file, .device = 8 }, .other_mount },
        .{ shared, .{ .uid = 0, .mode = file, .device = 8 }, .other_mount },
        .{ shared, .{ .uid = 1001, .mode = file, .device = 7, .mount = 3 }, .foreign_owner },
    };
    for (refused) |case| {
        try testing.expectEqual(case[2], entry_problem(case[0], case[1], euid).?);
        try testing.expect(entry_problem(closed, case[1], euid) == null);
    }
    // A real mount: as root, bind a directory over a name in a 1777 directory; refused. Linux
    // alone: macOS has no bind mount (there the device check is all, and the table covers it).
    if (!sys.is_linux) return error.SkipZigTest;
    if (sys.geteuid() != 0) return error.SkipZigTest;
    const linux = std.os.linux;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const base = try test_directory(arena);
    defer std.Io.Dir.cwd().deleteTree(io, base) catch {}; // Best effort: it is in /tmp.
    const good = try test_subdirectory(arena, base, "good");
    _ = try write_test_policy(arena, good);
    const sticky = try test_subdirectory(arena, base, "shared");
    try chmod_directory(sticky, 0o1777);
    const over = try test_subdirectory(arena, sticky, "over");
    const path = try std.fmt.allocPrint(arena, "{s}/trust.zon", .{over});
    var diag: Diag = undefined;
    diag.reset();
    try testing.expectError(error.BadConfig, read(arena, io, path, test_options, &diag));
    const bind = linux.mount(good, over, null, linux.MS.BIND, 0);
    if (linux.errno(bind) == .PERM) return error.SkipZigTest; // No CAP_SYS_ADMIN here.
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(bind));
    defer _ = linux.umount2(over, linux.MNT.DETACH); // Runs before the tree is deleted.
    diag.reset();
    try testing.expectError(error.BadConfig, read(arena, io, path, test_options, &diag));
    // The kernel sets `STATX_ATTR_MOUNT_ROOT` on a bind mount's root from Linux 5.8; before
    // it, the mount id (or the device) differs instead. Where the kernel reports the flag (read
    // here as linux/stat.h's 0x2000, apart from `trust_sys`), the cause must name it, so a
    // `trust_sys` that read the wrong bit (the pinned std's) fails here (PR #13's review).
    const words = if (test_reports_mount_root(try arena.dupeSentinel(u8, over, 0)))
        "that is a mount point"
    else
        "on another mount than its directory";
    const expected = try std.fmt.allocPrint(arena, "a directory {s}, in a directory others may " ++
        "write (mode 1777), is on the trust policy's path: {s}, on the way to {s}", .{
        words, over, path,
    });
    try expect_cause(expected, diag.causes.slice()[0].slice());
}

/// Whether the kernel reports `STATX_ATTR_MOUNT_ROOT` (0x2000 in linux/stat.h) for `path`.
fn test_reports_mount_root(path: [*:0]const u8) bool {
    const linux = std.os.linux;
    var stat = std.mem.zeroes(linux.Statx);
    const flags = linux.AT.SYMLINK_NOFOLLOW;
    const result = linux.statx(linux.AT.FDCWD, path, flags, .{ .TYPE = true }, &stat);
    assert(linux.errno(result) == .SUCCESS);
    return @as(u64, @bitCast(stat.attributes_mask)) & 0x2000 != 0;
}

test "in a directory others may write, nothing but a directory may have another name" {
    // Goal: PR #13's review (SHOULD): with `fs.protected_hardlinks` off (the kernel's default),
    // anyone may `ln /etc/zigbox/policy.zon /tmp/zcube-trust.zon` before the operator makes it:
    // a root-owned, 0644 file on the directory's own mount, which the server would then read.
    // Method: the rule on stat results (a file or link of 2 names, or of an unreported count,
    // refused there and passed in a closed directory; a directory of many passed); then a real
    // policy hard-linked into a 1777 directory, refused, and read under its first name.
    const euid: u32 = 1000;
    const shared: Owner = .{ .uid = 0, .mode = sys.S.IFDIR | 0o1777, .device = 7, .mount = 3 };
    const closed: Owner = .{ .uid = 0, .mode = sys.S.IFDIR | 0o755, .device = 7, .mount = 3 };
    const file: Owner = .{ .uid = 0, .mode = sys.S.IFREG | 0o644, .device = 7, .mount = 3 };
    try testing.expect(entry_problem(shared, file, euid) == null);
    var directory = file;
    directory.mode = sys.S.IFDIR | 0o755;
    directory.links = 5;
    try testing.expect(entry_problem(shared, directory, euid) == null);
    var linked = file;
    linked.links = 2;
    var unreported = file;
    unreported.links = 0;
    var link = linked;
    link.mode = sys.S.IFLNK | 0o777;
    for ([_]Owner{ linked, unreported, link }) |entry| {
        try testing.expectEqual(EntryProblem.hard_link, entry_problem(shared, entry, euid).?);
        try testing.expect(entry_problem(closed, entry, euid) == null);
    }

    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const base = try test_directory(arena);
    defer std.Io.Dir.cwd().deleteTree(io, base) catch {}; // Best effort: it is in /tmp.
    const good = try test_subdirectory(arena, base, "good");
    const target = try arena.dupeSentinel(u8, try write_test_policy(arena, good), 0);
    const sticky = try test_subdirectory(arena, base, "shared");
    try chmod_directory(sticky, 0o1777);
    const squat = try std.fmt.allocPrintSentinel(arena, "{s}/trust.zon", .{sticky}, 0);
    var diag: Diag = undefined;
    diag.reset();
    _ = try read(arena, io, target, test_options, &diag);
    try sys.test_link(target, squat);
    diag.reset();
    try testing.expectError(error.BadConfig, read(arena, io, squat, test_options, &diag));
    try testing.expectEqual(@as(?codes.Code, .E0505), diag.code);
    const expected = try std.fmt.allocPrint(arena, "a file with 2 hard links, in a directory " ++
        "others may write (mode 1777), is on the trust policy's path: {s}", .{squat});
    try expect_cause(expected, diag.causes.slice()[0].slice());
    // Under its first name, in a directory only its owner can write, it is still read.
    diag.reset();
    _ = try read(arena, io, target, test_options, &diag);
}

test "a refusal says why before it names the paths, which may be long" {
    // Goal: PR #10's third review (SHOULD): a cause is cut at `diag_field_bytes_max`, so the
    // reason must come before the paths. Method: a policy path of over 150 bytes, missing, then
    // in a directory others may write: each cause starts with its reason and keeps it.
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const base = try test_directory(arena);
    defer std.Io.Dir.cwd().deleteTree(io, base) catch {}; // Best effort: it is in /tmp.
    const long_name = "a-directory-with-a-rather-long-name-to-push-the-policy-path-past-the-cap";
    const held = try test_subdirectory(arena, base, long_name ++ "-" ++ long_name);
    const missing = try std.fmt.allocPrint(arena, "{s}/absent.zon", .{held});
    try testing.expect(missing.len > 150);
    var diag: Diag = undefined;
    diag.reset();
    try testing.expectError(error.BadConfig, read(arena, io, missing, test_options, &diag));
    const absent = diag.causes.slice()[0].slice();
    const reason = "can't look up the trust policy: no such file or directory (" ++
        sys.look_up_call ++ " ENOENT): ";
    try testing.expect(std.mem.startsWith(u8, absent, reason));
    const path = try write_test_policy(arena, held);
    try chmod_directory(held, 0o775);
    diag.reset();
    try testing.expectError(error.BadConfig, read(arena, io, path, test_options, &diag));
    const writable = diag.causes.slice()[0].slice();
    try testing.expect(writable.len <= constants.diag_field_bytes_max);
    const words = "a directory on the trust policy's path can be written by its group or by " ++
        "others (owner uid ";
    try testing.expect(std.mem.startsWith(u8, writable, words));
    try testing.expect(std.mem.indexOf(u8, writable, "mode 0775): /tmp/zcube-trust-") != null);
}

/// `cause` is `expected`, or its start cut at `diag_field_bytes_max` and marked with "...".
fn expect_cause(expected: []const u8, cause: []const u8) !void {
    if (cause.len < constants.diag_field_bytes_max) {
        return testing.expectEqualStrings(expected, cause);
    }
    try testing.expectEqual(@as(usize, constants.diag_field_bytes_max), cause.len);
    try testing.expect(std.mem.endsWith(u8, cause, "..."));
    const kept = cause[0 .. cause.len - "...".len];
    try testing.expect(std.mem.startsWith(u8, expected, kept));
}

/// A fresh directory for a test's policies, `/tmp/zcube-trust-<random>`, mode 0700 whatever the
/// umask: `/tmp` (root's, sticky) and `/` pass the directory rule, so a policy in it is judged by
/// its own owner and mode, never by the checkout's. The caller deletes it.
pub fn test_directory(arena: Allocator) ![:0]const u8 {
    var random: [8]u8 = undefined;
    try sys.test_random(&random);
    const name = std.mem.readInt(u64, &random, .little);
    const path = try std.fmt.allocPrintSentinel(arena, "/tmp/zcube-trust-{x:0>16}", .{name}, 0);
    try sys.test_mkdir(path, 0o700);
    try chmod_directory(path, 0o700);
    return path;
}

/// `parent/name`, made a directory of mode 0755 whatever the umask.
fn test_subdirectory(arena: Allocator, parent: []const u8, name: []const u8) ![:0]const u8 {
    const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ parent, name }, 0);
    try sys.test_mkdir(path, 0o755);
    try chmod_directory(path, 0o755);
    return path;
}

/// Writes a good policy, mode 0644, as `directory/trust.zon`, and returns its path.
fn write_test_policy(arena: Allocator, directory: []const u8) ![]const u8 {
    const io = testing.io;
    const public = zigbox.trust.key.public_text(zigbox.trust.key.public_of_seed(@splat(7)));
    const good = try std.fmt.allocPrint(arena, ".{{ .version = 1, .keys = .{{ .{{ " ++
        ".name = \"botpike\", .public = \"{s}\" }} }}, .require_signature = true }}", .{&public});
    const path = try std.fmt.allocPrint(arena, "{s}/trust.zon", .{directory});
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = good });
    const file = try std.Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o644));
    return path;
}

fn chmod_directory(path: [:0]const u8, mode: u32) !void {
    try sys.test_chmod(path, mode);
}
