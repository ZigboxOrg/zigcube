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
    const file = std.Io.Dir.cwd().openFile(io, walked.real(), .{ .follow_symlinks = false }) catch
        return bad(diag, options, "can't read the trust policy {s}", .{path}, options.fix);
    defer file.close(io);
    try check_owner(owner_of(file), path, options, diag);
    try check_same(io, file, walked.real(), path, options, diag);
    // A file of exactly the bound is allowed: the limit refuses one that reaches it.
    const limit: std.Io.Limit = .limited(zigbox.trust.limits.policy_bytes_max + 1);
    var reader = file.reader(io, &.{});
    const source = reader.interface.allocRemaining(arena, limit) catch |err| {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.StreamTooLong => bad(diag, options, "the trust policy {s} is larger than " ++
                "{d} bytes", .{ path, zigbox.trust.limits.policy_bytes_max }, "trim it"),
            error.ReadFailed => bad(diag, options, "can't read the trust policy {s}", .{path}, //
                options.fix),
        };
    };
    return parse(arena, source, path, options, diag);
}

/// Who owns the policy file and its mode bits.
pub const Owner = struct { uid: u32, mode: u32 };

const linux = std.os.linux;
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
        const result = linux.getcwd(&w.pending, w.pending.len);
        const found = if (linux.errno(result) == .SUCCESS)
            std.mem.indexOfScalar(u8, &w.pending, 0)
        else
            null;
        prefix_len = found orelse return bad(diag, options, "can't read the working " ++
            "directory, from which the trust policy {s} is a relative path", .{path}, //
            "name the policy by an absolute path");
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
    const reached = owner_stat(linux.AT.FDCWD, terminated(&buffer, w.real()), //
        linux.AT.SYMLINK_NOFOLLOW) orelse
        return bad(diag, options, "can't read the trust policy {s}", .{path}, options.fix);
    assert(reached.mode & linux.S.IFMT != linux.S.IFLNK);
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
    const owner = owner_stat(linux.AT.FDCWD, candidate, linux.AT.SYMLINK_NOFOLLOW) orelse
        return bad(diag, options, "can't read the trust policy {s}", .{path}, options.fix);
    try check_entry(holder, owner, candidate, path, options, diag);
    const kind = owner.mode & linux.S.IFMT;
    if (kind == linux.S.IFLNK) {
        w.resolved_len = parent_len;
        return walk_link(w, candidate, separated, path, options, diag);
    }
    // The kernel refuses a file followed by a separator (ENOTDIR), so `trust.zon/` and
    // `trust.zon/../trust.zon` are refused here too, not read by a textual `..`.
    if (separated and kind != linux.S.IFDIR) {
        return bad(diag, options, "the trust policy {s} goes on past {s}, which is not a " ++
            "directory", .{ path, candidate }, options.fix);
    }
}

/// In a directory others may write (the sticky exception), whoever made an entry owns it and may
/// point it anywhere, so every entry the walk passes there, a link included, must be owned by
/// root or the process's own user: the rule of `fs.protected_symlinks`, which the walk's
/// `readlinkat` is not subject to (PR #10's re-review).
fn check_entry(
    holder: Owner,
    entry: Owner,
    name: []const u8,
    path: []const u8,
    options: Options,
    diag: *Diag,
) Error!void {
    if (holder.mode & 0o022 == 0) return;
    assert(holder.mode & linux.S.ISVTX != 0);
    const euid = linux.geteuid();
    if (entry.uid == 0 or entry.uid == euid) return;
    const what = switch (entry.mode & linux.S.IFMT) {
        linux.S.IFLNK => "a symbolic link",
        linux.S.IFDIR => "a directory",
        else => "a file",
    };
    // The policy's own path is named once when it is the entry, so the line stays short.
    if (std.mem.eql(u8, name, path)) {
        return bad(diag, options, "the trust policy {s} is {s} owned by uid {d}, in a " ++
            "directory others may write (mode {o:0>4})", .{
            path, what, entry.uid, holder.mode & 0o7777,
        }, directory_fix);
    }
    return bad(diag, options, "the trust policy {s} goes through {s}, {s} owned by uid {d}, " ++
        "in a directory others may write", .{ path, name, what, entry.uid }, directory_fix);
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
        return bad(diag, options, "the trust policy {s} goes through more than {d} symbolic " ++
            "links", .{ path, constants.trust_policy_links_max }, options.fix);
    }
    var target: [path_max]u8 = undefined;
    const result = linux.readlinkat(linux.AT.FDCWD, link, &target, target.len);
    if (linux.errno(result) != .SUCCESS or result == 0) {
        return bad(diag, options, "can't read the symbolic link {s} on the way to the trust " ++
            "policy {s}", .{ link, path }, options.fix);
    }
    const length: usize = result;
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
    const owner = owner_stat(linux.AT.FDCWD, terminated(&buffer, directory), //
        linux.AT.SYMLINK_NOFOLLOW) orelse
        return bad(diag, options, "can't read the owner of {s}, the directory of the " ++
            "trust policy {s}", .{ directory, path }, options.fix);
    const problem = directory_problem(owner, linux.geteuid()) orelse return owner;
    return bad(diag, options, "the trust policy {s} is in {s}, which {s}{s} " ++
        "(owner uid {d}, mode {o:0>4})", .{
        path,
        directory,
        problem.text(),
        if (problem == .foreign_owner) options.user else "",
        owner.uid,
        owner.mode & 0o7777,
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
        "which file was opened as the trust policy {s} (is /proc mounted?)", .{path}, //
        "mount /proc where the process runs");
    if (std.mem.eql(u8, buffer[0..length], real)) return;
    return bad(diag, options, "the trust policy {s} changed while it was read: {s} was " ++
        "judged, {s} was opened", .{ path, real, buffer[0..length] }, options.fix);
}

fn too_long(path: []const u8, options: Options, diag: *Diag) Error {
    return bad(diag, options, "the trust policy {s} is longer than Linux's path limit once " ++
        "made absolute and its links followed", .{path}, options.fix);
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

/// Null when a directory of this owner and mode keeps a policy file in it from being swapped by
/// anyone but root and `euid`; otherwise what is wrong (never `not_regular`). A directory others
/// may write is allowed only with the sticky bit (`/tmp`): there no one may rename or remove a
/// file they do not own.
pub fn directory_problem(owner: Owner, euid: u32) ?OwnerProblem {
    if (owner.uid != 0 and owner.uid != euid) return .foreign_owner;
    if (owner.mode & 0o022 != 0 and owner.mode & linux.S.ISVTX == 0) return .writable;
    return null;
}

fn check_owner(owner_or_null: ?Owner, path: []const u8, options: Options, diag: *Diag) Error!void {
    const owner = owner_or_null orelse
        return bad(diag, options, "can't read the trust policy {s}", .{path}, options.fix);
    const problem = owner_problem(owner, linux.geteuid()) orelse return;
    return bad(diag, options, "the trust policy {s} {s}{s} (owner uid {d}, mode {o:0>4})", .{
        path,
        problem.text(),
        if (problem == .foreign_owner) options.user else "",
        owner.uid,
        owner.mode & 0o7777,
    }, options.owner_fix);
}

fn owner_of(file: std.Io.File) ?Owner {
    return owner_stat(file.handle, "", linux.AT.EMPTY_PATH);
}

fn owner_stat(dir: linux.fd_t, path: [*:0]const u8, flags: u32) ?Owner {
    var stat = std.mem.zeroes(linux.Statx);
    const mask: linux.STATX = .{ .TYPE = true, .MODE = true, .UID = true };
    const result = linux.statx(dir, path, flags, mask, &stat);
    if (linux.errno(result) != .SUCCESS) return null;
    if (!stat.mask.MODE or !stat.mask.UID) return null;
    return .{ .uid = stat.uid, .mode = stat.mode };
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
    if (owner.mode & linux.S.IFMT != linux.S.IFREG) return .not_regular;
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
        return bad(diag, options, "the trust policy {s} is not a policy zbx reads: {t} at " ++
            "{d}:{d}{s}{s}", .{
            path,
            problem.kind,
            problem.line,
            problem.column,
            if (detail.len > 0) " near " else "",
            detail,
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
    const regular: u32 = linux.S.IFREG;
    try testing.expect(owner_problem(.{ .uid = 0, .mode = regular | 0o644 }, euid) == null);
    try testing.expect(owner_problem(.{ .uid = euid, .mode = regular | 0o600 }, euid) == null);
    try testing.expect(owner_problem(.{ .uid = 0, .mode = regular | 0o4755 }, euid) == null);
    const refused = [_]struct { Owner, OwnerProblem }{
        .{ .{ .uid = 1001, .mode = regular | 0o644 }, .foreign_owner },
        .{ .{ .uid = 0, .mode = regular | 0o664 }, .writable },
        .{ .{ .uid = euid, .mode = regular | 0o646 }, .writable },
        .{ .{ .uid = 0, .mode = linux.S.IFDIR | 0o755 }, .not_regular },
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
    const made = linux.mknodat(linux.AT.FDCWD, fifo, linux.S.IFIFO | 0o600, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(made));
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
    const directory: u32 = linux.S.IFDIR;
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
        try testing.expect(std.mem.indexOf(u8, cause, "/policy, which can be written") != null);
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
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.symlink(pair[0], pair[1])));
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
        .{ links, "/links, which can be written" },
        .{ good, "/good, which can be written" },
    };
    for (cases) |case| {
        try chmod_directory(case[0], 0o775);
        for (paths) |path| {
            diag.reset();
            try testing.expectError(error.BadConfig, read(arena, io, path, test_options, &diag));
            const cause = diag.causes.slice()[0].slice();
            try testing.expect(std.mem.indexOf(u8, cause, case[1]) != null);
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
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.symlink(target, link)));
    var diag: Diag = undefined;
    diag.reset();
    _ = try read(arena, io, link, test_options, &diag);
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const nobody: u32 = 65534;
    const chowned = linux.fchownat(linux.AT.FDCWD, link, nobody, nobody, linux.AT.SYMLINK_NOFOLLOW);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(chowned));
    diag.reset();
    try testing.expectError(error.BadConfig, read(arena, io, link, test_options, &diag));
    try testing.expectEqual(@as(?codes.Code, .E0505), diag.code);
    const expected = "is a symbolic link owned by uid 65534, in a directory others may write " ++
        "(mode 1777)";
    try testing.expect(std.mem.indexOf(u8, diag.causes.slice()[0].slice(), expected) != null);
    // Through the link, it is named as the entry the walk passed.
    const through = try std.fmt.allocPrint(arena, "{s}/./trust.zon", .{shared});
    diag.reset();
    try testing.expectError(error.BadConfig, read(arena, io, through, test_options, &diag));
    const through_cause = diag.causes.slice()[0].slice();
    const named = try std.fmt.allocPrint(arena, "goes through {s}, a symbolic", .{link});
    try testing.expect(std.mem.indexOf(u8, through_cause, named) != null);
    // A file planted there by another uid is refused the same way.
    const planted = try write_test_policy(arena, try test_subdirectory(arena, shared, "own"));
    const file = try std.fmt.allocPrintSentinel(arena, "{s}/file.zon", .{shared}, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.rename(
        try arena.dupeSentinel(u8, planted, 0),
        file,
    )));
    const file_chowned = linux.fchownat(linux.AT.FDCWD, file, nobody, nobody, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(file_chowned));
    diag.reset();
    try testing.expectError(error.BadConfig, read(arena, io, file, test_options, &diag));
    const file_cause = diag.causes.slice()[0].slice();
    try testing.expect(std.mem.indexOf(u8, file_cause, "is a file owned by uid 65534,") != null);
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
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.symlink("trust.zon", link)));
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
        try testing.expect(std.mem.indexOf(u8, cause, "which is not a directory") != null);
    }
}

/// A fresh directory for a test's policies, `/tmp/zcube-trust-<random>`, mode 0700 whatever the
/// umask: `/tmp` (root's, sticky) and `/` pass the directory rule, so a policy in it is judged by
/// its own owner and mode, never by the checkout's. The caller deletes it.
pub fn test_directory(arena: Allocator) ![:0]const u8 {
    var random: [8]u8 = undefined;
    const got = linux.getrandom(&random, random.len, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(got));
    try testing.expectEqual(random.len, got);
    const name = std.mem.readInt(u64, &random, .little);
    const path = try std.fmt.allocPrintSentinel(arena, "/tmp/zcube-trust-{x:0>16}", .{name}, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mkdir(path, 0o700)));
    try chmod_directory(path, 0o700);
    return path;
}

/// `parent/name`, made a directory of mode 0755 whatever the umask.
fn test_subdirectory(arena: Allocator, parent: []const u8, name: []const u8) ![:0]const u8 {
    const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ parent, name }, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mkdir(path, 0o755)));
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
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.chmod(path, mode)));
}
