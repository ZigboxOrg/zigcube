//! A Zigbox trust policy file, read once at start (B5): by `zcube-server` for its `trust` entry
//! (ZC-E0106) and by `zcube-agent` for `--trust-policy` (ZC-E0505). Shell code: it reads a file.
//!
//! The file is judged and read through one descriptor, so it cannot be swapped between the two.
//! It must be a regular file, owned by root or by the process's own user, and writable by neither
//! group nor others: Zigbox's rule for its system policy (`trust/gate.zig`, "the system policy
//! binds users who cannot write it"), carried over to a process that need not run as root
//! (docs/decisions/2026-11-13-b5-policy-file-ownership.md). A policy Zigbox refuses names its
//! line, column and kind.

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
    // The path is judged before it is opened: opening a FIFO for reading blocks until a writer
    // comes, so a FIFO must be refused unopened. The open file is judged again, in case the
    // path was swapped in between.
    const path_z = try arena.dupeSentinel(u8, path, 0);
    try check_owner(owner_at(path_z), path, options, diag);
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch
        return bad(diag, options, "can't read the trust policy {s}", .{path}, options.fix);
    defer file.close(io);
    try check_owner(owner_of(file), path, options, diag);
    try check_directories(io, path, options, diag);
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

/// Each directory above the policy file, up to `/`, must be one that only root or the process's
/// own user can change: whoever may write a directory on the way can rename the policy away and
/// put their own in its place, which the next start reads (0.5.2 review 5927352205, item 8;
/// docs/decisions/2026-11-21-trust-policy-directories.md). The path is resolved first, so a
/// symbolic link is judged where it leads, as the file was.
fn check_directories(io: std.Io, path: []const u8, options: Options, diag: *Diag) Error!void {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = std.Io.Dir.cwd().realPathFile(io, path, &buffer) catch
        return bad(diag, options, "can't resolve the trust policy {s}", .{path}, options.fix);
    var real: []const u8 = buffer[0..length];
    assert(std.fs.path.isAbsolute(real));
    // A resolved path has at most one directory per separator: the walk is bounded by its length.
    var steps: usize = 0;
    while (std.fs.path.dirname(real)) |parent| : (steps += 1) {
        assert(steps < length);
        assert(parent.len < real.len);
        var parent_buffer: [std.fs.max_path_bytes:0]u8 = undefined;
        @memcpy(parent_buffer[0..parent.len], parent);
        parent_buffer[parent.len] = 0;
        const parent_z = parent_buffer[0..parent.len :0];
        const owner = owner_stat(std.os.linux.AT.FDCWD, parent_z, 0) orelse
            return bad(diag, options, "can't read the owner of {s}, the directory of the " ++
                "trust policy {s}", .{ parent, path }, options.fix);
        if (directory_problem(owner, std.os.linux.geteuid())) |problem| {
            return bad(diag, options, "the trust policy {s} is in {s}, which {s}{s} " ++
                "(owner uid {d}, mode {o:0>4})", .{
                path,
                parent,
                problem.text(),
                if (problem == .foreign_owner) options.user else "",
                owner.uid,
                owner.mode & 0o7777,
            }, directory_fix);
        }
        real = parent;
    }
}

const directory_fix = "keep the policy in a directory that only root or the process's own " ++
    "user can write, such as /etc/zcube, and chmod go-w every directory above it";

/// Null when a directory of this owner and mode keeps a policy file in it from being swapped by
/// anyone but root and `euid`; otherwise what is wrong (never `not_regular`). A directory others
/// may write is allowed only with the sticky bit (`/tmp`): there no one may rename or remove a
/// file they do not own.
pub fn directory_problem(owner: Owner, euid: u32) ?OwnerProblem {
    if (owner.uid != 0 and owner.uid != euid) return .foreign_owner;
    if (owner.mode & 0o022 != 0 and owner.mode & std.os.linux.S.ISVTX == 0) return .writable;
    return null;
}

fn check_owner(owner_or_null: ?Owner, path: []const u8, options: Options, diag: *Diag) Error!void {
    const owner = owner_or_null orelse
        return bad(diag, options, "can't read the trust policy {s}", .{path}, options.fix);
    const problem = owner_problem(owner, std.os.linux.geteuid()) orelse return;
    return bad(diag, options, "the trust policy {s} {s}{s} (owner uid {d}, mode {o:0>4})", .{
        path,
        problem.text(),
        if (problem == .foreign_owner) options.user else "",
        owner.uid,
        owner.mode & 0o7777,
    }, options.owner_fix);
}

fn owner_of(file: std.Io.File) ?Owner {
    return owner_stat(file.handle, "", std.os.linux.AT.EMPTY_PATH);
}

/// The owner of the file `path` names, following symbolic links as `openFile` does.
fn owner_at(path: [:0]const u8) ?Owner {
    return owner_stat(std.os.linux.AT.FDCWD, path, 0);
}

fn owner_stat(dir: std.os.linux.fd_t, path: [*:0]const u8, flags: u32) ?Owner {
    const linux = std.os.linux;
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
    if (owner.mode & std.os.linux.S.IFMT != std.os.linux.S.IFREG) return .not_regular;
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
    const regular: u32 = std.os.linux.S.IFREG;
    try testing.expect(owner_problem(.{ .uid = 0, .mode = regular | 0o644 }, euid) == null);
    try testing.expect(owner_problem(.{ .uid = euid, .mode = regular | 0o600 }, euid) == null);
    try testing.expect(owner_problem(.{ .uid = 0, .mode = regular | 0o4755 }, euid) == null);
    const refused = [_]struct { Owner, OwnerProblem }{
        .{ .{ .uid = 1001, .mode = regular | 0o644 }, .foreign_owner },
        .{ .{ .uid = 0, .mode = regular | 0o664 }, .writable },
        .{ .{ .uid = euid, .mode = regular | 0o646 }, .writable },
        .{ .{ .uid = 0, .mode = std.os.linux.S.IFDIR | 0o755 }, .not_regular },
    };
    for (refused) |case| try testing.expectEqual(case[1], owner_problem(case[0], euid).?);
}

test "a refusal raises the caller's code and names its setting" {
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
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var fifo_buffer: [128]u8 = undefined;
    const fifo = try std.fmt.bufPrintSentinel(&fifo_buffer, ".zig-cache/tmp/{s}/trust.zon", .{
        tmp.sub_path,
    }, 0);
    const linux = std.os.linux;
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
    const directory: u32 = std.os.linux.S.IFDIR;
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
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "policy", .default_dir);
    const public = zigbox.trust.key.public_text(zigbox.trust.key.public_of_seed(@splat(7)));
    const good = try std.fmt.allocPrint(arena, ".{{ .version = 1, .keys = .{{ .{{ " ++
        ".name = \"botpike\", .public = \"{s}\" }} }}, .require_signature = true }}", .{&public});
    try tmp.dir.writeFile(io, .{ .sub_path = "policy/trust.zon", .data = good });
    const file = try tmp.dir.openFile(io, "policy/trust.zon", .{ .mode = .read_write });
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o644));
    const held = try std.fmt.allocPrintSentinel(arena, ".zig-cache/tmp/{s}/policy", .{
        tmp.sub_path,
    }, 0);
    const path = try std.fmt.allocPrint(arena, "{s}/trust.zon", .{held});
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

fn chmod_directory(path: [:0]const u8, mode: u32) !void {
    const linux = std.os.linux;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.chmod(path, mode)));
}
