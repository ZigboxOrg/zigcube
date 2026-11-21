//! The sealing key's file and its lifecycle (docs/briefs/c5.md, "Sealing and the key's
//! lifecycle"). Shell code: it reads and writes the key file and draws the key from the kernel.
//!
//! The key is `seal-<hash>.key` (or `seal.key`), 0600, beside the CA key, named the way the CA
//! key is (`server_ca.key_name_for`). `open` is the one function that loads it:
//!
//! - No key and no sealed records (a new cluster, or a C3/C4 store upgraded): the key is made,
//!   never over a key another start wrote meanwhile (that one is read instead).
//! - Sealed records and no key, or a key that does not open one of them: ZC-E0824, naming the
//!   key file, the key id the records expect and the two fixes.
//! - `--discard-sealed` acts only then. With a key that opens every sealed record it deletes
//!   nothing, keeps the key and says so (ZC-W0808, "nothing to discard"). Otherwise `open` only
//!   plans the discard, and `discard` carries it out once every start step that can refuse has
//!   passed: the sealed records (and every ACME order) are deleted, the old key file is renamed
//!   aside (`<name>.discarded-<unix seconds>`, still 0600), a new key is written and ZC-W0808 is
//!   printed (docs/decisions/2026-11-18-c5-seal-fix-discard-and-find.md).
//!
//! The start-up check reads through the raw store, so that a store halted by the verified pair
//! (`first_check`) is still checked; the discard writes through the guarded store, so that its
//! deletes advance the remembered pair. Nothing here prints a key: only key ids.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const diag_mod = @import("diag.zig");
const files = @import("peer_files.zig");
const seal = @import("seal.zig");
const secure_random = @import("secure_random.zig");
const store = @import("store.zig");

const Allocator = std.mem.Allocator;
const Diag = diag_mod.Diag;

/// `Failed`: `diag` says why (ZC-E0824, ZC-E0806, ZC-E0821 or the store's code).
/// `Canceled`: the task was cancelled while the key was drawn; `diag` is empty.
pub const Error = files.Error || error{ OutOfMemory, Canceled };

pub const key_name_bytes_max = 64;
/// A key name, ".discarded-" and a count of seconds.
pub const aside_name_bytes_max = key_name_bytes_max + ".discarded-".len + 20;

/// The most records the start-up check reads under one prefix, and so the most `--discard-sealed`
/// is ever asked to delete under one: 4096 pages of 500, 2,048,000.
pub const scan_records_max: u64 = records_max(constants.seal_scan_pages_max);

/// The most records a scan of `pages_max` pages reads under one prefix.
fn records_max(pages_max: u32) u64 {
    assert(pages_max > 0);
    assert(pages_max <= constants.seal_scan_pages_max);
    return @as(u64, pages_max) * constants.store_list_limit_max;
}

/// The discard's rounds of `store_txn_ops_max` deletes under one prefix: enough for every record
/// a scan of `pages_max` pages admits, plus one failed compare (a record rewritten meanwhile)
/// per page, plus the last round, whose listing finds the prefix empty: with exactly that many
/// records and failed compares, the discard still sees that it finished.
fn rounds_max(pages_max: u32) u64 {
    const rounds = std.math.divCeil(u64, records_max(pages_max), constants.store_txn_ops_max) catch
        unreachable; // The divisor is a positive constant.
    assert(rounds * constants.store_txn_ops_max >= records_max(pages_max));
    return rounds + pages_max + 1;
}

comptime {
    assert(scan_records_max == 2_048_000);
    assert(rounds_max(constants.seal_scan_pages_max) == 128_000 + 4096 + 1);
}

pub const Options = struct {
    /// The key file's name in the state directory (`key_name_for`).
    key_name: []const u8,
    /// `--discard-sealed`.
    discard: bool = false,
    /// Say nothing on stderr (tests).
    quiet: bool = false,
    /// The pages the start-up check reads under one prefix, and so the discard's rounds: the
    /// constant, lowered only by tests to reach the bound with few records.
    scan_pages_max: u32 = constants.seal_scan_pages_max,
};

/// What `open` decided.
pub const Opened = union(enum) {
    /// The start goes on with this key.
    ready: seal.Key,
    /// `--discard-sealed`, and the key does not open the sealed records: `discard` deletes them
    /// and makes the key, after every start step that can refuse.
    discard,
};

/// The sealing key's file for the CA key file `ca_name`: `ca.key` gives `seal.key`, and
/// `ca-<hash>.key` gives `seal-<hash>.key`, so two stores sharing a state directory never share
/// a sealing key. The name is in `buffer`.
pub fn key_name_for(ca_name: []const u8, buffer: *[key_name_bytes_max]u8) []const u8 {
    assert(std.mem.startsWith(u8, ca_name, "ca"));
    assert(std.mem.endsWith(u8, ca_name, ".key"));
    assert(ca_name.len + 2 <= key_name_bytes_max);
    return std.fmt.bufPrint(buffer, "seal{s}", .{ca_name["ca".len..]}) catch
        unreachable; // Asserted above.
}

/// What the start-up check found: how many sealed records, and the first one the key does not
/// open, if any.
const Scan = struct {
    records: u64 = 0,
    refused: ?Refused = null,

    const Refused = struct {
        key_buffer: [constants.store_key_bytes_max]u8 = undefined,
        key_length: u32 = 0,
        expected: ?seal.KeyId,
        why: []const u8,
        /// The record cannot be read under any key (not one JSON object, a sealed member that
        /// is not one envelope of this version): the record is at fault, not the key file.
        damaged: bool,

        fn key(refused: *const Refused) []const u8 {
            return refused.key_buffer[0..refused.key_length];
        }
    };
};

/// Loads or makes the sealing key, or (with `discard`, when the key does not open the sealed
/// records) plans the discard. `scan` is the raw store; `state_dir` null means a memory store,
/// whose key lives in memory only. Deletes nothing.
pub fn open(
    gpa: Allocator,
    io: std.Io,
    scan: store.Store,
    state_dir: ?[]const u8,
    options: Options,
    diag: *Diag,
) Error!Opened {
    assert(diag.code == null);
    assert(options.key_name.len > 0);
    var found = try load(io, state_dir, options.key_name, diag);
    defer if (found) |*key| key.wipe();
    var result: Scan = .{};
    try check(gpa, scan, if (found) |*key| key else null, options.scan_pages_max, &result, diag);
    if (result.refused) |*refused| {
        if (options.discard) {
            // Planned first, so that the discard can finish: every prefix it empties is within
            // the bound its rounds are sized for.
            for (seal.discarded_prefixes) |prefix| {
                var counter: Counter = .{};
                try walk(gpa, scan, prefix, options.scan_pages_max, &counter, diag);
            }
            return .discard;
        }
        const found_id: ?seal.KeyId = if (found) |*key| key.id() else null;
        raise_refused(diag, .{
            .state_dir = state_dir,
            .key_name = options.key_name,
            .records = result.records,
            .record = refused.key(),
            .why = refused.why,
            .expected = refused.expected,
            .found = found_id,
            .damaged = refused.damaged,
        });
        return error.Failed;
    }
    if (options.discard and !options.quiet) warn_nothing(io);
    if (found) |key| return .{ .ready = key };
    assert(result.records == 0);
    return .{ .ready = try make(io, state_dir, options.key_name, diag) };
}

/// The key in the state directory, or null if there is no file (or no directory: memory).
fn load(io: std.Io, state_dir: ?[]const u8, name: []const u8, diag: *Diag) Error!?seal.Key {
    const path = state_dir orelse return null;
    var dir = try open_dir(io, path, name, diag);
    defer dir.close(io);
    const seed = try files.read_seed(io, dir, path, name, diag) orelse return null;
    return .{ .bytes = seed };
}

/// A new key from the kernel (ZC-E0821 if it fails), written to the state directory if there
/// is one. The file is never replaced: if another start wrote one first, that key is read and
/// returned instead, so two racing starts agree on one key.
fn make(io: std.Io, state_dir: ?[]const u8, name: []const u8, diag: *Diag) Error!seal.Key {
    var key: seal.Key = .{ .bytes = undefined };
    errdefer key.wipe();
    secure_random.fill(io, &key.bytes, diag, "the sealing key") catch |err| return switch (err) {
        error.Unavailable => error.Failed,
        error.Canceled => error.Canceled,
    };
    const path = state_dir orelse return key;
    var dir = try open_dir(io, path, name, diag);
    defer dir.close(io);
    if (try files.write_seed_new(io, dir, path, name, key.bytes, diag)) return key;
    key.wipe();
    return read_winner(io, dir, path, name, diag);
}

/// The key another start wrote first, which `make` found in its way: read, never replaced.
/// Gone again by now is ZC-E0806, never a second key.
fn read_winner(
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
    name: []const u8,
    diag: *Diag,
) Error!seal.Key {
    const seed = try files.read_seed(io, dir, path, name, diag) orelse {
        return files.unusable(diag, path, name, "read", "it was written and then removed");
    };
    return .{ .bytes = seed };
}

fn open_dir(io: std.Io, path: []const u8, name: []const u8, diag: *Diag) Error!std.Io.Dir {
    files.make_dir(io, path) catch |err| {
        return files.unusable(diag, path, name, "create the directory for", @errorName(err));
    };
    var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch |err| {
        return files.unusable(diag, path, name, "open the directory of", @errorName(err));
    };
    errdefer dir.close(io);
    try files.check_dir(io, dir, path, name, diag);
    return dir;
}

/// Opens every sealed record with `key` (or, with no key, notes the first), stopping at the
/// first that does not open. The plaintext is wiped as soon as it is read.
fn check(
    gpa: Allocator,
    scan: store.Store,
    key: ?*const seal.Key,
    pages_max: u32,
    result: *Scan,
    diag: *Diag,
) Error!void {
    for (seal.sealed_prefixes) |prefix| {
        var checker: Checker = .{ .key = key, .result = result };
        try walk(gpa, scan, prefix, pages_max, &checker, diag);
        if (result.refused != null) return;
    }
}

const Checker = struct {
    key: ?*const seal.Key,
    result: *Scan,

    fn visit(checker: *Checker, kv: store.KeyValue) bool {
        check_one(kv, checker.key, checker.result);
        return checker.result.refused == null;
    }
};

const Counter = struct {
    records: u64 = 0,

    fn visit(counter: *Counter, kv: store.KeyValue) bool {
        _ = kv;
        counter.records += 1;
        return true;
    }
};

/// Lists every record under `prefix` at one revision, page by page, handing each to
/// `visitor.visit` until it returns false. More than `pages_max` pages of records is ZC-E0824:
/// the start is refused, never half-checked.
fn walk(
    gpa: Allocator,
    scan: store.Store,
    prefix: []const u8,
    pages_max: u32,
    visitor: anytype,
    diag: *Diag,
) Error!void {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var revision: ?store.Revision = null;
    var after: ?[]const u8 = null;
    var after_buffer: [constants.store_key_bytes_max]u8 = undefined;
    var pages: u32 = 0;
    assert(pages_max <= constants.seal_scan_pages_max);
    while (pages < pages_max) : (pages += 1) {
        _ = arena_state.reset(.retain_capacity);
        const page = scan.list(arena_state.allocator(), .{
            .prefix = prefix,
            .at_revision = revision,
            .limit = constants.store_list_limit_max,
            .continue_after = after,
        }, diag) catch return error.Failed;
        revision = page.revision;
        for (page.kvs) |kv| {
            if (!visitor.visit(kv)) return;
        }
        const next = page.continue_after orelse return;
        @memcpy(after_buffer[0..next.len], next);
        after = after_buffer[0..next.len];
    }
    raise_too_many(diag, prefix, pages_max);
    return error.Failed;
}

/// ZC-E0824 for a prefix past the bound: one cause naming the bound and what was found, and a
/// fix that is not `--discard-sealed` (which would delete every one of them). Public for the
/// CLI golden test.
pub fn raise_too_many(diag: *Diag, prefix: []const u8, pages_max: u32) void {
    assert(diag.code == null);
    const records = records_max(pages_max);
    diag.raise(.E0824);
    diag.cause("more than {d} records under {s}; the start-up check reads at most {d} " ++
        "({d} pages of {d}), so it refuses to start rather than check part of them", .{
        records, prefix, records, pages_max, constants.store_list_limit_max,
    });
    diag.fix(.{ .sentence = "delete the records under that prefix that no public host uses " ++
        "any more, then start again" });
}

fn check_one(kv: store.KeyValue, key: ?*const seal.Key, result: *Scan) void {
    assert(result.refused == null);
    // Only the record's sealed member is opened (seal.sealed_of): a record without one holds
    // nothing sealed (an entry not yet given a key), and a record that cannot be read is
    // refused like one that does not open.
    const sealed = seal.sealed_of(kv.value);
    if (sealed == .none) return;
    result.records += 1;
    var expected: ?seal.KeyId = null;
    const why: Why = switch (sealed) {
        .none => unreachable, // Returned above.
        .unreadable => |text| .{ .text = text, .damaged = true },
        .envelope => |envelope| why: {
            expected = seal.key_id_of(envelope);
            break :why refusal_of(envelope, kv.key, key) orelse return;
        },
    };
    result.refused = .{ .expected = expected, .why = why.text, .damaged = why.damaged };
    const refused = &result.refused.?;
    assert(kv.key.len <= refused.key_buffer.len);
    @memcpy(refused.key_buffer[0..kv.key.len], kv.key);
    refused.key_length = @intCast(kv.key.len);
}

/// Why a record did not open, and whether the record itself is at fault.
const Why = struct { text: []const u8, damaged: bool };

/// Why `envelope` at `path` does not open with `key`, or null if it opens. A malformed envelope
/// is damaged: no key opens it, so the key file is not the cause.
fn refusal_of(envelope: []const u8, path: []const u8, key: ?*const seal.Key) ?Why {
    const k = key orelse return .{ .text = "there is no key file", .damaged = false };
    var plain: [constants.seal_plaintext_bytes_max]u8 = undefined;
    defer std.crypto.secureZero(u8, &plain);
    _ = seal.open(k, path, envelope, &plain) catch |err| return switch (err) {
        error.Malformed => .{
            .text = "it is not a sealed envelope this server can read",
            .damaged = true,
        },
        error.WrongKey => .{ .text = "it was sealed with another key", .damaged = false },
        error.Forged => .{
            .text = "it does not open with this key (changed, or moved from another key)",
            .damaged = false,
        },
    };
    return null;
}

/// What ZC-E0824 names.
pub const Refusal = struct {
    state_dir: ?[]const u8,
    key_name: []const u8,
    /// Sealed records checked, the refused one included.
    records: u64,
    /// The store key of the first record that did not open, and why.
    record: []const u8,
    why: []const u8,
    /// The key id the record names, if its header could be read.
    expected: ?seal.KeyId,
    /// The id of the key file's key, or null if there is no file.
    found: ?seal.KeyId,
    /// The record cannot be read under any key: it is named, and deleting it is the fix.
    damaged: bool = false,
};

/// ZC-E0824. Public for the CLI golden test.
pub fn raise_refused(diag: *Diag, refusal: Refusal) void {
    assert(diag.code == null);
    if (refusal.damaged) return raise_damaged(diag, refusal);
    diag.raise(.E0824);
    // Without --verbose only the last cause is shown: it names what the operator acts on, the
    // key id the records expect and the key file; the ones before say which record and why.
    // The directory comes last: a cause is a fixed-size text, and a long path is what is cut.
    diag.cause("{d} sealed record(s) checked; the rest were not read", .{refusal.records});
    diag.cause("{s} does not open: {s}", .{ refusal.record, refusal.why });
    const expected: []const u8 = if (refusal.expected) |*id| id else "(unreadable)";
    const where = refusal.state_dir orelse "memory";
    if (refusal.found) |*id| {
        diag.cause("the records expect key id {s}; {s} holds key id {s}, in {s}", .{
            expected, refusal.key_name, id, where,
        });
    } else {
        diag.cause("the records expect key id {s}; {s} is missing from {s}", .{
            expected, refusal.key_name, where,
        });
    }
    diag.fix(.{ .sentence = "restore the key file from a backup, mode 0600, and start again" });
    diag.fix(.{
        .sentence = "or start once with --discard-sealed: every sealed record is deleted and " ++
            "every public host is ordered again",
        .command = "zcube-server --discard-sealed",
    });
}

/// ZC-E0824 for a record no key can open: the record is named in the cause shown by default,
/// with no key id (the key file is not at fault), and the first fix deletes that one record;
/// `--discard-sealed`, which deletes every sealed record, is the fallback.
fn raise_damaged(diag: *Diag, refusal: Refusal) void {
    assert(refusal.damaged);
    diag.raise(.E0824);
    diag.cause("{d} sealed record(s) checked; the rest were not read", .{refusal.records});
    diag.cause("{s} cannot be read under any key: {s}", .{ refusal.record, refusal.why });
    diag.fix(.{ .sentence = "delete that record from the store (it is not a sealed record " ++
        "this server can read), then start again" });
    diag.fix(.{
        .sentence = "or start once with --discard-sealed: every sealed record is deleted and " ++
            "every public host is ordered again",
        .command = "zcube-server --discard-sealed",
    });
}

/// Carries out the discard `open` planned: deletes the sealed records and the ACME orders, then
/// renames the old key file aside, then makes and writes a new key, then warns (ZC-W0808). The
/// server calls it after every start step that can refuse. A crash part way leaves either the
/// old key and fewer records, or no key and no records: the next start, with the flag or
/// without, is never worse off.
pub fn discard(
    gpa: Allocator,
    io: std.Io,
    write: store.Store,
    state_dir: ?[]const u8,
    options: Options,
    diag: *Diag,
) Error!seal.Key {
    assert(diag.code == null);
    assert(options.discard);
    var deleted: u64 = 0;
    for (seal.discarded_prefixes) |prefix| {
        deleted += try delete_all(gpa, write, prefix, options.scan_pages_max, diag);
    }
    var aside_buffer: [aside_name_bytes_max]u8 = undefined;
    const aside = try set_aside(io, state_dir, options.key_name, &aside_buffer, diag);
    const key = try make(io, state_dir, options.key_name, diag);
    if (!options.quiet) warn_discarded(io, deleted, key.id(), aside);
    return key;
}

/// Renames the key file to `<name>.discarded-<unix seconds>`, never over another file, and
/// returns the new name; null if there is no key file (or no directory: memory).
fn set_aside(
    io: std.Io,
    state_dir: ?[]const u8,
    name: []const u8,
    buffer: *[aside_name_bytes_max]u8,
    diag: *Diag,
) Error!?[]const u8 {
    const path = state_dir orelse return null;
    var dir = try open_dir(io, path, name, diag);
    defer dir.close(io);
    dir.access(io, name, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return files.unusable(diag, path, name, "read", @errorName(err)),
    };
    const seconds = @divFloor(std.Io.Clock.real.now(io).toMilliseconds(), 1000);
    const aside = std.fmt.bufPrint(buffer, "{s}.discarded-{d}", .{ name, seconds }) catch
        unreachable; // A name of at most key_name_bytes_max and a 64-bit count.
    if (!try files.rename_new(io, dir, path, name, aside, diag)) {
        return files.unusable(diag, path, aside, "keep the old key as", "that file exists");
    }
    try files.sync_dir(io, dir, path, aside, diag);
    return aside;
}

/// Deletes every record under `prefix`, `store_txn_ops_max` to a transaction. Returns how many.
fn delete_all(
    gpa: Allocator,
    write: store.Store,
    prefix: []const u8,
    pages_max: u32,
    diag: *Diag,
) Error!u64 {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var deleted: u64 = 0;
    var round: u64 = 0;
    const rounds = rounds_max(pages_max);
    while (round < rounds) : (round += 1) {
        _ = arena_state.reset(.retain_capacity);
        const page = write.list(arena_state.allocator(), .{
            .prefix = prefix,
            .limit = constants.store_txn_ops_max,
        }, diag) catch return error.Failed;
        if (page.kvs.len == 0) return deleted;
        var ops: [constants.store_txn_ops_max]store.Op = undefined;
        var compares: [constants.store_txn_ops_max]store.Compare = undefined;
        for (page.kvs, 0..) |kv, index| {
            ops[index] = .{ .delete = kv.key };
            compares[index] = .{ .key = kv.key, .mod_revision = kv.mod_revision };
        }
        // Compared, so a record rewritten meanwhile is listed and judged again, never lost
        // unseen; a failed compare deletes nothing and the next round lists afresh.
        const result = write.txn(.{
            .compares = compares[0..page.kvs.len],
            .on_success = ops[0..page.kvs.len],
        }, diag) catch return error.Failed;
        if (result.succeeded) deleted += page.kvs.len;
    }
    raise_unfinished(diag, prefix, rounds);
    return error.Failed;
}

/// ZC-E0824 for a discard that could not finish: something kept writing under `prefix`. The fix
/// is not the flag, which the operator is already using. Public for the CLI golden test.
pub fn raise_unfinished(diag: *Diag, prefix: []const u8, rounds: u64) void {
    assert(diag.code == null);
    diag.raise(.E0824);
    diag.cause("--discard-sealed could not empty {s}: records kept appearing there after {d} " ++
        "rounds of deletes, so another writer is at work; the old key file is unchanged", .{
        prefix, rounds,
    });
    diag.fix(.{ .sentence = "stop every other zcube-server on this store, then start again" });
}

/// ZC-W0808 on stderr, rendered verbose: every cause matters once (the count, the new key's id,
/// where the old key went, the limits), and the text mode shows only the last.
fn warn(io: std.Io, diag: *Diag) void {
    var diagnostic: diag_mod.Diagnostic = undefined;
    diag_mod.to_diagnostic(&diagnostic, diag);
    var buffer: [constants.diag_output_bytes_max]u8 = undefined;
    const text = diag_mod.render(&diagnostic, .verbose, false, &buffer);
    std.Io.File.stderr().writeStreamingAll(io, text) catch {}; // Nowhere else to say it.
}

fn warn_discarded(io: std.Io, deleted: u64, id: seal.KeyId, aside: ?[]const u8) void {
    var diag: Diag = undefined;
    diag.reset();
    render_warning(&diag, deleted, id, aside);
    warn(io, &diag);
}

fn warn_nothing(io: std.Io) void {
    var diag: Diag = undefined;
    diag.reset();
    render_nothing(&diag);
    warn(io, &diag);
}

/// The warning's diagnostic, apart so that tests can render it. The id of the new key is
/// printed, never the key; `aside` is the old key file's new name, if there was one.
pub fn render_warning(diag: *Diag, deleted: u64, id: seal.KeyId, aside: ?[]const u8) void {
    assert(diag.code == null);
    diag.raise(.W0808);
    diag.cause("--discard-sealed deleted {d} sealed record(s) and ACME order(s)", .{deleted});
    if (aside) |name| {
        diag.cause("the old key file was renamed {s}, beside the new one (docs/sealing.md " ++
            "says how to restore it)", .{name});
    }
    diag.cause("a new sealing key was made, with id {s}", .{&id});
    diag.cause("every public host is ordered again, which counts against Let's Encrypt's " ++
        "limits: 50 certificates per registered domain per week and 5 duplicates per " ++
        "week", .{});
    diag.fix(.{
        .sentence = "back up the new key file; start without --discard-sealed from now on",
    });
}

/// ZC-W0808 when the key opens every sealed record: the flag did nothing.
pub fn render_nothing(diag: *Diag) void {
    assert(diag.code == null);
    diag.raise(.W0808);
    diag.cause("--discard-sealed: the sealing key opens every sealed record, so nothing was " ++
        "deleted and the key was kept", .{});
    diag.fix(.{ .sentence = "nothing to discard; remove --discard-sealed" });
}

// ---- Tests ---------------------------------------------------------------------------------

const testing = std.testing;
const clock_mod = @import("clock.zig");
const codes = @import("diag/codes.zig");
const redaction = @import("testing/redaction.zig");
const store_memory = @import("store_memory.zig");

const TestRig = struct {
    tmp: std.testing.TmpDir,
    path_buffer: [std.fs.max_path_bytes]u8 = undefined,
    path_length: u32 = 0,
    manual: clock_mod.ManualClock = .{ .ms = 1_000 },
    memory: store_memory.MemoryStore = undefined,
    diag: Diag = undefined,
    nonces: u64 = 0,

    /// In place: the memory store keeps a pointer to the clock.
    fn init(rig: *TestRig, io: std.Io) !void {
        rig.* = .{ .tmp = std.testing.tmpDir(.{}) };
        // A state directory is 0700 whatever the runner's umask (as in server_ca's tests).
        try rig.tmp.dir.setFilePermissions(io, ".", .fromMode(0o700), .{});
        rig.path_length = @intCast(try rig.tmp.dir.realPath(io, &rig.path_buffer));
        rig.memory.init(testing.allocator, rig.manual.clock());
        rig.diag.reset();
    }

    fn deinit(rig: *TestRig) void {
        rig.memory.deinit();
        rig.tmp.cleanup();
    }

    fn path(rig: *const TestRig) []const u8 {
        return rig.path_buffer[0..rig.path_length];
    }

    fn options(discard_sealed: bool) Options {
        return .{ .key_name = "seal.key", .discard = discard_sealed, .quiet = true };
    }

    /// `open`, then the planned discard if there is one, as the server does.
    fn open_key(rig: *TestRig, discard_sealed: bool) Error!seal.Key {
        const s = rig.memory.interface();
        const o = options(discard_sealed);
        return switch (try open(testing.allocator, testing.io, s, rig.path(), o, &rig.diag)) {
            .ready => |key| key,
            .discard => discard(testing.allocator, testing.io, s, rig.path(), o, &rig.diag),
        };
    }

    /// `open` alone.
    fn plan(rig: *TestRig, discard_sealed: bool) Error!Opened {
        const s = rig.memory.interface();
        const o = options(discard_sealed);
        return open(testing.allocator, testing.io, s, rig.path(), o, &rig.diag);
    }

    /// The names in the state directory that start with "seal.key.discarded-".
    fn asides(rig: *TestRig, first: *[aside_name_bytes_max]u8) !usize {
        var dir = try rig.tmp.dir.openDir(testing.io, ".", .{ .iterate = true });
        defer dir.close(testing.io);
        var iterator = dir.iterate();
        var found: usize = 0;
        while (try iterator.next(testing.io)) |entry| {
            if (!std.mem.startsWith(u8, entry.name, "seal.key.discarded-")) continue;
            if (found == 0) @memcpy(first[0..entry.name.len], entry.name);
            found += 1;
        }
        return found;
    }

    fn put(rig: *TestRig, key: []const u8, value: []const u8) !void {
        const ops = [_]store.Op{.{ .put = .{ .key = key, .value = value } }};
        const result = try rig.memory.interface().txn(.{ .on_success = &ops }, &rig.diag);
        try testing.expect(result.succeeded);
    }

    /// A record as later slices write one: clear members and the sealed key.
    fn put_sealed(rig: *TestRig, key: *const seal.Key, path_: []const u8, plain: []const u8) !void {
        // Distinct per record; a test needs no randomness here.
        rig.nonces += 1;
        var nonce: [seal.nonce_bytes]u8 = @splat(0);
        std.mem.writeInt(u64, nonce[0..8], rig.nonces, .little);
        var envelope: [seal.envelope_bytes_max]u8 = undefined;
        const sealed = seal.seal(key, path_, plain, nonce, &envelope);
        var value: [seal.envelope_bytes_max + 64]u8 = undefined;
        const text = try std.fmt.bufPrint(&value, "{{\"v\":1,\"key\":\"{s}\",\"state\":\"ok\"}}", .{
            sealed,
        });
        try rig.put(path_, text);
    }

    fn count(rig: *TestRig, prefix: []const u8) !usize {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const page = try rig.memory.interface().list(arena.allocator(), .{
            .prefix = prefix,
            .limit = constants.store_list_limit_max,
        }, &rig.diag);
        return page.kvs.len;
    }

    /// The rendered diagnostic, for checking what it names and that it holds no key.
    fn rendered(rig: *TestRig, buffer: *[constants.diag_output_bytes_max]u8) []const u8 {
        var diagnostic: diag_mod.Diagnostic = undefined;
        diag_mod.to_diagnostic(&diagnostic, &rig.diag);
        return diag_mod.render(&diagnostic, .text, false, buffer);
    }

    fn key_file(rig: *TestRig) !?[32]u8 {
        return files.read_seed(testing.io, rig.tmp.dir, "tmp", "seal.key", &rig.diag);
    }
};

const plain_key = "-----not a real P-256 key, but planted for the redaction checks-----";

test "a C4 store is upgraded: the key is made 0600 and kept, and nothing is refused" {
    // Goal: "no key and no sealed records" just works, and the key outlives a restart. Method: a
    // store with C4 records and no sealed ones; open twice and compare.
    var rig: TestRig = undefined;
    try rig.init(testing.io);
    defer rig.deinit();
    try rig.put("/services/hello", "{\"v\":3,\"name\":\"hello\"}");
    var first = try rig.open_key(false);
    defer first.wipe();
    var second = try rig.open_key(false);
    defer second.wipe();
    try testing.expectEqualSlices(u8, &first.bytes, &second.bytes);
    try testing.expectEqualSlices(u8, &first.bytes, &(try rig.key_file()).?);
    const file = try rig.tmp.dir.openFile(testing.io, "seal.key", .{});
    defer file.close(testing.io);
    const stat = try file.stat(testing.io);
    try testing.expectEqual(@as(std.posix.mode_t, 0o600), stat.permissions.toMode() & 0o777);
    try testing.expectEqual(@as(usize, 1), try rig.count("/services/"));
}

test "sealed records with the key removed, or another key, are ZC-E0824 naming the key id" {
    // Goal: the server never starts over records it cannot open. Method: seal a record, then
    // remove the key file, then put another key in its place; each start is refused with the
    // key file and the expected key id named, and no key in the text.
    var rig: TestRig = undefined;
    try rig.init(testing.io);
    defer rig.deinit();
    var key = try rig.open_key(false);
    defer key.wipe();
    try rig.put_sealed(&key, "/edge-certs/a.example", plain_key);
    try rig.put_sealed(&key, "/acme-account/0123abcd", plain_key);
    var again = try rig.open_key(false);
    again.wipe();

    try rig.tmp.dir.deleteFile(testing.io, "seal.key");
    try testing.expectError(error.Failed, rig.open_key(false));
    try testing.expectEqual(codes.Code.E0824, rig.diag.code.?);
    var buffer: [constants.diag_output_bytes_max]u8 = undefined;
    var text = rig.rendered(&buffer);
    const id = key.id();
    try testing.expect(std.mem.indexOf(u8, text, &id) != null);
    try testing.expect(std.mem.indexOf(u8, text, "seal.key is missing") != null);
    try testing.expect(std.mem.indexOf(u8, text, "--discard-sealed") != null);
    try expect_redacted_all(&rig.diag, &key.bytes, plain_key);
    // Nothing was made in its place: a refused start writes no key.
    try testing.expect((try rig.key_file()) == null);

    rig.diag.reset();
    var other: [32]u8 = @splat(0x42);
    try files.write_seed(testing.io, rig.tmp.dir, "tmp", "seal.key", other, &rig.diag);
    try testing.expectError(error.Failed, rig.open_key(false));
    try testing.expectEqual(codes.Code.E0824, rig.diag.code.?);
    text = rig.rendered(&buffer);
    try testing.expect(std.mem.indexOf(u8, text, &id) != null);
    try testing.expect(std.mem.indexOf(u8, text, &files_id(other)) != null);
    try expect_redacted_all(&rig.diag, &key.bytes, plain_key);
    try expect_redacted_all(&rig.diag, &other, plain_key);
    rig.diag.reset();
    try testing.expectEqual(@as(usize, 1), try rig.count("/edge-certs/"));
}

test "a moved record and a tampered record are refused at start" {
    // Goal: the store key is bound into each record. Method: copy a sealed value to another
    // host's key; then flip one byte of a value's ciphertext. Each start is ZC-E0824.
    var rig: TestRig = undefined;
    try rig.init(testing.io);
    defer rig.deinit();
    var key = try rig.open_key(false);
    defer key.wipe();
    try rig.put_sealed(&key, "/edge-certs/a.example", plain_key);
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const kv = (try rig.memory.interface().get(
        arena.allocator(),
        "/edge-certs/a.example",
        null,
        &rig.diag,
    )).kv.?;
    try rig.put("/edge-certs/b.example", kv.value);
    try testing.expectError(error.Failed, rig.open_key(false));
    try testing.expectEqual(codes.Code.E0824, rig.diag.code.?);
    var buffer: [constants.diag_output_bytes_max]u8 = undefined;
    try testing.expect(std.mem.indexOf(u8, rig.rendered(&buffer), &key.id()) != null);
    // The record is named in the full cause chain (--verbose).
    try testing.expect(cause_holds(&rig.diag, "/edge-certs/b.example"));

    rig.diag.reset();
    try rig.put("/edge-certs/b.example", "{\"v\":1,\"state\":\"pending\"}");
    var ok = try rig.open_key(false);
    ok.wipe();
    const tampered = try arena.allocator().dupe(u8, kv.value);
    const envelope_at = std.mem.indexOf(u8, tampered, seal.magic).?;
    const at = envelope_at + seal.header_bytes + 10;
    tampered[at] = if (tampered[at] == 'A') 'B' else 'A';
    try rig.put("/edge-certs/a.example", tampered);
    try testing.expectError(error.Failed, rig.open_key(false));
    try testing.expectEqual(codes.Code.E0824, rig.diag.code.?);
}

test "--discard-sealed deletes the sealed records and orders, makes a new key and warns" {
    // Goal: the way out of ZC-E0824. Method: seal records under each discarded prefix (more than
    // one transaction's worth), lose the key, start with the flag: they are gone, other records
    // stay, a new key is written, and the next plain start opens with it. W0808's text names the
    // new key's id and the limits, never the key.
    var rig: TestRig = undefined;
    try rig.init(testing.io);
    defer rig.deinit();
    var old = try rig.open_key(false);
    defer old.wipe();
    var name: [64]u8 = undefined;
    for (0..constants.store_txn_ops_max + 3) |index| {
        const host = try std.fmt.bufPrint(&name, "/edge-certs/h{d}.example", .{index});
        try rig.put_sealed(&old, host, plain_key);
    }
    try rig.put_sealed(&old, "/acme-account/0123abcd", plain_key);
    try rig.put("/acme-orders/h1.example", "{\"v\":1}");
    try rig.put("/services/hello", "{\"v\":3}");
    try rig.tmp.dir.deleteFile(testing.io, "seal.key");
    try testing.expectError(error.Failed, rig.open_key(false));
    rig.diag.reset();

    var fresh = try rig.open_key(true);
    defer fresh.wipe();
    try testing.expect(!std.mem.eql(u8, &old.bytes, &fresh.bytes));
    try testing.expectEqualSlices(u8, &fresh.bytes, &(try rig.key_file()).?);
    for (seal.discarded_prefixes) |prefix| {
        try testing.expectEqual(@as(usize, 0), try rig.count(prefix));
    }
    try testing.expectEqual(@as(usize, 1), try rig.count("/services/"));

    var next = try rig.open_key(false);
    defer next.wipe();
    try testing.expectEqualSlices(u8, &fresh.bytes, &next.bytes);
    // A sealed record written with the new key opens at the next start. (The new order itself
    // is the ACME shell's, slice 3b: docs/decisions/2026-11-18-c5-seal-discard-order.md.)
    try rig.put_sealed(&fresh, "/edge-certs/h1.example", plain_key);
    var after = try rig.open_key(false);
    after.wipe();

    var warning: Diag = undefined;
    warning.reset();
    render_warning(&warning, 21, fresh.id(), "seal.key.discarded-1700000000");
    try testing.expectEqual(codes.Code.W0808, warning.code.?);
    var diagnostic: diag_mod.Diagnostic = undefined;
    diag_mod.to_diagnostic(&diagnostic, &warning);
    var buffer: [constants.diag_output_bytes_max]u8 = undefined;
    const text = diag_mod.render(&diagnostic, .verbose, false, &buffer);
    try testing.expect(std.mem.indexOf(u8, text, &fresh.id()) != null);
    try testing.expect(std.mem.indexOf(u8, text, "50 certificates") != null);
    try testing.expect(std.mem.indexOf(u8, text, "seal.key.discarded-1700000000") != null);
    try redaction.expect_absent(text, &fresh.bytes, "W0808");
}

test "--discard-sealed with a key that opens every record deletes nothing and keeps the key" {
    // Goal: the flag acts only when the start check fails (ruling 1). Method: seal records with
    // the key in place and start with the flag: every record and the key file are as they were,
    // no file is set aside, and W0808's other text says to remove the flag.
    var rig: TestRig = undefined;
    try rig.init(testing.io);
    defer rig.deinit();
    var key = try rig.open_key(false);
    defer key.wipe();
    try rig.put_sealed(&key, "/edge-certs/a.example", plain_key);
    try rig.put("/acme-orders/a.example", "{\"v\":1}");
    var again = try rig.open_key(true);
    defer again.wipe();
    try testing.expectEqualSlices(u8, &key.bytes, &again.bytes);
    try testing.expectEqualSlices(u8, &key.bytes, &(try rig.key_file()).?);
    try testing.expectEqual(@as(usize, 1), try rig.count("/edge-certs/"));
    try testing.expectEqual(@as(usize, 1), try rig.count("/acme-orders/"));
    var name: [aside_name_bytes_max]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try rig.asides(&name));

    var warning: Diag = undefined;
    warning.reset();
    render_nothing(&warning);
    try testing.expectEqual(codes.Code.W0808, warning.code.?);
    var diagnostic: diag_mod.Diagnostic = undefined;
    diag_mod.to_diagnostic(&diagnostic, &warning);
    var buffer: [constants.diag_output_bytes_max]u8 = undefined;
    const text = diag_mod.render(&diagnostic, .text, false, &buffer);
    try testing.expect(std.mem.indexOf(u8, text, "nothing to discard; remove --discard-sealed") !=
        null);
}

test "--discard-sealed renames the old key aside, 0600, and a planned discard deletes nothing" {
    // Goal: the old key is never overwritten, and a start refused after `open` (CA, listeners)
    // deletes nothing (ruling 1). Method: another key in place of the sealing key; `open` with
    // the flag plans the discard and the records are all still there; then the discard runs and
    // the old key is found, unchanged and 0600, under its aside name.
    var rig: TestRig = undefined;
    try rig.init(testing.io);
    defer rig.deinit();
    var key = try rig.open_key(false);
    defer key.wipe();
    try rig.put_sealed(&key, "/edge-certs/a.example", plain_key);
    try rig.put("/acme-orders/a.example", "{\"v\":1}");
    rig.diag.reset();
    const other: [32]u8 = @splat(0x42);
    try rig.tmp.dir.deleteFile(testing.io, "seal.key");
    try files.write_seed(testing.io, rig.tmp.dir, "tmp", "seal.key", other, &rig.diag);

    try testing.expect(try rig.plan(true) == .discard);
    try testing.expectEqual(@as(usize, 1), try rig.count("/edge-certs/"));
    try testing.expectEqual(@as(usize, 1), try rig.count("/acme-orders/"));
    try testing.expectEqualSlices(u8, &other, &(try rig.key_file()).?);

    var fresh = try rig.open_key(true);
    defer fresh.wipe();
    try testing.expectEqual(@as(usize, 0), try rig.count("/edge-certs/"));
    try testing.expectEqual(@as(usize, 0), try rig.count("/acme-orders/"));
    var name: [aside_name_bytes_max]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), try rig.asides(&name));
    const aside = name[0 .. "seal.key.discarded-".len + 10];
    const kept = (try files.read_seed(testing.io, rig.tmp.dir, "tmp", aside, &rig.diag)).?;
    try testing.expectEqualSlices(u8, &other, &kept);
    try testing.expect(!std.mem.eql(u8, &other, &fresh.bytes));
}

test "a key written by another start meanwhile is read, never replaced" {
    // Goal: no-replace creation (ruling 4). Method: write the key file between the check and
    // `make`, as a racing start would: `make` returns that key and leaves the file as it was.
    var rig: TestRig = undefined;
    try rig.init(testing.io);
    defer rig.deinit();
    const racer: [32]u8 = @splat(0x17);
    try files.write_seed(testing.io, rig.tmp.dir, "tmp", "seal.key", racer, &rig.diag);
    var key = try make(testing.io, rig.path(), "seal.key", &rig.diag);
    defer key.wipe();
    try testing.expectEqualSlices(u8, &racer, &key.bytes);
    try testing.expectEqualSlices(u8, &racer, &(try rig.key_file()).?);
}

test "only the sealed member is opened: clear members shaped like envelopes start" {
    // Goal: review of PR #8 (MUST): a clear host `zcseal1.<16 hex>.example.com` refused every
    // start with ZC-E0824, and `--discard-sealed` could not end it. Method: records whose clear
    // members are such hosts (one ending at the quote), next to a good sealed member or with
    // none, start, again and again; a record naming the sealed member twice, or whose sealed
    // member does not open, or that is not JSON, is refused.
    var rig: TestRig = undefined;
    try rig.init(testing.io);
    defer rig.deinit();
    var key = try rig.open_key(false);
    defer key.wipe();
    const other: seal.Key = .{ .bytes = @splat(0x42) };
    var first: [seal.envelope_bytes_max]u8 = undefined;
    var second: [seal.envelope_bytes_max]u8 = undefined;
    const nonce: [seal.nonce_bytes]u8 = @splat(7);
    const host = "/edge-certs/zcseal1.0123456789abcdef.example.com";
    const a = seal.seal(&key, host, "one", nonce, &first);
    const b = seal.seal(&other, host, "two", nonce, &second);
    var value: [2 * seal.envelope_bytes_max + 128]u8 = undefined;
    const clear = "\"host\":\"zcseal1.0123456789abcdef.example.com\"," ++
        "\"alias\":\"zcseal1.0123456789abcdef.dev\"";
    try rig.put(host, try std.fmt.bufPrint(&value, "{{" ++ clear ++ ",\"key\":\"{s}\"}}", .{a}));
    try rig.put("/edge-certs/pending.example", "{" ++ clear ++ ",\"state\":\"pending\"}");
    for (0..3) |_| {
        var ok = try rig.open_key(false);
        defer ok.wipe();
        try testing.expectEqualSlices(u8, &key.bytes, &ok.bytes);
    }

    const refused = [_][]const u8{
        "{{\"key\":\"{s}\",\"key\":\"{s}\"}}",
        "{{\"key\":\"{s}{s}\"}}",
    };
    inline for (refused) |format| {
        rig.diag.reset();
        try rig.put(host, try std.fmt.bufPrint(&value, format, .{ a, b }));
        try testing.expectError(error.Failed, rig.open_key(false));
        try testing.expectEqual(codes.Code.E0824, rig.diag.code.?);
        try testing.expect(cause_holds(&rig.diag, host));
    }
    rig.diag.reset();
    try rig.put(host, try std.fmt.bufPrint(&value, "{{\"key\":\"{s}\"}}", .{b}));
    try testing.expectError(error.Failed, rig.open_key(false));
    try testing.expect(cause_holds(&rig.diag, "sealed with another key"));
    rig.diag.reset();
    try rig.put(host, "not json");
    try testing.expectError(error.Failed, rig.open_key(false));
    try testing.expect(cause_holds(&rig.diag, "cannot be read under any key: it is not one JSON"));
    rig.diag.reset();
}

test "a record no key can open is named, with the fix to delete it, not the key-id message" {
    // Goal: review of PR #8 (SHOULD): a damaged record under the right key was told "restore
    // the key file", a key that is not wrong. Method: with the right key file in place, each
    // damaged record (not JSON, an empty sealed member, a key cut short under the right key id,
    // another version's header) refuses the start; the default output names the record and
    // the delete fix, and never a key id or the restore fix. A `"key":null` entry starts. A
    // record sealed with another key still gets the key-id message.
    var rig: TestRig = undefined;
    try rig.init(testing.io);
    defer rig.deinit();
    var key = try rig.open_key(false);
    defer key.wipe();
    try rig.put_sealed(&key, "/edge-certs/a.example", plain_key);
    try rig.put("/edge-certs/pending.example", "{\"state\":\"pending\",\"key\":null}");
    var ok = try rig.open_key(false);
    ok.wipe();

    const id = key.id();
    const short = "{\"key\":\"zcseal1." ++ id ++ ".AAAA\"}";
    const damaged = [_][]const u8{
        "not json",
        "{\"state\":\"pending\",\"key\":\"\"}",
        short,
        "{\"key\":\"zcseal2." ++ id ++ ".AAAA\"}",
    };
    const host = "/edge-certs/b.example";
    for (damaged) |value| {
        rig.diag.reset();
        try rig.put(host, value);
        try testing.expectError(error.Failed, rig.open_key(false));
        try testing.expectEqual(codes.Code.E0824, rig.diag.code.?);
        try testing.expect(rendered_holds(&rig.diag, .text, host ++ " cannot be read under any"));
        try testing.expect(rendered_holds(&rig.diag, .text, "delete that record from the store"));
        try testing.expect(rendered_holds(&rig.diag, .text, "--discard-sealed"));
        try testing.expect(!rendered_holds(&rig.diag, .verbose, "key id"));
        try testing.expect(!rendered_holds(&rig.diag, .verbose, "restore the key file"));
    }

    rig.diag.reset();
    try rig.put(host, "{}");
    const other: seal.Key = .{ .bytes = @splat(0x42) };
    try rig.put_sealed(&other, host, plain_key);
    try testing.expectError(error.Failed, rig.open_key(false));
    try testing.expect(rendered_holds(&rig.diag, .text, "restore the key file"));
    try testing.expect(rendered_holds(&rig.diag, .text, "holds key id " ++ id));
    try testing.expect(!rendered_holds(&rig.diag, .verbose, "delete that record"));
    rig.diag.reset();
}

test "the damaged-record refusal's default output, pinned" {
    // Goal: the wording of ZC-E0824 for a record no key opens (DIAGNOSTICS.md: golden tests):
    // the record and the delete fix, no key id, no restore fix.
    var diag: Diag = undefined;
    diag.reset();
    raise_refused(&diag, .{
        .state_dir = "/var/lib/zcube-server",
        .key_name = "seal-0123456789abcdef.key",
        .records = 3,
        .record = "/edge-certs/shop.example.com",
        .why = "it is not one JSON object",
        .expected = null,
        .found = "5a1d0c4e9b2f7a68".*,
        .damaged = true,
    });
    var diagnostic: diag_mod.Diagnostic = undefined;
    diag_mod.to_diagnostic(&diagnostic, &diag);
    var buffer: [constants.diag_output_bytes_max]u8 = undefined;
    const text = diag_mod.render(&diagnostic, .text, false, &buffer);
    try testing.expectEqualStrings(damaged_golden, text);
}

/// Captured from this test's own output (a real render), beside the CLI goldens.
const damaged_golden = @embedFile("testdata/cli/E0824.damaged.txt");

test "the scan's bound is one cause naming the bound, the count and a remedy without the flag" {
    var diag: Diag = undefined;
    diag.reset();
    raise_too_many(&diag, "/edge-certs/", constants.seal_scan_pages_max);
    var diagnostic: diag_mod.Diagnostic = undefined;
    diag_mod.to_diagnostic(&diagnostic, &diag);
    var buffer: [constants.diag_output_bytes_max]u8 = undefined;
    const text = diag_mod.render(&diagnostic, .text, false, &buffer);
    try testing.expect(std.mem.indexOf(u8, text, "more than 2048000 records under /edge-certs/") !=
        null);
    try testing.expect(std.mem.indexOf(u8, text, "--discard-sealed") == null);
    diag.reset();
    raise_unfinished(&diag, "/edge-certs/", rounds_max(constants.seal_scan_pages_max));
    diag_mod.to_diagnostic(&diagnostic, &diag);
    const unfinished = diag_mod.render(&diagnostic, .text, false, &buffer);
    try testing.expectEqual(codes.Code.E0824, diag.code.?);
    try testing.expect(std.mem.indexOf(u8, unfinished, "start once with") == null);
    try testing.expect(std.mem.indexOf(u8, unfinished, "another writer") != null);
}

test "the sealing key is named after the CA key" {
    var buffer: [key_name_bytes_max]u8 = undefined;
    try testing.expectEqualStrings("seal.key", key_name_for("ca.key", &buffer));
    try testing.expectEqualStrings(
        "seal-0123456789abcdef.key",
        key_name_for("ca-0123456789abcdef.key", &buffer),
    );
}

fn files_id(bytes: [32]u8) seal.KeyId {
    const key: seal.Key = .{ .bytes = bytes };
    return key.id();
}

/// The diagnostic in each mode (text, --verbose, JSON) holds neither the key nor the plaintext.
fn expect_redacted_all(diag: *Diag, key: []const u8, plain: []const u8) !void {
    var diagnostic: diag_mod.Diagnostic = undefined;
    diag_mod.to_diagnostic(&diagnostic, diag);
    var buffer: [constants.diag_output_bytes_max]u8 = undefined;
    inline for (.{ .text, .verbose, .json }) |mode| {
        const text = diag_mod.render(&diagnostic, mode, false, &buffer);
        try redaction.expect_absent(text, key, @tagName(mode));
        try redaction.expect_absent(text, plain, @tagName(mode));
    }
}

/// Whether the full cause chain (--verbose) holds `needle`; see `rendered_holds`.
fn cause_holds(diag: *Diag, needle: []const u8) bool {
    return rendered_holds(diag, .verbose, needle);
}

/// Whether the diagnostic rendered in `mode` holds `needle`, the lines it wraps joined again:
/// every run of white space is read as one space.
fn rendered_holds(diag: *Diag, mode: @import("zigbox").render.Mode, needle: []const u8) bool {
    var diagnostic: diag_mod.Diagnostic = undefined;
    diag_mod.to_diagnostic(&diagnostic, diag);
    var buffer: [constants.diag_output_bytes_max]u8 = undefined;
    const text = diag_mod.render(&diagnostic, mode, false, &buffer);
    var joined: [constants.diag_output_bytes_max]u8 = undefined;
    var length: usize = 0;
    var spaced = false;
    for (text) |byte| {
        if (std.ascii.isWhitespace(byte)) {
            spaced = true;
            continue;
        }
        if (spaced and length > 0) {
            joined[length] = ' ';
            length += 1;
        }
        spaced = false;
        joined[length] = byte;
        length += 1;
    }
    return std.mem.indexOf(u8, joined[0..length], needle) != null;
}

/// The memory store with a fault: every compare fails, or the transactions after the first
/// `txns_left` fail outright (ZC-E0213, a dropped connection). `open` and `discard` reach only
/// `list` and `txn`; the rest are never called.
const FaultyStore = struct {
    inner: store.Store,
    compares_fail: bool = false,
    /// The next this many compared transactions fail, then they pass.
    compares_fail_next: u32 = 0,
    txns_left: ?u32 = null,

    const vtable: store.Store.VTable = .{
        .status = Unused.status,
        .get = Unused.get,
        .list = list,
        .txn = txn,
        .watch = Unused.watch,
        .lease_grant = Unused.lease_grant,
        .lease_keepalive = Unused.lease_keepalive,
        .lease_revoke = Unused.lease_revoke,
        .lease_list = Unused.lease_list,
        .expire_leases = Unused.expire_leases,
        .compact = Unused.compact,
        .hash_at = Unused.hash_at,
    };

    /// Neither `open` nor `discard` calls these.
    const Unused = struct {
        fn status(_: *anyopaque, _: *Diag) store.Error!store.Status {
            unreachable;
        }
        fn get(
            _: *anyopaque,
            _: Allocator,
            _: []const u8,
            _: ?store.Revision,
            _: *Diag,
        ) store.Error!store.GetResult {
            unreachable;
        }
        fn watch(_: *anyopaque, _: store.WatchOptions, _: *Diag) store.Error!store.Watch {
            unreachable;
        }
        fn lease_grant(_: *anyopaque, _: u32, _: *Diag) store.Error!store.Lease {
            unreachable;
        }
        fn lease_keepalive(_: *anyopaque, _: store.LeaseId, _: *Diag) store.Error!store.Lease {
            unreachable;
        }
        fn lease_revoke(_: *anyopaque, _: store.LeaseId, _: *Diag) store.Error!store.Revision {
            unreachable;
        }
        fn lease_list(_: *anyopaque, _: Allocator, _: *Diag) store.Error![]const store.LeaseInfo {
            unreachable;
        }
        fn expire_leases(_: *anyopaque, _: *Diag) store.Error!u32 {
            unreachable;
        }
        fn compact(_: *anyopaque, _: store.Revision, _: *Diag) store.Error!void {
            unreachable;
        }
        fn hash_at(_: *anyopaque, _: store.Revision, _: *Diag) store.Error!store.Hash {
            unreachable;
        }
    };

    fn interface(faulty: *FaultyStore) store.Store {
        return .{ .context = faulty, .vtable = &vtable };
    }

    fn from(context: *anyopaque) *FaultyStore {
        return @ptrCast(@alignCast(context));
    }

    fn list(
        context: *anyopaque,
        arena: Allocator,
        options_: store.ListOptions,
        diag: *Diag,
    ) store.Error!store.ListResult {
        const inner = from(context).inner;
        return inner.vtable.list(inner.context, arena, options_, diag);
    }

    fn txn(
        context: *anyopaque,
        request: store.TxnRequest,
        diag: *Diag,
    ) store.Error!store.TxnResult {
        const faulty = from(context);
        if (faulty.txns_left) |*left| {
            if (left.* == 0) {
                diag.raise(.E0213);
                diag.cause("the test cut the store's connection", .{});
                return error.BackendFailed;
            }
            left.* -= 1;
        }
        const inner = faulty.inner;
        const fail_next = faulty.compares_fail_next > 0;
        if (!(faulty.compares_fail or fail_next) or request.compares.len == 0) {
            return inner.vtable.txn(inner.context, request, diag);
        }
        if (fail_next) faulty.compares_fail_next -= 1;
        const instead: store.TxnRequest = .{ .on_success = request.on_failure };
        var failed = try inner.vtable.txn(inner.context, instead, diag);
        failed.succeeded = false;
        failed.hash = null;
        return failed;
    }
};

/// A rig whose key file holds another key than the one `sealed` records were sealed with, so
/// that `open` plans a discard. Returns the other key's bytes.
fn plant_unopenable(rig: *TestRig, edge: u32, accounts: u32, orders: u32) ![32]u8 {
    var old = try rig.open_key(false);
    defer old.wipe();
    var name: [64]u8 = undefined;
    for (0..edge) |index| {
        const host = try std.fmt.bufPrint(&name, "/edge-certs/h{d}.example", .{index});
        try rig.put_sealed(&old, host, plain_key);
    }
    for (0..accounts) |index| {
        const account = try std.fmt.bufPrint(&name, "/acme-account/a{d}", .{index});
        try rig.put_sealed(&old, account, plain_key);
    }
    for (0..orders) |index| {
        const order = try std.fmt.bufPrint(&name, "/acme-orders/h{d}.example", .{index});
        try rig.put(order, "{\"v\":1}");
    }
    const other: [32]u8 = @splat(0x5a);
    try files.write_seed(testing.io, rig.tmp.dir, rig.path(), "seal.key", other, &rig.diag);
    return other;
}

/// `open` and then `discard` with the flag, over `s`, scanning at most `pages_max` pages.
fn discard_over(rig: *TestRig, s: store.Store, pages_max: u32) !seal.Key {
    var o = TestRig.options(true);
    o.scan_pages_max = pages_max;
    const planned = try open(testing.allocator, testing.io, s, rig.path(), o, &rig.diag);
    try testing.expect(planned == .discard);
    return discard(testing.allocator, testing.io, s, rig.path(), o, &rig.diag);
}

test "a discard whose compares keep failing is ZC-E0824 unfinished, and keeps the old key" {
    // Goal: review of PR #8 (SHOULD): `delete_all`'s bound was never reached. Method: every
    // compare fails, as if another writer kept rewriting the records; one page bounds the
    // rounds. The discard stops at the bound naming it, deletes nothing, renames no key file
    // and writes no new one.
    var rig: TestRig = undefined;
    try rig.init(testing.io);
    defer rig.deinit();
    const other = try plant_unopenable(&rig, 3, 1, 1);
    var faulty: FaultyStore = .{ .inner = rig.memory.interface(), .compares_fail = true };
    try testing.expectError(error.Failed, discard_over(&rig, faulty.interface(), 1));
    try testing.expectEqual(codes.Code.E0824, rig.diag.code.?);
    var rounds_text: [64]u8 = undefined;
    const rounds = try std.fmt.bufPrint(&rounds_text, "after {d}", .{rounds_max(1)});
    try testing.expect(cause_holds(&rig.diag, "could not empty /edge-certs/"));
    try testing.expect(cause_holds(&rig.diag, rounds));
    rig.diag.reset();
    try testing.expectEqual(@as(usize, 3), try rig.count("/edge-certs/"));
    try testing.expectEqualSlices(u8, &other, &(try rig.key_file()).?);
    var aside: [aside_name_bytes_max]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try rig.asides(&aside));
}

test "a discard with every record the scan admits and a failed compare per page finishes" {
    // Goal: review of PR #8 (NIT): `rounds_max` had no round left to list the emptied prefix.
    // Method: one page bounds the scan, `records_max(1)` records under /edge-certs/ and
    // `pages_max` (1) failed compares: every round is used, the last one finds the prefix
    // empty, and the discard finishes rather than reporting itself unfinished.
    var rig: TestRig = undefined;
    try rig.init(testing.io);
    defer rig.deinit();
    const records: u32 = @intCast(records_max(1));
    _ = try plant_unopenable(&rig, records, 0, 0);
    var faulty: FaultyStore = .{ .inner = rig.memory.interface(), .compares_fail_next = 1 };
    var key = try discard_over(&rig, faulty.interface(), 1);
    key.wipe();
    try testing.expectEqual(@as(u32, 0), faulty.compares_fail_next);
    try testing.expectEqual(@as(usize, 0), try rig.count("/edge-certs/"));
    const deletes = std.math.divCeil(u64, records, constants.store_txn_ops_max) catch
        unreachable; // The divisor is a positive constant.
    try testing.expectEqual(rounds_max(1), deletes + 1 + 1);
}

test "a discard cut after one prefix leaves the old key; the next start with the flag ends it" {
    // Goal: review of PR #8 (SHOULD): a discard that fails part way is never worse off. Method:
    // the store drops its connection after the first delete, which empties /edge-certs/; the
    // account and the order are left, and so is the old key file. A start without the flag is
    // still refused (the account does not open); one with it, on a healthy store, finishes.
    var rig: TestRig = undefined;
    try rig.init(testing.io);
    defer rig.deinit();
    const other = try plant_unopenable(&rig, 3, 2, 1);
    var faulty: FaultyStore = .{ .inner = rig.memory.interface(), .txns_left = 1 };
    try testing.expectError(error.Failed, discard_over(&rig, faulty.interface(), 1));
    try testing.expectEqual(codes.Code.E0213, rig.diag.code.?);
    rig.diag.reset();
    try testing.expectEqual(@as(usize, 0), try rig.count("/edge-certs/"));
    try testing.expectEqual(@as(usize, 2), try rig.count("/acme-account/"));
    try testing.expectEqual(@as(usize, 1), try rig.count("/acme-orders/"));
    try testing.expectEqualSlices(u8, &other, &(try rig.key_file()).?);

    try testing.expectError(error.Failed, rig.open_key(false));
    try testing.expectEqual(codes.Code.E0824, rig.diag.code.?);
    try testing.expect(cause_holds(&rig.diag, "/acme-account/a"));
    rig.diag.reset();
    var fresh = try rig.open_key(true);
    defer fresh.wipe();
    for (seal.discarded_prefixes) |prefix| {
        try testing.expectEqual(@as(usize, 0), try rig.count(prefix));
    }
    try testing.expect(!std.mem.eql(u8, &other, &fresh.bytes));
    try testing.expectEqualSlices(u8, &fresh.bytes, &(try rig.key_file()).?);
    var aside: [aside_name_bytes_max]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), try rig.asides(&aside));
}

test "more records than the scan's pages hold refuse the start, never half-checked" {
    // Goal: review of PR #8 (SHOULD): `walk`'s bound was never reached. Method: one page of
    // `store_list_limit_max` clear records and one more, scanned with a bound of one page: the
    // start is ZC-E0824 naming the bound, and no key is written.
    var rig: TestRig = undefined;
    try rig.init(testing.io);
    defer rig.deinit();
    var name: [64]u8 = undefined;
    for (0..constants.store_list_limit_max + 1) |index| {
        const host = try std.fmt.bufPrint(&name, "/edge-certs/h{d}.example", .{index});
        try rig.put(host, "{\"v\":1,\"state\":\"pending\"}");
    }
    var o = TestRig.options(false);
    o.scan_pages_max = 1;
    const s = rig.memory.interface();
    const refused = open(testing.allocator, testing.io, s, rig.path(), o, &rig.diag);
    try testing.expectError(error.Failed, refused);
    try testing.expectEqual(codes.Code.E0824, rig.diag.code.?);
    var bound: [64]u8 = undefined;
    const more = try std.fmt.bufPrint(&bound, "more than {d} records under /edge-certs/", .{
        constants.store_list_limit_max,
    });
    try testing.expect(cause_holds(&rig.diag, more));
    rig.diag.reset();
    try testing.expect((try rig.key_file()) == null);
    // At the bound itself the start goes ahead.
    try rig.put("/edge-certs/h0.example", "{\"v\":1}");
    const page = [_]store.Op{.{ .delete = "/edge-certs/h500.example" }};
    _ = try rig.memory.interface().txn(.{ .on_success = &page }, &rig.diag);
    var ready = try open(testing.allocator, testing.io, s, rig.path(), o, &rig.diag);
    ready.ready.wipe();
}

test "an aside name in the way refuses the discard, and the old key is kept" {
    // Goal: review of PR #8 (SHOULD): `set_aside` with `<name>.discarded-<s>` already there.
    // Method: plant that name for this second and the next two; the discard deletes the records,
    // then refuses (ZC-E0806) before replacing anything. The old key file is unchanged and the
    // planted files keep their bytes; the next start, with no sealed records left, opens with
    // the old key.
    var rig: TestRig = undefined;
    try rig.init(testing.io);
    defer rig.deinit();
    const other = try plant_unopenable(&rig, 2, 0, 1);
    const now = @divFloor(std.Io.Clock.real.now(testing.io).toMilliseconds(), 1000);
    var name: [aside_name_bytes_max]u8 = undefined;
    for (0..3) |offset| {
        const seconds = now + @as(i64, @intCast(offset));
        const aside = try std.fmt.bufPrint(&name, "seal.key.discarded-{d}", .{seconds});
        try rig.tmp.dir.writeFile(testing.io, .{ .sub_path = aside, .data = "planted\n" });
    }
    try testing.expectError(error.Failed, rig.open_key(true));
    try testing.expectEqual(codes.Code.E0806, rig.diag.code.?);
    try testing.expect(cause_holds(&rig.diag, "that file exists"));
    rig.diag.reset();
    try testing.expectEqualSlices(u8, &other, &(try rig.key_file()).?);
    try testing.expectEqual(@as(usize, 3), try rig.asides(&name));
    try testing.expectEqual(@as(usize, 0), try rig.count("/edge-certs/"));
    var kept = try rig.open_key(false);
    defer kept.wipe();
    try testing.expectEqualSlices(u8, &other, &kept.bytes);
}

test "a key file gone between its write and its read is ZC-E0806, never a second key" {
    // Goal: review of PR #8 (SHOULD): `make`'s "written and then removed" branch. Method: call
    // the branch, `read_winner`, with no key file (another start wrote one and it was removed),
    // then with one: the first refuses, the second returns the file's key.
    var rig: TestRig = undefined;
    try rig.init(testing.io);
    defer rig.deinit();
    const gone = read_winner(testing.io, rig.tmp.dir, rig.path(), "seal.key", &rig.diag);
    try testing.expectError(error.Failed, gone);
    try testing.expectEqual(codes.Code.E0806, rig.diag.code.?);
    try testing.expect(cause_holds(&rig.diag, "it was written and then removed"));
    rig.diag.reset();
    const winner: [32]u8 = @splat(0x3c);
    try files.write_seed(testing.io, rig.tmp.dir, rig.path(), "seal.key", winner, &rig.diag);
    var read = try read_winner(testing.io, rig.tmp.dir, rig.path(), "seal.key", &rig.diag);
    defer read.wipe();
    try testing.expectEqualSlices(u8, &winner, &read.bytes);
}
