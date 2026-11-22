//! #14: `Server.stop` cancels the HTTP watchdog (`server_http.Shared.watchdog`) and waits for it.
//! `std.Io` delivers a cancel once, at the task's next cancelation point, and never again. The
//! watchdog's sweep and tick swallow their errors (a `shutdown`, the revoked file's `stat`, a log
//! line), so a cancel that one of them took was lost: the watchdog slept and swept for ever, and
//! the stop waited on it for ever. These tests stop the watchdog at each point of its loop, each
//! within a bound, so that a regression fails instead of hanging the test run.
//!
//! The hooks are the watchdog's own seams: its `Clock`, read once per sweep, and its `Tick`. A
//! hook that "swallows" does what the revoked file's `look` does: a cancelable call whose
//! `error.Canceled` it does not pass on. On a timeout the hook gives the swallowed cancel back
//! (`recancel`), so the watchdog ends and its threads are joined even when the test fails.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const constants = @import("constants.zig");
const http = @import("server_http.zig");
const Clock = @import("clock.zig").Clock;

/// Where the watchdog is when its cancel is asked for.
const Point = enum {
    /// In its sleep (the cancel is asked before the first sweep).
    sleep,
    /// In the sweep, at no cancelation point.
    sweep,
    /// In the sweep, at a cancelation point whose error is swallowed.
    sweep_cancel_point,
    /// In the tick, at no cancelation point.
    tick,
    /// In the tick, at a cancelation point whose error is swallowed.
    tick_cancel_point,
};

/// How long a swallowing hook stays in its cancelable call: the cancel is asked for within
/// microseconds of the hook's entry, so it lands inside unless the cancel point is blocked.
const window_ms = 250;
/// How long a non-cancelable hook holds the watchdog after the cancel was asked for.
const hold_ms = 50;
/// The bound on a stop. A watchdog that stops ends within one sleep and one hook.
const stop_ms_max = constants.http_watchdog_ms + window_ms + 4_000;
const poll_ms = 10;

const Rig = struct {
    shared: http.Shared,
    point: Point,
    future: std.Io.Future(void),
    /// The hook has been entered once (it acts on its first call only).
    entered: std.atomic.Value(bool) = .init(false),
    /// A non-cancelable hook may return.
    released: std.atomic.Value(bool) = .init(false),
    /// A hook's cancelable call returned `error.Canceled`, which it swallowed.
    swallowed: std.atomic.Value(bool) = .init(false),
    /// The stop took too long: give the swallowed cancel back.
    give_up: std.atomic.Value(bool) = .init(false),
    /// Set by the watchdog's thread only.
    recanceled: bool = false,
    /// The cancel has returned: the watchdog has ended.
    done: std.atomic.Value(bool) = .init(false),

    fn hook(rig: *Rig, here: Point) void {
        const io = rig.shared.io;
        if (rig.give_up.load(.acquire)) {
            if (rig.swallowed.load(.acquire)) {
                if (!rig.recanceled) {
                    rig.recanceled = true;
                    io.recancel(); // The cancel this thread took and swallowed, given back.
                }
            }
        }
        if (here != rig.point) return;
        if (rig.entered.swap(true, .acq_rel)) return;
        switch (rig.point) {
            .sleep => unreachable, // No hook acts at `sleep`.
            .sweep, .tick => rig.hold(),
            .sweep_cancel_point, .tick_cancel_point => {
                io.sleep(.fromMilliseconds(window_ms), .awake) catch {
                    rig.swallowed.store(true, .release);
                };
            },
        }
    }

    /// Waits for `released` with cancelation blocked, so this wait is no cancelation point.
    fn hold(rig: *Rig) void {
        const io = rig.shared.io;
        const protection = io.swapCancelProtection(.blocked);
        defer _ = io.swapCancelProtection(protection);
        // Real time, not a count of sleeps: a sleep may last longer than it asks for.
        const started = std.Io.Clock.awake.now(io);
        while (!rig.released.load(.acquire)) {
            assert(started.untilNow(io, .awake).toMilliseconds() < stop_ms_max);
            // Blocked above: no `Io` call returns `error.Canceled` until it is restored.
            io.sleep(.fromMilliseconds(1), .awake) catch unreachable;
        }
    }

    fn now_ms(context: *anyopaque) u64 {
        const rig: *Rig = @ptrCast(@alignCast(context));
        rig.hook(.sweep);
        rig.hook(.sweep_cancel_point);
        return 0;
    }

    fn tick(context: *anyopaque) void {
        const rig: *Rig = @ptrCast(@alignCast(context));
        rig.hook(.tick);
        rig.hook(.tick_cancel_point);
    }

    /// Stops the watchdog when the test fails before its canceller runs. `give_up` first, so
    /// that a cancel a swallowing hook takes is given back and this cancel returns.
    fn abandon(rig: *Rig) void {
        rig.give_up.store(true, .release);
        rig.released.store(true, .release);
        rig.future.cancel(rig.shared.io);
    }

    /// The stop's cancel, on a thread of its own so that the test can bound it.
    fn cancel(rig: *Rig) void {
        rig.future.cancel(rig.shared.io);
        rig.done.store(true, .release);
    }
};

/// Waits up to `limit_ms` for `flag`; whether it was set.
fn wait_for(flag: *const std.atomic.Value(bool), limit_ms: u32) bool {
    var waited_ms: u32 = 0;
    while (!flag.load(.acquire)) {
        if (waited_ms >= limit_ms) return false;
        testing.io.sleep(.fromMilliseconds(poll_ms), .awake) catch return false;
        waited_ms += poll_ms;
    }
    return true;
}

fn stop_at(point: Point) !void {
    const gpa = testing.allocator;
    const rig = try gpa.create(Rig);
    defer gpa.destroy(rig);
    rig.* = .{ .shared = undefined, .point = point, .future = undefined };
    // The watchdog reads only `io`, `clock`, `slots` (all empty) and `tick`; the store, the API
    // and the options stay unset.
    rig.shared = .{
        .gpa = gpa,
        .io = testing.io,
        .store = undefined,
        .clock = .{ .context = rig, .now_ms_fn = Rig.now_ms },
        .api = undefined,
        .options = undefined,
        .tick = .{ .context = rig, .run = Rig.tick },
    };
    assert(rig.shared.connections() == 0);
    const canceller = canceller: {
        rig.future = try testing.io.concurrent(http.Shared.watchdog, .{&rig.shared});
        // Until the canceller runs, an error return must stop the watchdog before `rig` is
        // freed. The block ends this `errdefer`'s reach: past it, the canceller owns the stop.
        errdefer rig.abandon();
        if (point != .sleep) {
            // The hook runs at the first sweep, one `http_watchdog_ms` after the start.
            if (!wait_for(&rig.entered, stop_ms_max)) return error.HookNeverEntered;
        }
        break :canceller try std.Thread.spawn(.{}, Rig.cancel, .{rig});
    };
    if (point == .sweep or point == .tick) {
        testing.io.sleep(.fromMilliseconds(hold_ms), .awake) catch {};
        rig.released.store(true, .release);
    }
    const stopped = wait_for(&rig.done, stop_ms_max);
    if (!stopped) {
        rig.give_up.store(true, .release);
        // Within a sweep or two the hook gives the cancel back and the watchdog ends.
        if (!wait_for(&rig.done, stop_ms_max)) @panic("the watchdog never stopped (#14)");
    }
    canceller.join();
    assert(rig.done.load(.acquire));
    if (!stopped) {
        std.debug.print("the watchdog did not stop within {d} ms, cancelled at {t}\n", .{
            stop_ms_max, point,
        });
        return error.WatchdogKeptRunning;
    }
    // The sweep and the tick are no cancelation points: the cancel reached the sleep.
    try testing.expect(!rig.swallowed.load(.acquire));
    if (point != .sleep) try testing.expect(rig.entered.load(.acquire));
}

test "the watchdog stops when cancelled in its sleep" {
    // Goal: the plain case, the cancel landing in the sleep. Method: cancel at once.
    try stop_at(.sleep);
}

test "the watchdog stops when cancelled in its sweep" {
    // Goal: a cancel asked for while the sweep runs is kept for the sleep. Method: the clock,
    // read by the sweep, holds the watchdog (no cancelation point) while the cancel is asked.
    try stop_at(.sweep);
}

test "the watchdog stops when cancelled at a cancelation point of its sweep (#14)" {
    // Goal: a cancelable call in the sweep (its `shutdown`) cannot take the cancel. Method: the
    // clock makes a cancelable call that swallows `error.Canceled`, and the cancel is asked then.
    try stop_at(.sweep_cancel_point);
}

test "the watchdog stops when cancelled in its tick" {
    // Goal: a cancel asked for while the tick runs is kept for the sleep. Method: the tick holds
    // the watchdog (no cancelation point) while the cancel is asked.
    try stop_at(.tick);
}

test "the watchdog stops when cancelled at a cancelation point of its tick (#14)" {
    // Goal: a cancelable call in the tick (the revoked file's `stat`, a log line) cannot take
    // the cancel. Method: the tick makes a cancelable call that swallows `error.Canceled`, and
    // the cancel is asked then; before the fix, this hung `Server.stop`.
    try stop_at(.tick_cancel_point);
}
