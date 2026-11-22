//! `sim-c3-teeth-template`: the cluster simulator with `c1_teeth_rollout_template` on
//! (`c1_teeth.zig`), to show that sim-c3 catches what that weakening lets through. Only the
//! `sim-c3-teeth` build step compiles this root; it installs the runner as
//! `sim_c1_teeth_rollout_template` for replay.

pub const c1_teeth_rollout_template = true;

pub const main = @import("sim_cluster_main.zig").main;
