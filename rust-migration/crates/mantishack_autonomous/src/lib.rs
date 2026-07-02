//! Autonomous planning — Rust port of the pure surface of `packages/autonomous/`.
//! The stateful, time-based, and I/O planner methods stay Python; the
//! keyword-driven goal classifier ports here.

pub mod goal_planner;

pub use goal_planner::{create_goal_from_user_input, Goal, GoalType};
