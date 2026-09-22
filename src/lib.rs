//! GraphXploit's local analysis engine.
//!
//! The engine never runs code from an indexed project. It stores compact symbol
//! and relationship metadata in a per-project SQLite database.

pub mod agent;
pub mod ai;
pub mod analysis;
pub mod git;
pub mod model;
pub mod store;
pub mod web;

pub use analysis::{
    context_preview, dependencies, graph, impact, scan_project, search, ScanOptions,
};
pub use git::{branch_changes, working_changes};
pub use model::{ProjectSummary, QueryResult};
