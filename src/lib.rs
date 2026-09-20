//! GraphXploit's local analysis engine.
//!
//! The engine never runs code from an indexed project. It stores compact symbol
//! and relationship metadata in a per-project SQLite database.

pub mod ai;
pub mod analysis;
pub mod model;
pub mod store;
pub mod web;

pub use analysis::{dependencies, impact, scan_project, ScanOptions};
pub use model::{ProjectSummary, QueryResult};
