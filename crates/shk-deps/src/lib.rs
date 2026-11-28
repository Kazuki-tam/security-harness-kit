//! Dependency advisory matching for `shk deps` (experimental).
//!
//! This crate never touches the network: it builds a local index from an
//! advisory dump someone else fetched, and matches packages against it.

pub mod audit;
pub mod cache;
pub mod cargo_lock;
pub mod config;
pub mod index;
pub mod model;
pub mod osv;
pub mod text;

pub use audit::{AuditRequest, DataState, DepsAuditReport, audit};
pub use config::DepsConfig;
pub use index::{BuiltIndex, IndexLimits, build_index, build_index_with_limits};
pub use model::{DependencyInfo, DepsFinding, Index, IndexEntry, Rule};
pub use osv::{AdvisoryDb, AdvisoryMatch};

#[cfg(test)]
pub(crate) mod testutil;
