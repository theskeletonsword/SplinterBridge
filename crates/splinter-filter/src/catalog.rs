//! Hot-reloadable regulatory catalog interface.
//!
//! Production deployments must back this with a config service that pushes
//! catalog updates (CAC, RKN, etc.) to gateway instances without restarting.
//! The trait is intentionally minimal so operators can plug their own catalog
//! distribution pipeline.

use splinter_proto::{DropReasonCode, Jurisdiction};
use std::time::{SystemTime, UNIX_EPOCH};

/// Errors from catalog operations.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("catalog unavailable")]
    Unavailable,
    #[error("invalid catalog format: {0}")]
    InvalidFormat(String),
}

/// Trait for a hot-reloadable jurisdiction catalog.
///
/// Implementations must:
/// - Support atomic swap of the underlying matcher without dropping in-flight
///   packets.
/// - Be versioned so operators can roll back a bad signature.
/// - Keep per-region catalogs sovereign (China catalog never leaves China).
pub trait RegulatoryCatalog: Send + Sync {
    /// Reloads the catalog from `bytes` (a serialized term list) and returns
    /// the new catalog version.
    fn reload(&self, bytes: &[u8]) -> Result<u64, CatalogError>;

    /// Returns the current catalog version.
    fn version(&self) -> u64;

    /// Checks whether `text` matches any term in the catalog for `jurisdiction`.
    fn is_match(&self, jurisdiction: Jurisdiction, text: &str) -> bool;

    /// Returns the drop reason code for a match in `jurisdiction`.
    fn drop_code(&self, jurisdiction: Jurisdiction) -> DropReasonCode;

    /// Current wall-clock time in milliseconds since the UNIX epoch.
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// Stub catalog that allows everything. Suitable for development until an
/// operator deploys a real catalog distribution pipeline.
pub struct AllowAllCatalog;

impl RegulatoryCatalog for AllowAllCatalog {
    fn reload(&self, _bytes: &[u8]) -> Result<u64, CatalogError> {
        Ok(self.now_ms())
    }

    fn version(&self) -> u64 {
        self.now_ms()
    }

    fn is_match(&self, _jurisdiction: Jurisdiction, _text: &str) -> bool {
        false
    }

    fn drop_code(&self, _jurisdiction: Jurisdiction) -> DropReasonCode {
        DropReasonCode::DropReasonNone
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_all_catalog_never_matches() {
        let catalog = AllowAllCatalog;
        assert!(!catalog.is_match(Jurisdiction::CnPiplCac, "anything"));
        assert_eq!(catalog.version(), catalog.now_ms());
    }
}
