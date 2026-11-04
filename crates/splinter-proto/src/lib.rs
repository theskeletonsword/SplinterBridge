//! SplinterBridge Protocol Buffers and gRPC stubs.

// Generated Tonic APIs return tonic::Status by value; their signatures are upstream.
#[allow(clippy::result_large_err)]
pub mod v1 {
    tonic::include_proto!("splinterbridge.v1");
}

pub use v1::*;

// Deliberately NOT re-exported into the federation protocol namespace.
#[allow(clippy::result_large_err)]
pub mod local_review {
    tonic::include_proto!("splinterbridge.local.v1");
}
