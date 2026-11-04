//! SplinterBridge Protocol Buffers and gRPC stubs.

pub mod v1 {
    tonic::include_proto!("splinterbridge.v1");
}

pub use v1::*;
