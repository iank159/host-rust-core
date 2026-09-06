//! Protocol models, codecs, derivation, and permission policy.
//! Application services own platform callbacks and transport orchestration.

pub mod attestation;
pub mod bulletin;
pub mod dotns;
pub mod dotns_gateway;
pub mod entropy;
pub mod extrinsic;
pub mod permissions;
pub mod product_account;
pub mod session;
pub mod session_store;
pub mod sso;
pub mod statement_store;
pub mod transaction;
