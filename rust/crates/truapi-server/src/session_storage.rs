//! Storage namespace activation for Rust hosts with identity-owned stores.

use truapi_platform::SessionUiInfo;

/// Commits a prepared identity namespace before the runtime publishes Connected.
/// Install this adapter when constructing the runtime, before boot restoration.
///
/// This synchronous operation runs in the session activation critical section.
/// Implementations must keep their maps and paths coherent on failure and must
/// not call back into the runtime or emit auth notifications. Returning an error
/// aborts activation and disconnects the runtime.
pub trait SessionStorage: Send + Sync {
    /// Prepare durable state, then atomically replace the mounted namespace.
    fn activate(&self, session: &SessionUiInfo) -> Result<(), String>;
}
