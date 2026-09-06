//! Permission decision and encoding policy without storage or prompt callbacks.
use parity_scale_codec::{Decode, Encode};
use truapi::latest::{RemotePermission, RemotePermissionRequest};
use truapi_platform::PermissionAuthorizationStatus;

/// Persisted answer for a single permission request. Keep `Authorized` at
/// discriminant 0 and `Denied` at 1 to preserve the existing two-variant cache
/// encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub(crate) enum StoredAuthorizationStatus {
    /// User authorized the permission.
    Authorized,
    /// User denied the permission.
    Denied,
}

impl From<StoredAuthorizationStatus> for PermissionAuthorizationStatus {
    fn from(status: StoredAuthorizationStatus) -> Self {
        match status {
            StoredAuthorizationStatus::Authorized => PermissionAuthorizationStatus::Authorized,
            StoredAuthorizationStatus::Denied => PermissionAuthorizationStatus::Denied,
        }
    }
}

impl From<bool> for StoredAuthorizationStatus {
    fn from(granted: bool) -> Self {
        if granted {
            Self::Authorized
        } else {
            Self::Denied
        }
    }
}

/// Domain patterns a remote request covers, or `None` when the request is not a
/// domain grant and so occupies a single slot of its own.
pub(crate) fn requested_domains(request: &RemotePermissionRequest) -> Option<&[String]> {
    match &request.permission {
        RemotePermission::Remote { domains } => Some(domains),
        _ => None,
    }
}

/// A domain bundle as a request, for the key that answers it as a whole.
pub(crate) fn remote_bundle_request(domains: &[String]) -> RemotePermissionRequest {
    RemotePermissionRequest {
        permission: RemotePermission::Remote {
            domains: domains.to_vec(),
        },
    }
}

/// What the stored per-domain decisions alone say about a bundle.
pub(crate) enum BundleResolution {
    /// Every domain in the bundle has a stored grant.
    Authorized,
    /// At least one domain has a stored denial, which denies the bundle: the
    /// product asked to reach all of them.
    Denied,
    /// Nothing is denied, and these domains have no decision of their own —
    /// exactly the set a prompt would put to the user.
    Undecided(Vec<String>),
}

pub(crate) fn status_into_stored(
    status: PermissionAuthorizationStatus,
) -> Option<StoredAuthorizationStatus> {
    match status {
        PermissionAuthorizationStatus::NotDetermined => None,
        PermissionAuthorizationStatus::Denied => Some(StoredAuthorizationStatus::Denied),
        PermissionAuthorizationStatus::Authorized => Some(StoredAuthorizationStatus::Authorized),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persisted_decisions_preserve_the_wire_discriminants() {
        assert_eq!(StoredAuthorizationStatus::Authorized.encode(), vec![0]);
        assert_eq!(StoredAuthorizationStatus::Denied.encode(), vec![1]);
        assert!(status_into_stored(PermissionAuthorizationStatus::NotDetermined).is_none());
    }
}
