//! Metadata projections and validated included-member snapshots shared by ring consumers.
use async_trait::async_trait;
use subxt::ext::scale_decode::DecodeAsType;
use verifiable::ring::RingDomainSize;

pub(crate) type RingPages = Vec<(u32, Vec<[u8; 32]>)>;

#[derive(Debug, derive_more::Display, derive_more::Error)]
pub(crate) enum SnapshotError {
    #[display("Members.RingKeysStatus is missing")]
    MissingStatus,
    #[display("Members.RingKeys page {actual} is not the expected page {expected}")]
    MissingPage { expected: usize, actual: u32 },
    #[display("Members.RingKeys contains an empty page")]
    EmptyPage,
    #[display("Members.RingKeys contains {actual} keys but RingKeysStatus includes {included}")]
    TooShort { actual: usize, included: u32 },
}

/// An adapter must bind all reads to one collection, ring index, and block.
#[async_trait]
pub(crate) trait RingSnapshotSource: Sync {
    type Error;
    async fn pages(&self) -> Result<RingPages, Self::Error>;
    async fn status(&self) -> Result<Option<RingStatus>, Self::Error>;
    fn invalid(error: SnapshotError) -> Self::Error;
}

pub(crate) struct RingSnapshot {
    pub(crate) members: Vec<[u8; 32]>,
}

impl RingSnapshot {
    pub(crate) async fn read<S: RingSnapshotSource>(source: &S) -> Result<Self, S::Error> {
        let pages = source.pages().await?;
        let status = source
            .status()
            .await?
            .ok_or_else(|| S::invalid(SnapshotError::MissingStatus))?;
        Self::validate(pages, status.included).map_err(S::invalid)
    }

    fn validate(mut pages: RingPages, included: u32) -> Result<Self, SnapshotError> {
        pages.sort_unstable_by_key(|(page, _)| *page);
        let mut members = Vec::new();
        for (expected, (actual, page)) in pages.into_iter().enumerate() {
            if actual as usize != expected {
                return Err(SnapshotError::MissingPage { expected, actual });
            }
            if page.is_empty() {
                return Err(SnapshotError::EmptyPage);
            }
            members.extend(page);
        }
        if members.len() < included as usize {
            return Err(SnapshotError::TooShort {
                actual: members.len(),
                included,
            });
        }
        members.truncate(included as usize);
        Ok(Self { members })
    }
}

#[derive(Debug, PartialEq, Eq, DecodeAsType)]
pub(crate) enum RingPosition {
    Onboarding {},
    Included { ring_index: u32, ring_position: u32 },
    Suspended,
}

#[derive(Debug, PartialEq, Eq, DecodeAsType)]
pub(crate) struct RingStatus {
    pub(crate) included: u32,
}

#[derive(Debug, PartialEq, Eq, DecodeAsType)]
pub(crate) struct CollectionInfo {
    pub(crate) ring_size: RingExponent,
}

#[derive(Debug, PartialEq, Eq, DecodeAsType)]
pub(crate) enum RingExponent {
    R2e9,
    R2e10,
    R2e14,
}

impl RingExponent {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn exponent(self) -> u8 {
        match self {
            Self::R2e9 => 9,
            Self::R2e10 => 10,
            Self::R2e14 => 14,
        }
    }

    pub(crate) fn domain_size(self) -> RingDomainSize {
        match self {
            Self::R2e9 => RingDomainSize::Domain11,
            Self::R2e10 => RingDomainSize::Domain12,
            Self::R2e14 => RingDomainSize::Domain16,
        }
    }
}

#[derive(Debug, PartialEq, Eq, DecodeAsType)]
pub(crate) struct BoundedMembers(pub(crate) Vec<[u8; 32]>);

#[derive(Debug, PartialEq, Eq, DecodeAsType)]
pub(crate) struct RingRoot {
    pub(crate) revision: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_order_gaps_duplicates_and_included_prefix() {
        let page = |index, key| (index, vec![[key; 32]]);
        let snapshot = RingSnapshot::validate(vec![page(1, 2), page(0, 1)], 1).unwrap();
        assert_eq!(snapshot.members, vec![[1; 32]]);
        for pages in [
            vec![page(1, 1)],
            vec![page(0, 1), page(2, 2)],
            vec![page(0, 1), page(0, 2)],
        ] {
            assert!(matches!(
                RingSnapshot::validate(pages, 1),
                Err(SnapshotError::MissingPage { .. })
            ));
        }
        assert!(matches!(
            RingSnapshot::validate(vec![page(0, 1)], 2),
            Err(SnapshotError::TooShort { .. })
        ));
        assert!(matches!(
            RingSnapshot::validate(vec![(0, vec![])], 0),
            Err(SnapshotError::EmptyPage)
        ));
    }

    #[test]
    fn absent_status_never_promotes_unincluded_members() {
        struct Missing;
        #[async_trait]
        impl RingSnapshotSource for Missing {
            type Error = SnapshotError;
            async fn pages(&self) -> Result<RingPages, Self::Error> {
                Ok(vec![(0, vec![[1; 32]])])
            }
            async fn status(&self) -> Result<Option<RingStatus>, Self::Error> {
                Ok(None)
            }
            fn invalid(error: SnapshotError) -> Self::Error {
                error
            }
        }
        assert!(matches!(
            futures::executor::block_on(RingSnapshot::read(&Missing)),
            Err(SnapshotError::MissingStatus)
        ));
    }
}
