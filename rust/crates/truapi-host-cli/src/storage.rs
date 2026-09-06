//! Durable replacement of host-private state files.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// Replace a private state file, keeping temporary and final files private.
///
/// `NamedTempFile` creates an exclusive, randomly named file with Unix mode
/// 0600, and removes it on any failed write or replacement. `persist` replaces
/// the destination atomically, including on Windows. Sync the containing
/// directory on Unix so the replacement survives a crash.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".truapi-")
        .tempfile_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_replacement_preserves_contents_and_cleans_temporary_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        write_private(&path, b"first").unwrap();
        write_private(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);

        // A directory cannot be replaced by a state file. The old destination
        // and its contents survive, and the failed replacement leaves no temp.
        let blocked = directory.path().join("blocked");
        fs::create_dir(&blocked).unwrap();
        assert!(write_private(&blocked, b"invalid").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn both_new_and_replaced_state_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        write_private(&path, b"synthetic secret").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&path, b"replacement").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
