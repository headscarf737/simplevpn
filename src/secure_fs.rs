// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::fd::AsRawFd,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub const MAX_STATE_BYTES: u64 = 16 * 1024 * 1024;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn open_directory(path: &Path) -> io::Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?;
    let metadata = directory.metadata()?;
    if (metadata.uid() != 0 && metadata.uid() != crate::effective_uid())
        || metadata.mode() & 0o022 != 0
    {
        return Err(invalid(
            "state directory must have a trusted owner and must not be writable by group or others",
        ));
    }
    Ok(directory)
}

pub fn ensure_directory(path: &Path, mode: u32) -> io::Result<()> {
    match fs::DirBuilder::new().mode(mode).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let directory = open_directory(path)?;
    if directory.metadata()?.uid() != crate::effective_uid() {
        return Err(invalid("state directory has an unexpected owner"));
    }
    // Validate ownership and access before changing permissions, using the same FD.
    directory.set_permissions(fs::Permissions::from_mode(mode))?;
    if directory.metadata()?.mode() & 0o777 != mode {
        return Err(invalid("state directory permissions could not be verified"));
    }
    Ok(())
}

fn parent(path: &Path) -> io::Result<&Path> {
    path.parent()
        .ok_or_else(|| invalid("state path has no parent"))
}

pub fn read(path: &Path, mode: u32, limit: u64) -> io::Result<Vec<u8>> {
    let _directory = open_directory(parent(path)?)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || (metadata.uid() != 0 && metadata.uid() != crate::effective_uid())
        || metadata.mode() & 0o777 != mode
    {
        return Err(invalid(
            "state file type, owner, links, or permissions are unsafe",
        ));
    }
    if metadata.len() > limit {
        return Err(invalid("state file exceeds the size limit"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("state file exceeds the size limit"));
    }
    Ok(bytes)
}

pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    if bytes.len() as u64 >= MAX_STATE_BYTES {
        return Err(invalid("state file exceeds the size limit"));
    }
    let directory = open_directory(parent(path)?)?;
    if directory.metadata()?.uid() != crate::effective_uid() {
        return Err(invalid("state directory has an unexpected owner"));
    }
    // Exclusive random names never follow or truncate an existing temporary file,
    // including hard links. A stale temporary file does not prevent crash recovery.
    let mut temporary = tempfile::NamedTempFile::new_in(parent(path)?)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temporary.write_all(bytes)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    directory.sync_all()
}

pub fn open_log(path: &Path) -> io::Result<File> {
    let _directory = open_directory(parent(path)?)?;
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.uid() != crate::effective_uid() {
        return Err(invalid("supervisor log type, links, or owner are unsafe"));
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    if file.metadata()?.mode() & 0o777 != 0o600 {
        return Err(invalid("supervisor log permissions could not be verified"));
    }
    Ok(file)
}

pub fn lock_supervisor(path: &Path) -> io::Result<File> {
    let file = open_log(path)?;
    // SAFETY: file owns a valid FD. The returned file keeps the advisory lock alive.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use std::{ffi::CString, os::unix::fs::symlink};

    use super::*;

    #[test]
    fn state_reads_reject_symlinks_hardlinks_permissions_and_oversized_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        write_atomic(&path, b"{}", 0o600).unwrap();
        assert!(read(&path, 0o600, 2).is_err());
        assert_eq!(read(&path, 0o600, 32).unwrap(), b"{}\n");
        let alias = dir.path().join("alias");
        symlink(&path, &alias).unwrap();
        assert!(read(&alias, 0o600, 32).is_err());
        fs::remove_file(&alias).unwrap();
        fs::hard_link(&path, &alias).unwrap();
        assert!(read(&path, 0o600, 32).is_err());
        fs::remove_file(&alias).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read(&path, 0o600, 32).is_err());
    }

    #[test]
    fn unsafe_directory_is_rejected_before_chmod() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(ensure_directory(dir.path(), 0o700).is_err());
        assert_eq!(fs::metadata(dir.path()).unwrap().mode() & 0o777, 0o777);
    }

    #[test]
    fn log_hardlink_is_rejected_without_changing_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"unchanged").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        let log = dir.path().join("supervisor.log");
        fs::hard_link(&target, &log).unwrap();
        assert!(open_log(&log).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");
        assert_eq!(fs::metadata(target).unwrap().mode() & 0o777, 0o644);
    }

    #[test]
    fn atomic_write_does_not_truncate_linked_targets_or_stale_temporary_files() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"unchanged").unwrap();
        let path = dir.path().join("state.json");
        let stale = dir.path().join("state.json.tmp");
        fs::hard_link(&target, &path).unwrap();
        fs::hard_link(&target, &stale).unwrap();
        write_atomic(&path, b"new state", 0o600).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");
        assert_eq!(fs::read(&stale).unwrap(), b"unchanged");
        assert_eq!(read(&path, 0o600, 32).unwrap(), b"new state\n");
    }

    #[test]
    fn fifo_state_file_is_rejected_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let c_path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: c_path is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert!(read(&path, 0o600, 32).is_err());
    }

    #[test]
    fn supervisor_lock_prevents_concurrent_network_owners() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("supervisor.lock");
        let first = lock_supervisor(&path).unwrap();
        assert!(lock_supervisor(&path).is_err());
        drop(first);
        assert!(lock_supervisor(&path).is_ok());
    }
}
