use fs2::FileExt;
use std::fs::OpenOptions;

pub struct ShieldLock {
    _file: std::fs::File,
}

pub fn acquire_lock() -> Result<ShieldLock, String> {
    let mut lock_path =
        std::env::current_dir().map_err(|e| format!("Cannot get current directory: {e}"))?;

    lock_path.push("liberty-shield.lock");

    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| format!("Cannot open lock file {:?}: {e}", lock_path))?;

    file.try_lock_exclusive()
        .map_err(|_| "Liberty Shield is already running.".to_string())?;

    Ok(ShieldLock { _file: file })
}
