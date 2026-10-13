use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::vault;

const STATE_FILE: &str = "security-state";
const STATE_VERSION: u32 = 1;
const MAX_STATE_BYTES: u64 = 4 * 1024;
const TAG_LABEL: &[u8] = b"mykeys:security-state:v1|";
const FREE_ATTEMPTS: u32 = 2;
const MAX_FAILURES: u32 = 1_000_000;

#[derive(Default)]
struct Counters {
    failures: u32,
    updated_at: u64,
    unlock_after: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredState {
    version: u32,
    failures: u32,
    updated_at: u64,
    unlock_after: u64,
    tag: String,
}

fn tag(failures: u32, updated_at: u64, unlock_after: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(TAG_LABEL);
    hasher.update(format!("{failures}|{updated_at}|{unlock_after}"));
    B64.encode(hasher.finalize())
}

pub fn delay_seconds(failures: u32) -> u64 {
    match failures {
        0..=FREE_ATTEMPTS => 0,
        3 => 5,
        4 => 30,
        _ => 5 * 60,
    }
}

fn remaining(counters: &Counters, now: u64) -> u64 {
    if counters.unlock_after == 0 {
        return 0;
    }
    if now < counters.updated_at {
        return counters.unlock_after.saturating_sub(counters.updated_at);
    }
    counters.unlock_after.saturating_sub(now)
}

fn load_at(path: &Path) -> Counters {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Counters::default();
    };
    if metadata.file_type().is_symlink() || metadata.len() > MAX_STATE_BYTES {
        return Counters::default();
    }
    let Ok(bytes) = fs::read(path) else {
        return Counters::default();
    };
    let Ok(state) = serde_json::from_slice::<StoredState>(&bytes) else {
        return Counters::default();
    };
    if state.version != STATE_VERSION
        || state.failures > MAX_FAILURES
        || state.tag != tag(state.failures, state.updated_at, state.unlock_after)
    {
        return Counters::default();
    }
    Counters {
        failures: state.failures,
        updated_at: state.updated_at,
        unlock_after: state.unlock_after,
    }
}

fn save_at(directory: &Path, counters: &Counters) -> Result<(), String> {
    fs::create_dir_all(directory).map_err(|error| format!("创建数据目录失败：{error}"))?;
    let state = StoredState {
        version: STATE_VERSION,
        failures: counters.failures,
        updated_at: counters.updated_at,
        unlock_after: counters.unlock_after,
        tag: tag(
            counters.failures,
            counters.updated_at,
            counters.unlock_after,
        ),
    };
    let bytes = serde_json::to_vec(&state).map_err(|_| "安全状态序列化失败".to_string())?;
    let suffix = B64
        .encode(vault::random::<9>())
        .replace(['/', '+', '='], "");
    let temporary = directory.join(format!(".security-state.{suffix}.tmp"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut output = options
            .open(&temporary)
            .map_err(|error| format!("创建安全状态文件失败：{error}"))?;
        output
            .write_all(&bytes)
            .map_err(|error| format!("写入安全状态失败：{error}"))?;
        output
            .sync_all()
            .map_err(|error| format!("同步安全状态失败：{error}"))?;
        fs::rename(&temporary, directory.join(STATE_FILE))
            .map_err(|error| format!("提交安全状态失败：{error}"))?;
        Ok::<(), String>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn clear_at(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("清除安全状态失败：{error}")),
    }
}

fn state_path() -> Result<PathBuf, String> {
    Ok(vault::app_dir()?.join(STATE_FILE))
}

fn load() -> Counters {
    match state_path() {
        Ok(path) => load_at(&path),
        Err(_) => Counters::default(),
    }
}

pub fn blocked_for() -> u64 {
    remaining(&load(), vault::now())
}

pub fn register_failure() -> Result<u64, String> {
    let failures = load().failures.saturating_add(1).min(MAX_FAILURES);
    let delay = delay_seconds(failures);
    let now = vault::now();
    save_at(
        &vault::app_dir()?,
        &Counters {
            failures,
            updated_at: now,
            unlock_after: now.saturating_add(delay),
        },
    )?;
    Ok(delay)
}

pub fn clear() -> Result<(), String> {
    clear_at(&state_path()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_directory() -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "mykeys-security-state-{}",
            B64.encode(vault::random::<9>())
                .replace(['/', '+', '='], "")
        ));
        fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn delay_schedule_matches_design_document() {
        assert_eq!(delay_seconds(0), 0);
        assert_eq!(delay_seconds(1), 0);
        assert_eq!(delay_seconds(2), 0);
        assert_eq!(delay_seconds(3), 5);
        assert_eq!(delay_seconds(4), 30);
        assert_eq!(delay_seconds(5), 300);
        assert_eq!(delay_seconds(50), 300);
    }

    #[test]
    fn remaining_counts_down_and_holds_on_clock_rollback() {
        let idle = Counters::default();
        assert_eq!(remaining(&idle, 1_000), 0);
        let counters = Counters {
            failures: 5,
            updated_at: 2_000,
            unlock_after: 2_300,
        };
        assert_eq!(remaining(&counters, 2_100), 200);
        assert_eq!(remaining(&counters, 2_300), 0);
        assert_eq!(remaining(&counters, 2_400), 0);
        assert_eq!(remaining(&counters, 1_500), 300);
    }

    #[cfg(unix)]
    #[test]
    fn state_round_trips_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = temp_directory();
        let path = directory.join(STATE_FILE);
        save_at(
            &directory,
            &Counters {
                failures: 4,
                updated_at: 1_000,
                unlock_after: 1_030,
            },
        )
        .unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let loaded = load_at(&path);
        assert_eq!(loaded.failures, 4);
        assert_eq!(remaining(&loaded, 1_020), 10);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn tampered_state_is_rejected_instead_of_locking_out() {
        let directory = temp_directory();
        let path = directory.join(STATE_FILE);
        save_at(
            &directory,
            &Counters {
                failures: 1,
                updated_at: 1_000,
                unlock_after: 1_000,
            },
        )
        .unwrap();
        let mut state: StoredState = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        state.failures = 500;
        state.unlock_after = 9_999_999;
        fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        let loaded = load_at(&path);
        assert_eq!(loaded.failures, 0);
        assert_eq!(remaining(&loaded, 1_000), 0);
        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn clearing_removes_state_and_tolerates_missing_file() {
        let directory = temp_directory();
        let path = directory.join(STATE_FILE);
        save_at(
            &directory,
            &Counters {
                failures: 3,
                updated_at: 1_000,
                unlock_after: 1_005,
            },
        )
        .unwrap();
        clear_at(&path).unwrap();
        assert_eq!(load_at(&path).failures, 0);
        clear_at(&path).unwrap();
        assert_eq!(load_at(&path).failures, 0);
        fs::remove_dir_all(&directory).unwrap();
    }
}
