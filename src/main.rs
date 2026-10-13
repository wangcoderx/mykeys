#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod vault;

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use tauri::{Manager, State, WindowEvent};
use vault::{KeyRecord, UnlockMode, VaultData, VaultFile};
use zeroize::{Zeroize, Zeroizing};

const SERVICE: &str = "com.mykeys.vault";
const ACCOUNT: &str = "local-vault";
const SESSION_IDLE: Duration = Duration::from_secs(5 * 60);
const RETRIEVAL_AUTH: Duration = Duration::from_secs(5 * 60);
const TRUST_72_HOURS: u64 = 72 * 60 * 60;

struct RuntimeState {
    session: Mutex<Option<Session>>,
    authorized_until: Mutex<Option<Instant>>,
    vault_op: Mutex<()>,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            session: Mutex::new(None),
            authorized_until: Mutex::new(None),
            vault_op: Mutex::new(()),
        }
    }
}

struct Session {
    dek: Zeroizing<Vec<u8>>,
    last_activity: Instant,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppStatus {
    initialized: bool,
    unlocked: bool,
    unlock_mode: String,
    retrieve_auth: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NewKey {
    name: String,
    provider: String,
    secret: String,
    expires_at: Option<String>,
    permissions: Option<String>,
    notes: Option<String>,
}

impl Drop for NewKey {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeySummary {
    id: String,
    name: String,
    provider: String,
    masked: String,
    expires_at: Option<String>,
    permissions: Option<String>,
    notes: Option<String>,
    updated_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCredential {
    version: u32,
    vault_id: String,
    issued_at: u64,
    last_used_at: u64,
    expires_at: Option<u64>,
    dek: String,
}

fn keychain() -> Result<Entry, String> {
    Entry::new(SERVICE, ACCOUNT).map_err(|error| format!("系统凭据不可用：{error}"))
}

fn remove_credential_verified() -> Result<(), String> {
    let entry = keychain()?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => {}
        Err(error) => return Err(format!("删除系统凭据失败：{error}")),
    }
    match entry.get_password() {
        Err(keyring::Error::NoEntry) => Ok(()),
        Ok(_) => Err("系统凭据删除失败，安全设置未更改".into()),
        Err(error) => Err(format!("无法验证系统凭据已删除：{error}")),
    }
}

fn make_credential(
    file: &VaultFile,
    dek: &[u8],
    mode: UnlockMode,
) -> Result<StoredCredential, String> {
    let issued_at = vault::now();
    Ok(StoredCredential {
        version: 1,
        vault_id: file.vault_id.clone().ok_or("保险库缺少 vault ID")?,
        issued_at,
        last_used_at: issued_at,
        expires_at: (mode == UnlockMode::Trust72Hours).then_some(issued_at + TRUST_72_HOURS),
        dek: B64.encode(dek),
    })
}

fn save_credential(credential: &StoredCredential) -> Result<(), String> {
    let value = Zeroizing::new(
        serde_json::to_string(credential).map_err(|_| "系统凭据序列化失败".to_string())?,
    );
    keychain()?
        .set_password(&value)
        .map_err(|error| format!("写入系统凭据失败：{error}"))
}

fn validate_input(input: &NewKey) -> Result<(), String> {
    vault::validate_text(&input.name, 256, "名称", false)?;
    vault::validate_text(&input.provider, 128, "厂商", false)?;
    vault::validate_text(&input.secret, 64 * 1024, "API Key", false)?;
    if let Some(value) = &input.expires_at {
        vault::validate_text(value, 64, "到期时间", true)?;
    }
    if let Some(value) = &input.permissions {
        vault::validate_text(value, 2 * 1024, "权限", true)?;
    }
    if let Some(value) = &input.notes {
        vault::validate_text(value, 64 * 1024, "备注", true)?;
    }
    Ok(())
}

fn set_session(state: &RuntimeState, dek: Zeroizing<Vec<u8>>) -> Result<(), String> {
    *state.session.lock().map_err(|_| "会话锁异常")? = Some(Session {
        dek,
        last_activity: Instant::now(),
    });
    *state.authorized_until.lock().map_err(|_| "授权锁异常")? = None;
    Ok(())
}

fn clear_session(state: &RuntimeState) -> Result<(), String> {
    *state.session.lock().map_err(|_| "会话锁异常")? = None;
    *state.authorized_until.lock().map_err(|_| "授权锁异常")? = None;
    Ok(())
}

fn session(state: &RuntimeState) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut guard = state.session.lock().map_err(|_| "会话锁异常")?;
    let Some(current) = guard.as_mut() else {
        return Err("保险库已锁定".into());
    };
    if current.last_activity.elapsed() >= SESSION_IDLE {
        *guard = None;
        *state.authorized_until.lock().map_err(|_| "授权锁异常")? = None;
        return Err("保险库因闲置已锁定".into());
    }
    current.last_activity = Instant::now();
    Ok(Zeroizing::new(current.dek.to_vec()))
}

fn session_peek(state: &RuntimeState) -> Result<Zeroizing<Vec<u8>>, String> {
    state
        .session
        .lock()
        .map_err(|_| "会话锁异常")?
        .as_ref()
        .map(|current| Zeroizing::new(current.dek.to_vec()))
        .ok_or_else(|| "保险库已锁定".into())
}

fn session_status(state: &RuntimeState) -> Result<bool, String> {
    let mut guard = state.session.lock().map_err(|_| "会话锁异常")?;
    if guard
        .as_ref()
        .is_some_and(|current| current.last_activity.elapsed() >= SESSION_IDLE)
    {
        *guard = None;
        *state.authorized_until.lock().map_err(|_| "授权锁异常")? = None;
    }
    Ok(guard.is_some())
}

#[tauri::command]
fn status(state: State<'_, RuntimeState>) -> Result<AppStatus, String> {
    let initialized = vault::vault_path()?.exists();
    let unlocked = session_status(&state)?;
    let mut mode = UnlockMode::EveryLaunch;
    let mut retrieve_auth = true;
    if initialized && unlocked {
        if let Ok(file) = vault::read_file() {
            if let Ok(dek) = session_peek(&state) {
                if let Ok(data) = vault::read_data(&file, &dek) {
                    mode = data.unlock_mode;
                    retrieve_auth = data.retrieve_auth;
                }
            }
        }
    }
    Ok(AppStatus {
        initialized,
        unlocked,
        unlock_mode: mode.label().into(),
        retrieve_auth,
    })
}

#[tauri::command]
fn initialize(
    password: String,
    unlock_mode: String,
    retrieve_auth: bool,
    state: State<'_, RuntimeState>,
) -> Result<(), String> {
    let password = Zeroizing::new(password);
    vault::validate_password(&password)?;
    let mode = UnlockMode::parse(&unlock_mode)?;
    let _operation = state.vault_op.lock().map_err(|_| "保险库事务锁异常")?;
    let _file_lock = vault::acquire_file_lock()?;
    if vault::vault_path()?.exists() {
        return Err("保险库已经存在".into());
    }
    let data = VaultData {
        records: vec![],
        unlock_mode: mode,
        retrieve_auth,
    };
    let (file, dek) = vault::create_file(&password, &data)?;
    if mode == UnlockMode::EveryLaunch {
        // The safest mode must remain usable when a platform keychain is unavailable.
        // A stale credential cannot unlock this vault because try_system_unlock verifies
        // the encrypted mode before creating a session.
        let _ = remove_credential_verified();
    } else {
        save_credential(&make_credential(&file, &dek, mode)?)?;
    }
    if let Err(error) = vault::atomic_write(&file) {
        if mode != UnlockMode::EveryLaunch {
            let _ = remove_credential_verified();
        }
        return Err(error);
    }
    set_session(&state, dek)
}

#[tauri::command]
fn unlock(password: String, state: State<'_, RuntimeState>) -> Result<(), String> {
    let password = Zeroizing::new(password);
    let _operation = state.vault_op.lock().map_err(|_| "保险库事务锁异常")?;
    let _file_lock = vault::acquire_file_lock()?;
    let mut file = vault::read_file()?;
    let dek = vault::unwrap_dek(&file, &password)?;
    let data = vault::read_data(&file, &dek)?;
    if file.version == vault::LEGACY_VERSION {
        vault::migrate_v1(&mut file, &dek, &password, &data)?;
        if data.unlock_mode != UnlockMode::EveryLaunch {
            save_credential(&make_credential(&file, &dek, data.unlock_mode)?)?;
        }
    }
    set_session(&state, dek)
}

#[tauri::command]
fn try_system_unlock(state: State<'_, RuntimeState>) -> Result<bool, String> {
    let _operation = state.vault_op.lock().map_err(|_| "保险库事务锁异常")?;
    let file = vault::read_file()?;
    if file.version != vault::FORMAT_VERSION {
        return Ok(false);
    }
    let Ok(raw) = keychain()?.get_password() else {
        return Ok(false);
    };
    let raw = Zeroizing::new(raw);
    let Ok(mut credential) = serde_json::from_str::<StoredCredential>(&raw) else {
        let _ = remove_credential_verified();
        return Ok(false);
    };
    if credential.version != 1 || Some(credential.vault_id.as_str()) != file.vault_id.as_deref() {
        return Ok(false);
    }
    let current = vault::now();
    if current < credential.issued_at
        || current < credential.last_used_at
        || credential
            .expires_at
            .is_some_and(|expires| current > expires)
    {
        let _ = remove_credential_verified();
        return Ok(false);
    }
    let dek = Zeroizing::new(vault::decode_limited(&credential.dek, 32, "系统数据密钥")?);
    if dek.len() != 32 {
        return Err("系统数据密钥长度无效".into());
    }
    let data = vault::read_data(&file, &dek)?;
    let matches = match data.unlock_mode {
        UnlockMode::EveryLaunch => false,
        UnlockMode::Trust72Hours => credential.expires_at.is_some(),
        UnlockMode::SystemCredential => credential.expires_at.is_none(),
    };
    if !matches {
        let _ = remove_credential_verified();
        return Ok(false);
    }
    credential.last_used_at = current;
    save_credential(&credential)?;
    set_session(&state, dek)?;
    Ok(true)
}

#[tauri::command]
fn lock(state: State<'_, RuntimeState>) -> Result<(), String> {
    clear_session(&state)
}

#[tauri::command]
fn list_keys(state: State<'_, RuntimeState>) -> Result<Vec<KeySummary>, String> {
    let dek = session(&state)?;
    let file = vault::read_file()?;
    let data = vault::read_data(&file, &dek)?;
    Ok(data
        .records
        .iter()
        .map(|record| {
            let tail = record
                .secret
                .chars()
                .rev()
                .take(4)
                .collect::<String>()
                .chars()
                .rev()
                .collect::<String>();
            KeySummary {
                id: record.id.clone(),
                name: record.name.clone(),
                provider: record.provider.clone(),
                masked: format!("••••••••••••{tail}"),
                expires_at: record.expires_at.clone(),
                permissions: record.permissions.clone(),
                notes: record.notes.clone(),
                updated_at: record.updated_at,
            }
        })
        .collect())
}

#[tauri::command]
fn add_key(mut input: NewKey, state: State<'_, RuntimeState>) -> Result<String, String> {
    validate_input(&input)?;
    let _operation = state.vault_op.lock().map_err(|_| "保险库事务锁异常")?;
    let _file_lock = vault::acquire_file_lock()?;
    let dek = session(&state)?;
    let mut file = vault::read_file()?;
    let mut data = vault::read_data(&file, &dek)?;
    if data.records.len() >= vault::MAX_RECORDS {
        return Err("保险库记录数已达到上限".into());
    }
    let id = B64
        .encode(vault::random::<12>())
        .replace(['/', '+', '='], "");
    let timestamp = vault::now();
    data.records.push(KeyRecord {
        id: id.clone(),
        name: std::mem::take(&mut input.name),
        provider: std::mem::take(&mut input.provider),
        secret: std::mem::take(&mut input.secret),
        expires_at: std::mem::take(&mut input.expires_at),
        permissions: std::mem::take(&mut input.permissions),
        notes: std::mem::take(&mut input.notes),
        created_at: timestamp,
        updated_at: timestamp,
    });
    vault::persist(&mut file, &dek, &data)?;
    Ok(id)
}

#[tauri::command]
fn reveal_key(id: String, state: State<'_, RuntimeState>) -> Result<String, String> {
    vault::validate_text(&id, 128, "记录 ID", false)?;
    let dek = session(&state)?;
    let file = vault::read_file()?;
    let mut data = vault::read_data(&file, &dek)?;
    if data.retrieve_auth {
        let valid = state
            .authorized_until
            .lock()
            .map_err(|_| "授权锁异常")?
            .is_some_and(|deadline| Instant::now() < deadline);
        if !valid {
            return Err("需要主密码验证".into());
        }
    }
    data.records
        .iter_mut()
        .find(|record| record.id == id)
        .map(|record| std::mem::take(&mut record.secret))
        .ok_or_else(|| "记录不存在".into())
}

#[tauri::command]
fn authorize_retrieval(password: String, state: State<'_, RuntimeState>) -> Result<(), String> {
    let password = Zeroizing::new(password);
    let dek = session(&state)?;
    let file = vault::read_file()?;
    if *vault::unwrap_dek(&file, &password)? != *dek {
        return Err("主密码错误".into());
    }
    *state.authorized_until.lock().map_err(|_| "授权锁异常")? =
        Some(Instant::now() + RETRIEVAL_AUTH);
    Ok(())
}

#[tauri::command]
fn update_settings(
    unlock_mode: String,
    retrieve_auth: bool,
    password: String,
    state: State<'_, RuntimeState>,
) -> Result<(), String> {
    let password = Zeroizing::new(password);
    let mode = UnlockMode::parse(&unlock_mode)?;
    let _operation = state.vault_op.lock().map_err(|_| "保险库事务锁异常")?;
    let _file_lock = vault::acquire_file_lock()?;
    let dek = session(&state)?;
    let mut file = vault::read_file()?;
    if *vault::unwrap_dek(&file, &password)? != *dek {
        return Err("主密码错误".into());
    }
    let mut data = vault::read_data(&file, &dek)?;
    if file.version == vault::LEGACY_VERSION {
        vault::migrate_v1(&mut file, &dek, &password, &data)?;
    }
    if mode == UnlockMode::EveryLaunch {
        remove_credential_verified()?;
    } else {
        save_credential(&make_credential(&file, &dek, mode)?)?;
    }
    let previous = data.unlock_mode;
    data.unlock_mode = mode;
    data.retrieve_auth = retrieve_auth;
    if let Err(error) = vault::persist(&mut file, &dek, &data) {
        if previous == UnlockMode::EveryLaunch {
            let _ = remove_credential_verified();
        } else if let Ok(credential) = make_credential(&file, &dek, previous) {
            let _ = save_credential(&credential);
        }
        return Err(error);
    }
    *state.authorized_until.lock().map_err(|_| "授权锁异常")? = None;
    Ok(())
}

#[tauri::command]
fn change_password(
    old_password: String,
    new_password: String,
    state: State<'_, RuntimeState>,
) -> Result<(), String> {
    let old_password = Zeroizing::new(old_password);
    let new_password = Zeroizing::new(new_password);
    vault::validate_password(&new_password)?;
    let _operation = state.vault_op.lock().map_err(|_| "保险库事务锁异常")?;
    let _file_lock = vault::acquire_file_lock()?;
    let dek = session(&state)?;
    let mut file = vault::read_file()?;
    if *vault::unwrap_dek(&file, &old_password)? != *dek {
        return Err("当前主密码错误".into());
    }
    let data = vault::read_data(&file, &dek)?;
    vault::rewrap(&mut file, &dek, &new_password)?;
    vault::persist(&mut file, &dek, &data)?;
    if data.unlock_mode != UnlockMode::EveryLaunch {
        save_credential(&make_credential(&file, &dek, data.unlock_mode)?)?;
    }
    *state.authorized_until.lock().map_err(|_| "授权锁异常")? = None;
    Ok(())
}

#[tauri::command]
fn destroy_vault(confirmation: String, state: State<'_, RuntimeState>) -> Result<(), String> {
    if confirmation != "删除全部数据" {
        return Err("销毁确认文字不正确".into());
    }
    let _operation = state.vault_op.lock().map_err(|_| "保险库事务锁异常")?;
    let _file_lock = vault::acquire_file_lock()?;
    clear_session(&state)?;
    remove_credential_verified()?;
    let path = vault::vault_path()?;
    if path.exists() {
        std::fs::remove_file(path).map_err(|error| format!("删除保险库失败：{error}"))?;
    }
    Ok(())
}

fn main() {
    let app = tauri::Builder::default()
        .manage(RuntimeState::default())
        .invoke_handler(tauri::generate_handler![
            status,
            initialize,
            unlock,
            try_system_unlock,
            lock,
            list_keys,
            add_key,
            reveal_key,
            authorize_retrieval,
            update_settings,
            change_password,
            destroy_vault
        ])
        .on_window_event(|window, event| {
            if matches!(event, WindowEvent::Focused(false) | WindowEvent::Destroyed) {
                if let Some(state) = window.try_state::<RuntimeState>() {
                    let _ = clear_session(&state);
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("failed to build MyKeys");
    app.run(|handle, event| {
        if matches!(
            event,
            tauri::RunEvent::Exit | tauri::RunEvent::ExitRequested { .. }
        ) {
            if let Some(state) = handle.try_state::<RuntimeState>() {
                let _ = clear_session(&state);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_expiry_depends_on_mode() {
        let data = VaultData {
            records: vec![],
            unlock_mode: UnlockMode::EveryLaunch,
            retrieve_auth: true,
        };
        let (file, dek) = vault::create_file("correct horse battery staple", &data).unwrap();
        let temporary = make_credential(&file, &dek, UnlockMode::Trust72Hours).unwrap();
        let system = make_credential(&file, &dek, UnlockMode::SystemCredential).unwrap();
        assert_eq!(
            temporary.expires_at,
            Some(temporary.issued_at + TRUST_72_HOURS)
        );
        assert!(system.expires_at.is_none());
    }

    #[test]
    fn frontend_does_not_interpolate_vault_fields_as_html() {
        let html = include_str!("../MyKeys-2.0/index.html");
        let config = include_str!("../tauri.conf.json");
        for unsafe_expression in [
            "${k.name}",
            "${k.provider}",
            "${k.secret}",
            "${k.masked}",
            "${k.note}",
            "${k.permission}",
        ] {
            assert!(!html.contains(unsafe_expression));
        }
        assert!(html.contains("escapeHtml(state.revealed?k.secret:k.masked)"));
        assert!(!config.contains("script-src 'self' 'unsafe-inline'"));
    }
}
