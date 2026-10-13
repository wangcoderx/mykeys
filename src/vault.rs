use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use fs2::FileExt;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub const FORMAT_VERSION: u32 = 2;
pub const LEGACY_VERSION: u32 = 1;
pub const MAX_RECORDS: usize = 5_000;
pub const MIN_PASSWORD_CHARS: usize = 16;
const MAX_FILE_BYTES: u64 = 25 * 1024 * 1024;
const MAX_PLAIN_BYTES: usize = 20 * 1024 * 1024;
const MAX_NAME_BYTES: usize = 256;
const MAX_PROVIDER_BYTES: usize = 128;
const MAX_SECRET_BYTES: usize = 64 * 1024;
const MAX_SHORT_BYTES: usize = 2 * 1024;
const MAX_NOTES_BYTES: usize = 64 * 1024;
const AAD_WRAP_V1: &[u8] = b"mykeys:v1:wrapped-dek";
const AAD_DATA_V1: &[u8] = b"mykeys:v1:vault-data";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnlockMode {
    #[serde(rename = "每次启动")]
    EveryLaunch,
    #[serde(rename = "72 小时")]
    Trust72Hours,
    #[serde(rename = "系统凭据")]
    SystemCredential,
}

impl UnlockMode {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "每次启动" => Ok(Self::EveryLaunch),
            "72 小时" => Ok(Self::Trust72Hours),
            "系统凭据" => Ok(Self::SystemCredential),
            _ => Err("不支持的解锁模式".into()),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::EveryLaunch => "每次启动",
            Self::Trust72Hours => "72 小时",
            Self::SystemCredential => "系统凭据",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyRecord {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub secret: String,
    pub expires_at: Option<String>,
    pub permissions: Option<String>,
    pub notes: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl Drop for KeyRecord {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultData {
    pub records: Vec<KeyRecord>,
    pub unlock_mode: UnlockMode,
    pub retrieve_auth: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KdfSpec {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfSpec {
    fn default() -> Self {
        Self {
            algorithm: "argon2id-1.3".into(),
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }
}

impl KdfSpec {
    fn validate(&self) -> Result<(), String> {
        if self.algorithm != "argon2id-1.3"
            || !(64 * 1024..=1024 * 1024).contains(&self.memory_kib)
            || !(3..=10).contains(&self.iterations)
            || !(1..=8).contains(&self.parallelism)
        {
            return Err("保险库 KDF 参数不受支持".into());
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultFile {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<KdfSpec>,
    pub salt: String,
    pub wrap_nonce: String,
    pub wrapped_dek: String,
    pub data_nonce: String,
    pub ciphertext: String,
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut output = [0_u8; N];
    OsRng.fill_bytes(&mut output);
    output
}

pub fn app_dir() -> Result<PathBuf, String> {
    dirs::data_dir()
        .map(|path| path.join("MyKeys"))
        .ok_or_else(|| "无法确定应用数据目录".into())
}

pub fn vault_path() -> Result<PathBuf, String> {
    Ok(app_dir()?.join("vault.mykeys"))
}

pub fn validate_password(password: &str) -> Result<(), String> {
    let lower = password.to_lowercase();
    let weak = [
        "password",
        "1234567890",
        "qwerty",
        "letmein",
        "admin",
        "iloveyou",
    ];
    let all_same = password
        .chars()
        .next()
        .is_some_and(|first| password.chars().all(|value| value == first));
    if password.chars().count() < MIN_PASSWORD_CHARS
        || all_same
        || weak.iter().any(|value| lower.contains(value))
    {
        return Err("主密码至少需要 16 个字符，且不能包含常见弱口令".into());
    }
    Ok(())
}

pub fn validate_text(
    value: &str,
    max: usize,
    label: &str,
    allow_empty: bool,
) -> Result<(), String> {
    if (!allow_empty && value.trim().is_empty()) || value.len() > max {
        return Err(format!("{label}为空或超过长度限制"));
    }
    if value.contains('\0') {
        return Err(format!("{label}包含无效字符"));
    }
    Ok(())
}

pub fn validate_record(record: &KeyRecord) -> Result<(), String> {
    validate_text(&record.id, 128, "记录 ID", false)?;
    validate_text(&record.name, MAX_NAME_BYTES, "名称", false)?;
    validate_text(&record.provider, MAX_PROVIDER_BYTES, "厂商", false)?;
    validate_text(&record.secret, MAX_SECRET_BYTES, "API Key", false)?;
    if let Some(value) = &record.expires_at {
        validate_text(value, 64, "到期时间", true)?;
    }
    if let Some(value) = &record.permissions {
        validate_text(value, MAX_SHORT_BYTES, "权限", true)?;
    }
    if let Some(value) = &record.notes {
        validate_text(value, MAX_NOTES_BYTES, "备注", true)?;
    }
    Ok(())
}

pub fn validate_data(data: &VaultData) -> Result<(), String> {
    if data.records.len() > MAX_RECORDS {
        return Err("保险库记录数超过限制".into());
    }
    data.records.iter().try_for_each(validate_record)
}

fn kdf(password: &str, salt: &[u8], spec: &KdfSpec) -> Result<Zeroizing<Vec<u8>>, String> {
    spec.validate()?;
    if salt.len() != 16 {
        return Err("保险库 salt 长度无效".into());
    }
    let params = Params::new(spec.memory_kib, spec.iterations, spec.parallelism, Some(32))
        .map_err(|_| "KDF 参数无效")?;
    let mut output = Zeroizing::new(vec![0_u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|_| String::from("密码派生失败"))?;
    Ok(output)
}

fn encrypt(key: &[u8], nonce: &[u8; 24], plain: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| "密钥长度无效")?
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plain, aad })
        .map_err(|_| "加密失败".into())
}

fn decrypt(
    key: &[u8],
    nonce: &[u8],
    cipher: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    if key.len() != 32 || nonce.len() != 24 || cipher.len() < 16 {
        return Err("保险库加密字段长度无效".into());
    }
    let plain = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| "密钥长度无效")?
        .decrypt(XNonce::from_slice(nonce), Payload { msg: cipher, aad })
        .map_err(|_| "认证失败".to_string())?;
    Ok(Zeroizing::new(plain))
}

pub fn decode_limited(value: &str, max: usize, label: &str) -> Result<Vec<u8>, String> {
    if value.len() > max.saturating_mul(4) / 3 + 8 {
        return Err(format!("{label}超过长度限制"));
    }
    B64.decode(value).map_err(|_| format!("{label}编码损坏"))
}

fn v2_header(file: &VaultFile) -> Result<(&str, &KdfSpec), String> {
    if file.version != FORMAT_VERSION {
        return Err("保险库版本不受支持".into());
    }
    let id = file.vault_id.as_deref().ok_or("保险库缺少 vault ID")?;
    validate_text(id, 128, "vault ID", false)?;
    let spec = file.kdf.as_ref().ok_or("保险库缺少 KDF 参数")?;
    spec.validate()?;
    Ok((id, spec))
}

fn wrap_aad(file: &VaultFile) -> Result<Vec<u8>, String> {
    if file.version == LEGACY_VERSION {
        return Ok(AAD_WRAP_V1.to_vec());
    }
    let (id, spec) = v2_header(file)?;
    Ok(format!(
        "mykeys:v2:wrapped-dek|{id}|{}|{}|{}|{}|{}",
        file.version, spec.algorithm, spec.memory_kib, spec.iterations, spec.parallelism
    )
    .into_bytes())
}

fn data_aad(file: &VaultFile) -> Result<Vec<u8>, String> {
    if file.version == LEGACY_VERSION {
        return Ok(AAD_DATA_V1.to_vec());
    }
    let (id, _) = v2_header(file)?;
    Ok(format!("mykeys:v2:vault-data|{id}|{}", file.version).into_bytes())
}

pub fn validate_file(file: &VaultFile) -> Result<(), String> {
    if file.version != LEGACY_VERSION && file.version != FORMAT_VERSION {
        return Err("保险库版本不受支持".into());
    }
    if file.version == FORMAT_VERSION {
        v2_header(file)?;
    } else if file.vault_id.is_some() || file.kdf.is_some() {
        return Err("旧版保险库头字段异常".into());
    }
    let salt = decode_limited(&file.salt, 16, "salt")?;
    let wrap_nonce = decode_limited(&file.wrap_nonce, 24, "包装 nonce")?;
    let wrapped = decode_limited(&file.wrapped_dek, 48, "包装密文")?;
    let data_nonce = decode_limited(&file.data_nonce, 24, "数据 nonce")?;
    let ciphertext = decode_limited(&file.ciphertext, MAX_PLAIN_BYTES + 16, "数据密文")?;
    if salt.len() != 16
        || wrap_nonce.len() != 24
        || wrapped.len() != 48
        || data_nonce.len() != 24
        || ciphertext.len() < 16
    {
        return Err("保险库字段长度无效".into());
    }
    Ok(())
}

fn reject_symlink(path: &Path, label: &str) -> Result<(), String> {
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(format!("{label}不能是符号链接"));
    }
    Ok(())
}

pub fn read_file() -> Result<VaultFile, String> {
    let path = vault_path()?;
    reject_symlink(&path, "保险库文件")?;
    let metadata = fs::metadata(&path).map_err(|error| format!("读取保险库失败：{error}"))?;
    if metadata.len() > MAX_FILE_BYTES {
        return Err("保险库文件超过大小限制".into());
    }
    let bytes = fs::read(&path).map_err(|error| format!("读取保险库失败：{error}"))?;
    let file = serde_json::from_slice(&bytes).map_err(|_| "保险库格式损坏".to_string())?;
    validate_file(&file)?;
    Ok(file)
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("设置数据目录权限失败：{error}"))
}

#[cfg(not(unix))]
fn secure_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn open_secure_temp(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| format!("创建临时保险库失败：{error}"))
}

pub fn atomic_write(file: &VaultFile) -> Result<(), String> {
    validate_file(file)?;
    let directory = app_dir()?;
    reject_symlink(&directory, "应用数据目录")?;
    fs::create_dir_all(&directory).map_err(|error| format!("创建数据目录失败：{error}"))?;
    secure_directory(&directory)?;
    let path = directory.join("vault.mykeys");
    reject_symlink(&path, "保险库文件")?;
    let suffix = B64.encode(random::<12>()).replace(['/', '+', '='], "");
    let temporary = directory.join(format!(".vault.mykeys.{suffix}.tmp"));
    let bytes = serde_json::to_vec(file).map_err(|_| "序列化失败")?;
    let result = (|| {
        let mut output = open_secure_temp(&temporary)?;
        output
            .write_all(&bytes)
            .map_err(|error| format!("写入临时文件失败：{error}"))?;
        output
            .sync_all()
            .map_err(|error| format!("同步临时文件失败：{error}"))?;
        fs::rename(&temporary, &path).map_err(|error| format!("提交保险库失败：{error}"))?;
        #[cfg(unix)]
        File::open(&directory)
            .and_then(|directory_file| directory_file.sync_all())
            .map_err(|error| format!("同步数据目录失败：{error}"))?;
        Ok::<(), String>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn acquire_file_lock() -> Result<File, String> {
    let directory = app_dir()?;
    reject_symlink(&directory, "应用数据目录")?;
    fs::create_dir_all(&directory).map_err(|error| format!("创建数据目录失败：{error}"))?;
    secure_directory(&directory)?;
    let path = directory.join(".vault.lock");
    reject_symlink(&path, "保险库锁文件")?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options
        .open(path)
        .map_err(|error| format!("打开保险库锁失败：{error}"))?;
    lock.lock_exclusive()
        .map_err(|error| format!("锁定保险库失败：{error}"))?;
    Ok(lock)
}

pub fn unwrap_dek(file: &VaultFile, password: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let salt = decode_limited(&file.salt, 16, "salt")?;
    let spec = file.kdf.clone().unwrap_or_default();
    let kek = kdf(password, &salt, &spec)?;
    let nonce = decode_limited(&file.wrap_nonce, 24, "包装 nonce")?;
    let cipher = decode_limited(&file.wrapped_dek, 48, "包装密文")?;
    let plain = decrypt(&kek, &nonce, &cipher, &wrap_aad(file)?)
        .map_err(|_| "主密码错误或保险库已损坏".to_string())?;
    if plain.len() != 32 {
        return Err("数据密钥长度无效".into());
    }
    Ok(plain)
}

pub fn read_data(file: &VaultFile, dek: &[u8]) -> Result<VaultData, String> {
    let nonce = decode_limited(&file.data_nonce, 24, "数据 nonce")?;
    let cipher = decode_limited(&file.ciphertext, MAX_PLAIN_BYTES + 16, "数据密文")?;
    let plain = decrypt(dek, &nonce, &cipher, &data_aad(file)?)?;
    if plain.len() > MAX_PLAIN_BYTES {
        return Err("保险库明文超过大小限制".into());
    }
    let data = serde_json::from_slice(&plain).map_err(|_| "保险库数据损坏".to_string())?;
    validate_data(&data)?;
    Ok(data)
}

pub fn persist(file: &mut VaultFile, dek: &[u8], data: &VaultData) -> Result<(), String> {
    validate_data(data)?;
    let plain = Zeroizing::new(serde_json::to_vec(data).map_err(|_| "序列化失败")?);
    if plain.len() > MAX_PLAIN_BYTES {
        return Err("保险库明文超过大小限制".into());
    }
    let nonce = random::<24>();
    file.data_nonce = B64.encode(nonce);
    file.ciphertext = B64.encode(encrypt(dek, &nonce, &plain, &data_aad(file)?)?);
    atomic_write(file)
}

pub fn create_file(
    password: &str,
    data: &VaultData,
) -> Result<(VaultFile, Zeroizing<Vec<u8>>), String> {
    let salt = random::<16>();
    let wrap_nonce = random::<24>();
    let data_nonce = random::<24>();
    let dek = Zeroizing::new(random::<32>().to_vec());
    let plain = Zeroizing::new(serde_json::to_vec(data).map_err(|_| "序列化失败")?);
    let mut file = VaultFile {
        version: FORMAT_VERSION,
        vault_id: Some(B64.encode(random::<18>()).replace(['/', '+', '='], "")),
        kdf: Some(KdfSpec::default()),
        salt: B64.encode(salt),
        wrap_nonce: B64.encode(wrap_nonce),
        wrapped_dek: String::new(),
        data_nonce: B64.encode(data_nonce),
        ciphertext: String::new(),
    };
    let kek = kdf(password, &salt, file.kdf.as_ref().expect("KDF initialized"))?;
    file.wrapped_dek = B64.encode(encrypt(&kek, &wrap_nonce, &dek, &wrap_aad(&file)?)?);
    file.ciphertext = B64.encode(encrypt(&dek, &data_nonce, &plain, &data_aad(&file)?)?);
    Ok((file, dek))
}

pub fn rewrap(file: &mut VaultFile, dek: &[u8], password: &str) -> Result<(), String> {
    if file.version == LEGACY_VERSION {
        file.version = FORMAT_VERSION;
        file.vault_id = Some(B64.encode(random::<18>()).replace(['/', '+', '='], ""));
        file.kdf = Some(KdfSpec::default());
    }
    let salt = random::<16>();
    let nonce = random::<24>();
    file.salt = B64.encode(salt);
    file.wrap_nonce = B64.encode(nonce);
    let spec = file.kdf.as_ref().ok_or("保险库缺少 KDF 参数")?;
    let kek = kdf(password, &salt, spec)?;
    file.wrapped_dek = B64.encode(encrypt(&kek, &nonce, dek, &wrap_aad(file)?)?);
    Ok(())
}

pub fn migrate_v1(
    file: &mut VaultFile,
    dek: &[u8],
    password: &str,
    data: &VaultData,
) -> Result<(), String> {
    if file.version == LEGACY_VERSION {
        rewrap(file, dek, password)?;
        persist(file, dek, data)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (VaultFile, Zeroizing<Vec<u8>>, VaultData) {
        let data = VaultData {
            records: vec![KeyRecord {
                id: "test-id".into(),
                name: "normal".into(),
                provider: "OpenAI".into(),
                secret: "sk-audit-not-real".into(),
                expires_at: None,
                permissions: None,
                notes: None,
                created_at: 1,
                updated_at: 1,
            }],
            unlock_mode: UnlockMode::EveryLaunch,
            retrieve_auth: true,
        };
        let (file, dek) = create_file("correct horse battery staple", &data).unwrap();
        (file, dek, data)
    }

    #[test]
    fn round_trip_and_wrong_password() {
        let (file, _, _) = fixture();
        assert!(unwrap_dek(&file, "incorrect-password-value").is_err());
        let dek = unwrap_dek(&file, "correct horse battery staple").unwrap();
        assert_eq!(
            read_data(&file, &dek).unwrap().records[0].secret,
            "sk-audit-not-real"
        );
    }

    #[test]
    fn header_and_ciphertext_tampering_fails() {
        let (mut file, dek, _) = fixture();
        let original_id = file.vault_id.clone();
        file.vault_id = Some("attacker".into());
        assert!(unwrap_dek(&file, "correct horse battery staple").is_err());
        file.vault_id = original_id;
        let mut ciphertext = B64.decode(&file.ciphertext).unwrap();
        ciphertext[0] ^= 1;
        file.ciphertext = B64.encode(ciphertext);
        assert!(read_data(&file, &dek).is_err());
    }

    #[test]
    fn rejects_unknown_version_and_oversized_input() {
        let (mut file, _, mut data) = fixture();
        file.version = 99;
        assert!(validate_file(&file).is_err());
        data.records[0].name = "x".repeat(MAX_NAME_BYTES + 1);
        assert!(validate_data(&data).is_err());
    }

    #[test]
    fn password_policy_rejects_short_and_common_passwords() {
        assert!(validate_password("abc123456789").is_err());
        assert!(validate_password("password-very-long").is_err());
        assert!(validate_password("correct horse battery staple").is_ok());
    }

    #[test]
    fn legacy_v1_vault_remains_readable_before_migration() {
        let password = "legacy master password";
        let salt = random::<16>();
        let wrap_nonce = random::<24>();
        let data_nonce = random::<24>();
        let dek = Zeroizing::new(random::<32>().to_vec());
        let data = VaultData {
            records: vec![],
            unlock_mode: UnlockMode::EveryLaunch,
            retrieve_auth: true,
        };
        let plain = Zeroizing::new(serde_json::to_vec(&data).unwrap());
        let kek = kdf(password, &salt, &KdfSpec::default()).unwrap();
        let file = VaultFile {
            version: LEGACY_VERSION,
            vault_id: None,
            kdf: None,
            salt: B64.encode(salt),
            wrap_nonce: B64.encode(wrap_nonce),
            wrapped_dek: B64.encode(encrypt(&kek, &wrap_nonce, &dek, AAD_WRAP_V1).unwrap()),
            data_nonce: B64.encode(data_nonce),
            ciphertext: B64.encode(encrypt(&dek, &data_nonce, &plain, AAD_DATA_V1).unwrap()),
        };
        let recovered = unwrap_dek(&file, password).unwrap();
        assert_eq!(*recovered, *dek);
        assert_eq!(read_data(&file, &recovered).unwrap().records.len(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn secure_temp_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "mykeys-permission-test-{}",
            B64.encode(random::<12>()).replace(['/', '+', '='], "")
        ));
        let file = open_secure_temp(&path).unwrap();
        let mode = file.metadata().unwrap().permissions().mode() & 0o777;
        drop(file);
        fs::remove_file(path).unwrap();
        assert_eq!(mode, 0o600);
    }
}
