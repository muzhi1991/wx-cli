//! Minimal in-place key maintenance for the current account configuration.
use crate::{config::Config, crypto, scanner::KeyEntry};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_DATABASES: usize = 4096;
const MAX_KEY_FILE: u64 = 16 * 1024 * 1024;

pub fn status(json_output: bool) -> Result<()> {
    let cfg = crate::config::load_config()?;
    let source = KeyFile::read(&cfg.keys_file)?;
    let report = inspect(&cfg.db_dir, &source.document)?;
    super::output::print_value(&report.json(), &super::output::resolve(json_output))
}
pub fn refresh(database: Option<String>, json_output: bool) -> Result<()> {
    let cfg = crate::config::load_config()?;
    let result = refresh_with(
        &cfg,
        database.as_deref(),
        crate::scanner::scan_keys_for_databases,
        super::transport::stop_daemon,
    )?;
    super::output::print_value(&result, &super::output::resolve(json_output))
}

struct KeyFile {
    path: PathBuf,
    bytes: Vec<u8>,
    stamp: u64,
    document: Value,
    #[cfg(unix)]
    owner: (u32, u32),
}
impl KeyFile {
    fn read(path: &Path) -> Result<Self> {
        let name = path
            .file_name()
            .context("keys_file must name a regular file")?;
        let parent = fs::canonicalize(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        let path = parent.join(name);
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.file_type().is_file(),
            "keys_file must be a regular file, not a symlink"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(metadata.nlink() == 1, "keys_file must not have hard links");
        }
        let mut file = File::open(&path)?;
        ensure!(
            metadata.len() <= MAX_KEY_FILE,
            "keys_file exceeds size limit"
        );
        let stamp = crypto::source_stamp(&metadata);
        ensure!(
            crypto::source_stamp(&file.metadata()?) == stamp,
            "keys_file changed while opening"
        );
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_KEY_FILE + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_KEY_FILE,
            "keys_file exceeds size limit"
        );
        ensure!(
            crypto::source_stamp(&file.metadata()?) == stamp
                && crypto::source_stamp(&fs::symlink_metadata(&path)?) == stamp,
            "keys_file changed while reading"
        );
        let document = serde_json::from_slice(&bytes).context("invalid keys_file JSON")?;
        key_entries(&document)?;
        Ok(Self {
            path,
            bytes,
            stamp,
            document,
            #[cfg(unix)]
            owner: {
                use std::os::unix::fs::MetadataExt;
                (metadata.uid(), metadata.gid())
            },
        })
    }
    fn unchanged(&self) -> Result<()> {
        let current = Self::read(&self.path)?;
        ensure!(
            current.stamp == self.stamp && current.bytes == self.bytes,
            "keys_file changed concurrently; no update saved"
        );
        Ok(())
    }
}
fn relative_database(path: &str) -> Result<String> {
    let normalized = path.replace('\\', "/");
    ensure!(
        !normalized.is_empty()
            && normalized.ends_with(".db")
            && !normalized.contains(':')
            && normalized
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && !Path::new(&normalized).is_absolute(),
        "invalid database relative path"
    );
    Ok(normalized)
}
/// Returns only path/index metadata. Key values never enter reports or errors.
fn key_entries(document: &Value) -> Result<BTreeMap<String, String>> {
    let object = document
        .as_object()
        .context("keys_file must contain a JSON object")?;
    let mut entries = BTreeMap::new();
    if let Some(version) = object.get("schema_version") {
        ensure!(version == 1, "unsupported key vault schema");
        let rows = document["databases"]
            .as_array()
            .context("vault databases must be an array")?;
        for (index, row) in rows.iter().enumerate() {
            let name = row["database"]
                .as_str()
                .context("vault entry needs a database path")?;
            let rel = relative_database(name)?;
            ensure!(
                entries.insert(rel, index.to_string()).is_none(),
                "duplicate database entry"
            );
        }
    } else {
        for name in object.keys().filter(|name| name.ends_with(".db")) {
            let rel = relative_database(name)?;
            ensure!(
                entries.insert(rel, name.clone()).is_none(),
                "duplicate normalized database entry"
            );
        }
    }
    Ok(entries)
}
fn entry<'a>(document: &'a Value, locator: &str) -> &'a Value {
    if document.get("schema_version").is_some() {
        &document["databases"][locator.parse::<usize>().unwrap()]
    } else {
        &document[locator]
    }
}
fn key_and_salt(document: &Value, locator: &str) -> Option<([u8; 32], Option<Vec<u8>>)> {
    let value = entry(document, locator);
    let vault = document.get("schema_version").is_some();
    let raw = if vault {
        value["raw_key_hex"].as_str()
    } else {
        value.as_str().or_else(|| value["enc_key"].as_str())
    }?;
    let key = crate::daemon::cache::hex_to_32bytes(raw).ok()?;
    let salt = if vault {
        let text = value["salt_hex"].as_str()?;
        if text.len() != 32 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Some(
            (0..32)
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                .collect(),
        )
    } else {
        None
    };
    Some((key, salt))
}
fn inventory(root: &Path) -> Result<(PathBuf, Vec<String>)> {
    let root = fs::canonicalize(root)?;
    ensure!(root.is_dir(), "db_dir must be a directory");
    let mut pending = vec![(root.clone(), 0usize)];
    let mut names = Vec::new();
    while let Some((dir, depth)) = pending.pop() {
        ensure!(depth <= 16, "database directory depth exceeded");
        for item in fs::read_dir(dir)? {
            let item = item?;
            let typ = item.file_type()?;
            ensure!(!typ.is_symlink(), "database inventory contains a symlink");
            if typ.is_dir() {
                pending.push((item.path(), depth + 1));
            } else if item.path().extension().is_some_and(|x| x == "db") {
                ensure!(typ.is_file(), "database must be a regular file");
                let rel = item
                    .path()
                    .strip_prefix(&root)?
                    .to_string_lossy()
                    .replace('\\', "/");
                names.push(relative_database(&rel)?);
                ensure!(names.len() <= MAX_DATABASES, "too many databases");
            }
        }
    }
    names.sort();
    Ok((root, names))
}
fn page(root: &Path, rel: &str) -> Result<[u8; 4096]> {
    let path = root.join(rel);
    ensure!(
        fs::canonicalize(&path)? == path,
        "database path contains a symlink or changed"
    );
    let before = fs::symlink_metadata(&path)?;
    ensure!(
        before.file_type().is_file(),
        "database path changed or is not a regular file"
    );
    let mut file = File::open(&path)?;
    let stamp = crypto::source_stamp(&before);
    ensure!(
        crypto::source_stamp(&file.metadata()?) == stamp,
        "database changed while opening"
    );
    let mut page = [0u8; 4096];
    file.read_exact(&mut page)
        .with_context(|| format!("cannot read database first page: {rel}"))?;
    ensure!(
        crypto::source_stamp(&file.metadata()?) == stamp
            && crypto::source_stamp(&fs::symlink_metadata(&path)?) == stamp,
        "database changed while reading; retry status after it stabilizes"
    );
    ensure!(
        &page[..16] != crypto::SQLITE_HDR,
        "plaintext SQLite database is unsupported by key maintenance; no scan performed: {rel}"
    );
    Ok(page)
}
fn authenticated(page: &[u8; 4096], key: &[u8; 32], salt: Option<&[u8]>) -> bool {
    salt.is_none_or(|salt| salt == &page[..16])
        && crypto::authenticated_page(key, &crypto::hmac_key(key, &page[..16]), page, 1).is_ok()
}
struct Report {
    root: PathBuf,
    names: Vec<String>,
    valid: usize,
    missing: Vec<String>,
    invalid: Vec<String>,
}
impl Report {
    fn json(&self) -> Value {
        json!({"databases":self.names.len(),"valid":self.valid,"missing":self.missing,"invalid":self.invalid})
    }
    fn targets(&self, selected: Option<&str>) -> Result<Vec<String>> {
        if let Some(selected) = selected {
            let target = relative_database(selected)?;
            ensure!(
                self.names.contains(&target),
                "selected database does not exist in db_dir"
            );
            return Ok(
                if self.missing.contains(&target) || self.invalid.contains(&target) {
                    vec![target]
                } else {
                    vec![]
                },
            );
        }
        let mut targets = self.missing.clone();
        targets.extend(self.invalid.clone());
        targets.sort();
        Ok(targets)
    }
}
fn inspect(db_dir: &Path, document: &Value) -> Result<Report> {
    let entries = key_entries(document)?;
    let (root, names) = inventory(db_dir)?;
    let mut report = Report {
        root,
        names,
        valid: 0,
        missing: vec![],
        invalid: vec![],
    };
    for name in &report.names {
        let page = page(&report.root, name)?;
        let Some(locator) = entries.get(name) else {
            report.missing.push(name.clone());
            continue;
        };
        if key_and_salt(document, locator)
            .is_some_and(|(key, salt)| authenticated(&page, &key, salt.as_deref()))
        {
            report.valid += 1;
        } else {
            report.invalid.push(name.clone());
        }
    }
    Ok(report)
}

struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn private_new(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
fn private_owned(path: &Path, source: &KeyFile) -> Result<File> {
    let file = private_new(path)?;
    #[cfg(unix)]
    {
        use std::os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, PermissionsExt},
        };
        let owned = (|| -> Result<()> {
            // Set mode while we still own the new file; changing ownership first
            // would unnecessarily require CAP_FOWNER for an elevated refresh.
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            let metadata = file.metadata()?;
            if (metadata.uid(), metadata.gid()) != source.owner {
                ensure!(
                    unsafe { libc::fchown(file.as_raw_fd(), source.owner.0, source.owner.1) } == 0,
                    "cannot preserve keys_file ownership; no update saved"
                );
            }
            let metadata = file.metadata()?;
            ensure!(
                (metadata.uid(), metadata.gid()) == source.owner,
                "cannot preserve keys_file ownership; no update saved"
            );
            Ok(())
        })();
        if let Err(error) = owned {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(error);
        }
    }
    #[cfg(not(unix))]
    let _ = source;
    Ok(file)
}
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}
fn save(source: &KeyFile, document: &Value) -> Result<(PathBuf, bool)> {
    source.unchanged()?;
    let tag = format!(
        ".{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    );
    let backup = sibling(&source.path, &format!(".backup{tag}"));
    let mut old = private_owned(&backup, source)?;
    old.write_all(&source.bytes)?;
    old.sync_all()?;
    drop(old);
    let temp = Temporary(sibling(&source.path, &format!(".partial{tag}")));
    let mut file = private_owned(&temp.0, source)?;
    file.write_all(&serde_json::to_vec_pretty(document)?)?;
    file.sync_all()?;
    drop(file);
    source.unchanged()?;
    fs::rename(&temp.0, &source.path)?;
    let synced = File::open(source.path.parent().unwrap())
        .and_then(|dir| dir.sync_all())
        .is_ok();
    Ok((backup, synced))
}
fn merge(document: &Value, entries: &[KeyEntry]) -> Result<Value> {
    let mut result = document.clone();
    let locators = key_entries(document)?;
    let vault = document.get("schema_version").is_some();
    let strings = !vault
        && locators
            .values()
            .any(|loc| entry(document, loc).is_string())
        && locators
            .values()
            .all(|loc| entry(document, loc).is_string());
    for key in entries {
        if vault {
            let rows = result["databases"].as_array_mut().unwrap();
            let index = if let Some(index) = locators.get(&key.db_name) {
                index.parse::<usize>()?
            } else {
                rows.push(json!({"database":key.db_name}));
                rows.len() - 1
            };
            let row = rows[index]
                .as_object_mut()
                .context("vault entry must be an object")?;
            row.insert("raw_key_hex".into(), json!(key.enc_key));
            row.insert("salt_hex".into(), json!(key.salt));
            row.insert(
                "validated_at".into(),
                json!(chrono::Utc::now().to_rfc3339()),
            );
        } else {
            let name = locators.get(&key.db_name).unwrap_or(&key.db_name);
            if result.get(name).is_some_and(Value::is_string)
                || (result.get(name).is_none() && strings)
            {
                result[name] = json!(key.enc_key);
            } else {
                if result.get(name).is_none() {
                    result[name] = json!({});
                }
                let object = result[name]
                    .as_object_mut()
                    .context("cannot preserve unsupported key entry format")?;
                object.insert("enc_key".into(), json!(key.enc_key));
            }
        }
    }
    Ok(result)
}
fn refresh_with(
    cfg: &Config,
    selected: Option<&str>,
    scan: impl FnOnce(&Path, &[String]) -> Result<Vec<KeyEntry>>,
    stop: impl FnOnce() -> Result<()>,
) -> Result<Value> {
    let source = KeyFile::read(&cfg.keys_file)?;
    let mut report = inspect(&cfg.db_dir, &source.document)?;
    let targets = report.targets(selected)?;
    let mut result = report.json();
    result["updated"] = json!([]);
    result["saved"] = json!(false);
    result["scan_performed"] = json!(false);
    if targets.is_empty() {
        result["restart_required"] = json!(false);
        return Ok(result);
    }
    let lock_path = sibling(&source.path, ".lock");
    let mut handle =
        private_new(&lock_path).context("key refresh lock unavailable; no scan performed")?;
    let _lock = Temporary(lock_path);
    writeln!(handle, "{}", std::process::id())?;
    handle.sync_all()?;
    source.unchanged()?;
    let scanned = scan(&report.root, &targets)?;
    let mut verified = Vec::new();
    let mut seen = BTreeSet::new();
    for key in scanned {
        if !targets.contains(&key.db_name) {
            continue;
        }
        ensure!(
            seen.insert(key.db_name.clone()),
            "scanner returned duplicate target"
        );
        let bytes = crate::daemon::cache::hex_to_32bytes(&key.enc_key)?;
        let first = page(&report.root, &key.db_name)?;
        ensure!(
            authenticated(&first, &bytes, None),
            "target key authentication failed; no update saved"
        );
        let salt = first[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        ensure!(
            key.salt.eq_ignore_ascii_case(&salt),
            "target salt mismatch; no update saved"
        );
        verified.push(key);
    }
    ensure!(
        verified.len() == targets.len(),
        "scan did not authenticate every target; no update saved"
    );
    let document = merge(&source.document, &verified)?;
    let (backup, synced) = save(&source, &document)?;
    report.valid += targets.len();
    report.missing.retain(|x| !targets.contains(x));
    report.invalid.retain(|x| !targets.contains(x));
    result = report.json();
    result["updated"] = json!(targets);
    result["saved"] = json!(true);
    result["scan_performed"] = json!(true);
    result["backup_file"] = json!(backup);
    result["directory_synced"] = json!(synced);
    let stopped = stop().is_ok();
    result["daemon_stopped"] = json!(stopped);
    result["restart_required"] = json!(!stopped);
    if !stopped {
        result["warning"] =
            json!("keys saved; daemon stop failed; restart wx daemon before querying");
    }
    if !synced {
        result["durability_warning"] = json!("keys saved; directory sync failed");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Fixture {
        root: PathBuf,
        cfg: Config,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "wx-keys-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            let db = root.join("db");
            fs::create_dir(&db).unwrap();
            let cfg = Config {
                db_dir: db,
                keys_file: root.join("keys.json"),
                decrypted_dir: root.join("plain"),
                wechat_process: String::new(),
            };
            Self { root, cfg }
        }
        fn database(&self, name: &str) -> KeyEntry {
            let path = self.cfg.db_dir.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            crypto::encrypted_test_database(&path, "CREATE TABLE sample(value TEXT);", &[7; 32]);
            KeyEntry {
                db_name: name.into(),
                enc_key: "07".repeat(32),
                salt: "42".repeat(16),
            }
        }
        fn write(&self, value: Value) -> Vec<u8> {
            let bytes = serde_json::to_vec_pretty(&value).unwrap();
            fs::write(&self.cfg.keys_file, &bytes).unwrap();
            bytes
        }
        fn document(&self) -> Value {
            serde_json::from_slice(&fs::read(&self.cfg.keys_file).unwrap()).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    fn no_scan(_: &Path, _: &[String]) -> Result<Vec<KeyEntry>> {
        panic!("scanner must not be called")
    }
    fn no_stop() -> Result<()> {
        panic!("daemon must not be stopped")
    }
    #[test]
    fn status_counts_valid_missing_and_invalid_without_secrets() {
        let f = Fixture::new();
        let a = f.database("a.db");
        f.database("b.db");
        f.database("c.db");
        f.write(json!({"a.db":a.enc_key,"c.db":{"enc_key":"bad"},"_metadata":{"keep":true}}));
        let r = inspect(&f.cfg.db_dir, &f.document()).unwrap().json();
        assert_eq!(
            r,
            json!({"databases":3,"valid":1,"missing":["b.db"],"invalid":["c.db"]})
        );
        assert!(!r.to_string().contains(&"07".repeat(32)));
    }
    #[test]
    fn valid_noop_and_valid_target_do_not_scan_write_or_stop() {
        let f = Fixture::new();
        let a = f.database("a.db");
        let original = f.write(json!({"a.db":a.enc_key}));
        let r = refresh_with(&f.cfg, None, no_scan, no_stop).unwrap();
        assert_eq!(r["saved"], false);
        assert_eq!(r["scan_performed"], false);
        f.database("b.db");
        let r = refresh_with(&f.cfg, Some("a.db"), no_scan, no_stop).unwrap();
        assert_eq!(r["missing"], json!(["b.db"]));
        assert_eq!(fs::read(&f.cfg.keys_file).unwrap(), original);
        assert!(!sibling(&f.cfg.keys_file, ".lock").exists());
    }
    #[test]
    fn target_filter_preserves_other_entries_and_backup_is_exact() {
        let f = Fixture::new();
        let a = f.database("a.db");
        let b = f.database("b.db");
        let original=f.write(json!({"a.db":{"enc_key":"invalid","custom":[1,2]},"_note":{"preserved":true},"historical.db":{"enc_key":"untouched","nested":{"x":1}}}));
        let r = refresh_with(
            &f.cfg,
            Some("b.db"),
            |_, targets| {
                assert_eq!(targets, &["b.db"]);
                Ok(vec![a, b])
            },
            || Ok(()),
        )
        .unwrap();
        assert_eq!(r["updated"], json!(["b.db"]));
        assert_eq!(r["invalid"], json!(["a.db"]));
        assert_eq!(r["saved"], true);
        let old: Value = serde_json::from_slice(&original).unwrap();
        let updated = f.document();
        for name in ["a.db", "_note", "historical.db"] {
            assert_eq!(updated[name], old[name]);
        }
        let backup = PathBuf::from(r["backup_file"].as_str().unwrap());
        assert_eq!(fs::read(&backup).unwrap(), original);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            for p in [&backup, &f.cfg.keys_file] {
                let m = fs::metadata(p).unwrap();
                assert_eq!(m.mode() & 0o777, 0o600);
                assert_eq!(m.uid(), unsafe { libc::geteuid() });
            }
        }
        assert_eq!(r["directory_synced"], true);
    }
    #[test]
    fn string_object_and_vault_formats_preserve_unknown_fields() {
        for kind in 0..3 {
            let f = Fixture::new();
            let a = f.database("a.db");
            let b = f.database("b.db");
            let original = match kind {
                0 => json!({"a.db":"bad","_metadata":{"token":"synthetic"}}),
                1 => json!({"a.db":{"enc_key":"bad","custom":{"keep":true}},"_metadata":[1,2]}),
                _ => {
                    json!({"schema_version":1,"profile":{"keep":true},"databases":[{"database":"a.db","raw_key_hex":"bad","salt_hex":"bad","custom":{"keep":true}},{"database":"old.db","raw_key_hex":"unchanged","note":42}]})
                }
            };
            f.write(original.clone());
            refresh_with(
                &f.cfg,
                None,
                |_, targets| {
                    assert_eq!(targets, &["a.db", "b.db"]);
                    Ok(vec![a, b])
                },
                || Ok(()),
            )
            .unwrap();
            let updated = f.document();
            if kind == 0 {
                assert!(updated["a.db"].is_string() && updated["b.db"].is_string());
                assert_eq!(updated["_metadata"], original["_metadata"]);
            }
            if kind == 1 {
                assert!(updated["b.db"].is_object());
                assert_eq!(updated["a.db"]["custom"], original["a.db"]["custom"]);
                assert_eq!(updated["_metadata"], original["_metadata"]);
            }
            if kind == 2 {
                assert_eq!(updated["profile"], original["profile"]);
                assert_eq!(
                    updated["databases"][0]["custom"],
                    original["databases"][0]["custom"]
                );
                assert_eq!(updated["databases"][1], original["databases"][1]);
                assert_eq!(updated["databases"].as_array().unwrap().len(), 3);
            }
            assert_eq!(inspect(&f.cfg.db_dir, &updated).unwrap().valid, 2);
        }
    }
    #[test]
    fn failed_missing_duplicate_or_unverified_scan_preserves_original() {
        for mode in 0..4 {
            let f = Fixture::new();
            let a = f.database("a.db");
            let original = f.write(json!({}));
            let result = refresh_with(
                &f.cfg,
                None,
                |_, _| match mode {
                    0 => Err(anyhow::anyhow!("injected scanner failure")),
                    1 => Ok(vec![]),
                    2 => {
                        let mut bad = a.clone();
                        bad.enc_key = "08".repeat(32);
                        Ok(vec![bad])
                    }
                    _ => Ok(vec![a.clone(), a]),
                },
                no_stop,
            );
            assert!(result.is_err());
            assert_eq!(fs::read(&f.cfg.keys_file).unwrap(), original);
            assert!(!sibling(&f.cfg.keys_file, ".lock").exists());
        }
    }
    #[test]
    fn concurrent_change_and_existing_lock_are_never_overwritten() {
        let f = Fixture::new();
        let a = f.database("a.db");
        f.write(json!({}));
        let external = b"{\"_concurrent\":true}";
        assert!(refresh_with(
            &f.cfg,
            None,
            |_, _| {
                fs::write(&f.cfg.keys_file, external)?;
                Ok(vec![a])
            },
            no_stop
        )
        .is_err());
        assert_eq!(fs::read(&f.cfg.keys_file).unwrap(), external);
        let lock = sibling(&f.cfg.keys_file, ".lock");
        fs::write(&lock, b"other owner").unwrap();
        assert!(refresh_with(&f.cfg, None, no_scan, no_stop).is_err());
        assert_eq!(fs::read(lock).unwrap(), b"other owner");
    }
    #[test]
    fn selected_paths_io_and_plaintext_errors_never_trigger_scan() {
        let f = Fixture::new();
        f.database("a.db");
        f.write(json!({}));
        for target in ["../a.db", "/a.db", "a/../a.db", "C:/a.db", "no.db", "a.db/"] {
            assert!(refresh_with(&f.cfg, Some(target), no_scan, no_stop).is_err());
        }
        fs::write(f.cfg.db_dir.join("a.db"), b"partial page").unwrap();
        assert!(refresh_with(&f.cfg, None, no_scan, no_stop).is_err());
        fs::remove_file(f.cfg.db_dir.join("a.db")).unwrap();
        let conn = rusqlite::Connection::open(f.cfg.db_dir.join("plain.db")).unwrap();
        conn.execute_batch("CREATE TABLE t(value TEXT)").unwrap();
        drop(conn);
        assert!(refresh_with(&f.cfg, None, no_scan, no_stop)
            .unwrap_err()
            .to_string()
            .contains("plaintext"));
    }
    #[cfg(unix)]
    #[test]
    fn unsafe_links_and_unpreservable_ownership_leave_original() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new();
        let a = f.database("a.db");
        let original = f.write(json!({}));
        let alias = f.root.join("alias.json");
        symlink(&f.cfg.keys_file, &alias).unwrap();
        assert!(KeyFile::read(&alias).is_err());
        let alias = f.cfg.db_dir.join("alias.db");
        symlink(f.cfg.db_dir.join("a.db"), &alias).unwrap();
        assert!(refresh_with(&f.cfg, None, no_scan, no_stop).is_err());
        fs::remove_file(alias).unwrap();
        let mut source = KeyFile::read(&f.cfg.keys_file).unwrap();
        source.owner = (u32::MAX, u32::MAX);
        assert!(save(&source, &merge(&source.document, &[a]).unwrap()).is_err());
        assert_eq!(fs::read(&f.cfg.keys_file).unwrap(), original);
    }
    #[test]
    fn saved_result_stops_daemon_after_new_keys_are_loadable() {
        for stop_fails in [false, true] {
            let f = Fixture::new();
            let a = f.database("a.db");
            f.write(json!({}));
            let r = refresh_with(
                &f.cfg,
                None,
                |_, _| Ok(vec![a]),
                || {
                    assert_eq!(
                        crate::daemon::load_keys(&f.document(), &f.cfg.db_dir)?.len(),
                        1
                    );
                    if stop_fails {
                        anyhow::bail!("injected stop failure");
                    }
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(r["saved"], true);
            assert_eq!(r["restart_required"], stop_fails);
            assert_eq!(r["daemon_stopped"], !stop_fails);
            if stop_fails {
                assert!(r["warning"].as_str().unwrap().contains("keys saved"));
            }
        }
    }
    #[cfg(unix)]
    #[test]
    #[ignore = "requires root with CHOWN and DAC_OVERRIDE; run separately on synthetic files"]
    fn sudo_refresh_preserves_nonroot_owner() {
        use std::os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, PermissionsExt},
        };
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let f = Fixture::new();
        let a = f.database("a.db");
        f.write(json!({}));
        let file = File::open(&f.cfg.keys_file).unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        assert_eq!(unsafe { libc::fchown(file.as_raw_fd(), 1000, 1000) }, 0);
        drop(file);
        let r = refresh_with(&f.cfg, None, |_, _| Ok(vec![a]), || Ok(())).unwrap();
        for path in [
            &f.cfg.keys_file,
            Path::new(r["backup_file"].as_str().unwrap()),
        ] {
            let metadata = fs::metadata(path).unwrap();
            assert_eq!(
                (metadata.uid(), metadata.gid(), metadata.mode() & 0o777),
                (1000, 1000, 0o600)
            );
        }
    }
}
