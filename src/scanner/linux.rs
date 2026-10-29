//! Read-only, bounded CipherConfig raw-key recovery for the pinned Linux build.
//! Public ELF offsets are a compatibility profile, never account key material.
use super::{collect_db_salts, KeyEntry};
use anyhow::{bail, ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::Read,
    os::unix::fs::FileExt,
    path::Path,
    time::{Duration, Instant},
};
const ELF_HASH: &str = "2749535f299ba67feb8ef80cab898bb0531fa8f376b16f8a72db706811c84132";
const VTABLE: u64 = 0xaa1ab70;
const MASK_VA: u64 = 0x1e2fe00;
const MASK: [u8; 32] = [
    0xd2, 0xc7, 0x44, 0x24, 0x58, 0x02, 0, 0, 0, 0x48, 0x89, 0x44, 0x24, 0x50, 0x48, 0x8b, 0x45, 0,
    0x48, 0x84, 0x4c, 0x24, 0x48, 0x48, 0x89, 0x44, 0x25, 0x40, 0x48, 0x58, 0x4c, 0x24,
];
const BYTE_LIMIT: usize = 1536 * 1024 * 1024;
const CHUNK: usize = 2 * 1024 * 1024;
fn identity(pid: u32) -> Result<(String, std::path::PathBuf)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let rest = stat.rsplit_once(") ").context("invalid process stat")?.1;
    Ok((
        rest.split_whitespace()
            .nth(19)
            .context("missing process start time")?
            .to_owned(),
        fs::read_link(format!("/proc/{pid}/exe"))?,
    ))
}
fn find_pid() -> Result<u32> {
    if let Ok(value) = std::env::var("WX_WECHAT_PID") {
        return Ok(value.parse()?);
    }
    let mut pids = Vec::new();
    for entry in fs::read_dir("/proc")?.flatten() {
        if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
            let comm = fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
            if ["wechat", "weixin"].contains(&comm.trim().to_lowercase().as_str()) {
                pids.push(pid);
            }
        }
    }
    ensure!(
        pids.len() == 1,
        "expected one WeChat process; set WX_WECHAT_PID explicitly"
    );
    Ok(pids[0])
}
fn decode_literal(encoded: &[u8]) -> Option<([u8; 32], String)> {
    let mut decoded: Vec<u8> = encoded
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ MASK[i % 32])
        .collect();
    if decoded.last() == Some(&0) {
        decoded.pop();
    }
    let result = (|| {
        if decoded.len() != 99
            || ![b'x', b'X'].contains(&decoded[0])
            || decoded[1] != b'\''
            || decoded[98] != b'\''
            || !decoded[2..98].iter().all(u8::is_ascii_hexdigit)
        {
            return None;
        }
        let raw = std::str::from_utf8(&decoded[2..66]).ok()?;
        let key = crate::daemon::cache::hex_to_32bytes(raw).ok()?;
        let salt = std::str::from_utf8(&decoded[66..98]).ok()?.to_lowercase();
        Some((key, salt))
    })();
    decoded.fill(0);
    result
}
pub fn scan_keys(db_dir: &Path) -> Result<Vec<KeyEntry>> {
    scan_with_databases(db_dir, collect_db_salts(db_dir))
}
pub fn scan_keys_for_databases(db_dir: &Path, targets: &[String]) -> Result<Vec<KeyEntry>> {
    let root = fs::canonicalize(db_dir)?;
    scan_with_databases(&root, target_databases(&root, targets)?)
}
fn target_databases(root: &Path, targets: &[String]) -> Result<Vec<(String, String)>> {
    let mut databases = Vec::new();
    for target in targets {
        ensure!(
            !target.contains('\\')
                && !target.contains(':')
                && target.ends_with(".db")
                && target
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != ".."),
            "invalid scan target path"
        );
        let path = root.join(target);
        ensure!(
            fs::canonicalize(&path)? == path && fs::symlink_metadata(&path)?.file_type().is_file(),
            "unsafe scan target path"
        );
        let salt = super::read_db_salt(&path).context("cannot read encrypted scan target")?;
        ensure!(
            !databases.iter().any(|(_, name)| name == target),
            "duplicate scan target"
        );
        databases.push((salt, target.clone()));
    }
    Ok(databases)
}
fn scan_with_databases(db_dir: &Path, databases: Vec<(String, String)>) -> Result<Vec<KeyEntry>> {
    ensure!(!databases.is_empty(), "no encrypted databases found");
    let pid = find_pid()?;
    let expected = identity(pid)?;
    if let Ok(start) = std::env::var("WX_WECHAT_STARTTIME") {
        ensure!(start == expected.0, "unexpected WeChat process start time");
    }
    let exe = fs::File::open(format!("/proc/{pid}/exe"))?;
    let mut hash = Sha256::new();
    let mut reader = std::io::BufReader::new(exe);
    let mut buf = [0; 65536];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    ensure!(
        format!("{:x}", hash.finalize()) == ELF_HASH,
        "unsupported Linux WeChat ELF; use an authenticated existing key vault"
    );
    let canonical = fs::canonicalize(db_dir)?;
    let account_open = fs::read_dir(format!("/proc/{pid}/fd"))?
        .flatten()
        .filter_map(|e| fs::read_link(e.path()).ok())
        .any(|p| p.starts_with(&canonical));
    ensure!(
        account_open,
        "selected process has no open database in the requested account"
    );
    let maps = fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let mut regions = Vec::new();
    let mut bases = Vec::new();
    for line in maps.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let Some((a, b)) = fields[0].split_once('-') else {
            continue;
        };
        let (lo, hi) = (u64::from_str_radix(a, 16)?, u64::from_str_radix(b, 16)?);
        if fields[1].starts_with("rw") {
            regions.push((lo, hi));
        }
        if fields.len() == 6 && Path::new(fields[5]) == expected.1 && fields[2] == "00000000" {
            bases.push(lo);
        }
    }
    ensure!(bases.len() == 1, "cannot identify executable mapping");
    let base = bases[0];
    let needle = (base + VTABLE).to_le_bytes();
    let pattern: String = needle.iter().map(|b| format!("\\x{b:02x}")).collect();
    let matcher = regex::bytes::RegexBuilder::new(&pattern)
        .unicode(false)
        .build()?;
    let contains = |address: u64, size: usize| {
        regions.iter().any(|(lo, hi)| {
            address >= *lo
                && address
                    .checked_add(size as u64)
                    .is_some_and(|end| end <= *hi)
        })
    };
    if let Some(claim) = std::env::var_os("WX_SCAN_CLAIM") {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(claim)
            .context("scan claim exists; refusing repeat")?;
        writeln!(file, "pid={pid};starttime={}", expected.0)?;
        file.sync_all()?;
    }
    let mem=fs::File::open(format!("/proc/{pid}/mem")).context("cannot read target memory; use existing keys or an explicitly authorized diagnostic process")?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut bytes = 0usize;
    let mut read = |address: u64, size: usize| -> Result<Vec<u8>> {
        ensure!(
            Instant::now() < deadline && bytes.checked_add(size).is_some_and(|n| n <= BYTE_LIMIT),
            "bounded scan budget exhausted"
        );
        ensure!(
            identity(pid)? == expected,
            "WeChat process identity changed"
        );
        let mut data = vec![0; size];
        mem.read_exact_at(&mut data, address)?;
        bytes += size;
        ensure!(Instant::now() < deadline, "bounded scan time exhausted");
        Ok(data)
    };
    ensure!(
        read(base + MASK_VA, 32)? == MASK,
        "runtime profile mismatch"
    );
    let mut found = HashMap::new();
    let mut objects = 0;
    'regions: for &(lo, hi) in &regions {
        let mut pos = lo;
        let mut tail = Vec::new();
        while pos < hi {
            let n = ((hi - pos) as usize).min(CHUNK);
            let data = read(pos, n)?;
            let tail_len = tail.len();
            tail.extend_from_slice(&data);
            for matched in matcher.find_iter(&tail) {
                let offset = matched.start();
                let address = pos - tail_len as u64 + offset as u64;
                if address % 8 != 0 || !contains(address, 0x1e0) {
                    continue;
                }
                objects += 1;
                ensure!(objects <= 256, "cipher object limit exceeded");
                let obj = read(address, 0x1e0)?;
                let u32at = |i| u32::from_le_bytes(obj[i..i + 4].try_into().unwrap());
                let u64at = |i| u64::from_le_bytes(obj[i..i + 8].try_into().unwrap());
                if obj[..8] != needle || u32at(0x1d8) != 4096 || ![0, 4].contains(&u32at(0x1dc)) {
                    continue;
                }
                let pointer = u64at(0x98);
                let length = u64at(0xa0) as usize;
                if ![99, 100].contains(&length) || !contains(pointer, length) {
                    continue;
                }
                let mut encoded = read(pointer, length)?;
                if let Some((mut key, salt)) = decode_literal(&encoded) {
                    for (db_salt, name) in &databases {
                        if db_salt == &salt
                            && !found.contains_key(name)
                            && crate::crypto::verify_database_key(&db_dir.join(name), &key, None)
                                .is_ok()
                        {
                            found.insert(
                                name.clone(),
                                KeyEntry {
                                    db_name: name.clone(),
                                    enc_key: key.iter().map(|b| format!("{b:02x}")).collect(),
                                    salt: salt.clone(),
                                },
                            );
                        }
                    }
                    key.fill(0);
                }
                encoded.fill(0);
                if found.len() == databases.len() {
                    break 'regions;
                }
            }
            tail = tail[tail.len().saturating_sub(7)..].to_vec();
            pos += n as u64;
        }
    }
    ensure!(
        identity(pid)? == expected,
        "WeChat process identity changed"
    );
    eprintln!(
        "Bounded scan: {} bytes read; {} / {} database keys authenticated",
        bytes,
        found.len(),
        databases.len()
    );
    if found.is_empty() {
        bail!("no authenticated CipherConfig keys found; no retry performed");
    }
    let mut entries: Vec<_> = found.into_values().collect();
    entries.sort_by(|a, b| a.db_name.cmp(&b.db_name));
    Ok(entries)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_inventory_is_exact_and_rejects_path_escape() {
        let root = std::env::temp_dir().join(format!("wx-targets-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        for name in ["a.db", "b.db"] {
            crate::crypto::encrypted_test_database(
                &root.join(name),
                "CREATE TABLE t(x INTEGER);",
                &[7; 32],
            );
        }
        let root = fs::canonicalize(root).unwrap();
        let list = target_databases(&root, &["b.db".into()]).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].1, "b.db");
        assert!(target_databases(&root, &["../a.db".into()]).is_err());
        assert!(target_databases(&root, &["b.db".into(), "b.db".into()]).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn decodes_only_exact_raw_key_literal() {
        let raw = format!("x'{}{}'", "12".repeat(32), "34".repeat(16));
        let encoded: Vec<_> = raw
            .bytes()
            .enumerate()
            .map(|(i, b)| b ^ MASK[i % 32])
            .collect();
        let (key, salt) = decode_literal(&encoded).unwrap();
        assert_eq!(key, [0x12; 32]);
        assert_eq!(salt, "34".repeat(16));
        assert!(decode_literal(&encoded[..98]).is_none());
        let mut wrong = encoded;
        wrong[5] ^= 0xff;
        assert!(decode_literal(&wrong).is_none());
    }
}
