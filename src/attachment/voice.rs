//! Exact local voice lookup. Listing reads sizes and headers, never whole blobs.
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::daemon::cache::DbCache;

const MAX_BYTES: i64 = 16 * 1024 * 1024;
const MAX_SHARDS: usize = 128;

#[derive(Clone)]
pub struct MessageIdentity {
    pub chat: String,
    pub local_id: i64,
    pub server_id: i64,
    pub create_time: i64,
}

pub struct VoiceLookup {
    pub metadata: Value,
    candidate: Option<Candidate>,
}
struct Candidate {
    path: PathBuf,
    rowid: i64,
    chat_id: i64,
    identity: MessageIdentity,
    size: i64,
    format: &'static str,
}
impl VoiceLookup {
    fn unavailable(status: &str) -> Self {
        Self {
            metadata: json!({"status":status}),
            candidate: None,
        }
    }

    /// Recheck identity and size inside SQL before materializing any audio bytes.
    pub fn export(&self, output: &Path, overwrite: bool) -> Result<Value> {
        let Some(c) = &self.candidate else {
            return Ok(
                json!({"kind":"voice","local_status":self.metadata["status"],"local":self.metadata,"exported":false}),
            );
        };
        let conn = Connection::open_with_flags(&c.path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let bytes: Option<Vec<u8>> = conn
            .query_row(
                "SELECT voice_data FROM VoiceInfo WHERE rowid=?1 AND chat_name_id=?2
             AND local_id=?3 AND svr_id=?4 AND create_time=?5
             AND typeof(voice_data)='blob' AND length(voice_data)=?6
             AND length(voice_data) BETWEEN 1 AND ?7
             AND EXISTS (SELECT 1 FROM Name2Id WHERE rowid=VoiceInfo.chat_name_id AND user_name=?8)
             AND (SELECT COUNT(*) FROM Name2Id WHERE user_name=?8)=1",
                params![
                    c.rowid,
                    c.chat_id,
                    c.identity.local_id,
                    c.identity.server_id,
                    c.identity.create_time,
                    c.size,
                    MAX_BYTES,
                    c.identity.chat
                ],
                |row| row.get(0),
            )
            .optional()?;
        let bytes = bytes.context("local voice changed during export")?;
        anyhow::ensure!(
            audio_format(&bytes, bytes.len() as i64) == Some(c.format),
            "voice header changed during export"
        );
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        write_raw(output, &bytes, overwrite)?;
        Ok(
            json!({"kind":"voice","local_status":"available","exported":true,
            "output":output,"output_size":bytes.len(),"sha256":sha256,
            "format":c.format,"raw_bytes":true,"prefix_preserved":true,"decoded":false,
            "source_database":self.metadata["source_database"]}),
        )
    }
}
fn write_raw(output: &Path, bytes: &[u8], overwrite: bool) -> Result<()> {
    use std::io::Write;
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if overwrite {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    options.open(output)?.write_all(bytes)?;
    Ok(())
}
fn audio_format(header: &[u8], size: i64) -> Option<&'static str> {
    if size > 10 && header.starts_with(b"\x02#!SILK_V3") {
        Some("wechat_silk")
    } else if size > 9 && header.starts_with(b"#!SILK_V3") {
        Some("silk")
    } else {
        None
    }
}
fn media_name(name: &str) -> bool {
    name.strip_prefix("media_")
        .and_then(|s| s.strip_suffix(".db"))
        .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
}

pub async fn lookup(db: &DbCache, identity: &MessageIdentity) -> Result<VoiceLookup> {
    let directory = db.db_dir().join("message");
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(VoiceLookup::unavailable("media_database_missing"))
        }
        Err(e) => return Err(e.into()),
    };
    let mut shards = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !media_name(&name) {
            continue;
        }
        anyhow::ensure!(
            entry.file_type()?.is_file(),
            "media database is not a regular file"
        );
        shards.push(format!("message/{name}"));
        anyhow::ensure!(shards.len() <= MAX_SHARDS, "too many media database shards");
    }
    shards.sort();
    if shards.is_empty() {
        return Ok(VoiceLookup::unavailable("media_database_missing"));
    }
    let mut paths = Vec::new();
    for rel in shards {
        let Some(path) = db.get(&rel).await? else {
            let mut result = VoiceLookup::unavailable("key_unavailable");
            result.metadata["database"] = json!(rel);
            return Ok(result);
        };
        paths.push((rel, path));
    }
    let identity = identity.clone();
    tokio::task::spawn_blocking(move || lookup_paths(&paths, &identity)).await?
}
fn has_columns(conn: &Connection, table: &str, expected: &[&str]) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = stmt
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(expected
        .iter()
        .all(|name| columns.iter().any(|c| c == name)))
}
fn lookup_paths(paths: &[(String, PathBuf)], identity: &MessageIdentity) -> Result<VoiceLookup> {
    let mut found = Vec::new();
    for (rel, path) in paths {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        if !has_columns(&conn, "Name2Id", &["user_name"])?
            || !has_columns(
                &conn,
                "VoiceInfo",
                &[
                    "chat_name_id",
                    "create_time",
                    "local_id",
                    "svr_id",
                    "voice_data",
                    "data_index",
                ],
            )?
        {
            return Ok(VoiceLookup::unavailable("unsupported_media_schema"));
        }
        let ids = conn
            .prepare("SELECT rowid FROM Name2Id WHERE user_name=?1 LIMIT 2")?
            .query_map([&identity.chat], |r| r.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if ids.len() > 1 {
            return Ok(VoiceLookup::unavailable("ambiguous_audio"));
        }
        let Some(chat_id) = ids.first() else {
            continue;
        };
        let mut stmt = conn.prepare("SELECT rowid,typeof(voice_data),length(voice_data),
            CASE WHEN typeof(voice_data)='blob' THEN substr(voice_data,1,10) ELSE NULL END
            FROM VoiceInfo WHERE chat_name_id=?1 AND local_id=?2 AND svr_id=?3 AND create_time=?4 LIMIT 2")?;
        let rows = stmt.query_map(
            params![
                chat_id,
                identity.local_id,
                identity.server_id,
                identity.create_time
            ],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, Option<Vec<u8>>>(3)?,
                ))
            },
        )?;
        for row in rows {
            found.push((rel.clone(), path.clone(), *chat_id, row?));
            if found.len() > 1 {
                return Ok(VoiceLookup::unavailable("ambiguous_audio"));
            }
        }
    }
    let Some((rel, path, chat_id, (rowid, typ, size, header))) = found.pop() else {
        return Ok(VoiceLookup::unavailable("audio_unavailable"));
    };
    let size = size.unwrap_or(0);
    if size == 0 {
        return Ok(VoiceLookup::unavailable("audio_empty"));
    }
    if typ != "blob" {
        return Ok(VoiceLookup::unavailable("unsupported_audio_storage"));
    }
    if size > MAX_BYTES {
        return Ok(VoiceLookup::unavailable("audio_too_large"));
    }
    let Some(format) = audio_format(header.as_deref().unwrap_or_default(), size) else {
        return Ok(VoiceLookup::unavailable("unsupported_audio_format"));
    };
    Ok(VoiceLookup {
        metadata: json!({"status":"available","size":size,"format":format,"raw_bytes":true,
            "prefix_preserved":true,"source_database":rel,"message_identity_matched":true}),
        candidate: Some(Candidate {
            path,
            rowid,
            chat_id,
            identity: identity.clone(),
            size,
            format,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "wx-voice-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn db(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE Name2Id(user_name TEXT); INSERT INTO Name2Id VALUES('chat-a');
                CREATE TABLE VoiceInfo(chat_name_id INTEGER,create_time INTEGER,local_id INTEGER,svr_id INTEGER,voice_data BLOB,data_index TEXT);").unwrap();
            conn.execute(
                "INSERT INTO VoiceInfo VALUES(1,123,7,900,?1,'opaque-index')",
                [raw()],
            )
            .unwrap();
            path
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn raw() -> Vec<u8> {
        b"\x02#!SILK_V3synthetic-payload".to_vec()
    }
    fn identity() -> MessageIdentity {
        MessageIdentity {
            chat: "chat-a".into(),
            local_id: 7,
            server_id: 900,
            create_time: 123,
        }
    }
    fn paths(path: &Path) -> Vec<(String, PathBuf)> {
        vec![("message/media_0.db".into(), path.to_path_buf())]
    }
    fn status(paths: &[(String, PathBuf)], id: &MessageIdentity) -> String {
        lookup_paths(paths, id).unwrap().metadata["status"]
            .as_str()
            .unwrap()
            .into()
    }
    #[test]
    fn exact_identity_requires_chat_local_server_and_time() {
        let fixture = Fixture::new();
        let paths = paths(&fixture.db("media.db"));
        assert_eq!(status(&paths, &identity()), "available");
        for field in 0..4 {
            let mut id = identity();
            match field {
                0 => id.chat = "chat-b".into(),
                1 => id.local_id += 1,
                2 => id.server_id += 1,
                _ => id.create_time += 1,
            }
            assert_eq!(status(&paths, &id), "audio_unavailable");
        }
    }
    #[test]
    fn rejects_duplicate_rows_shards_and_chat_mappings() {
        let fixture = Fixture::new();
        let p = fixture.db("a.db");
        let other = fixture.db("b.db");
        let mut pair = paths(&p);
        pair.push(("message/media_1.db".into(), other));
        assert_eq!(status(&pair, &identity()), "ambiguous_audio");
        let conn = Connection::open(&p).unwrap();
        conn.execute("INSERT INTO VoiceInfo SELECT * FROM VoiceInfo", [])
            .unwrap();
        assert_eq!(status(&paths(&p), &identity()), "ambiguous_audio");
        conn.execute("DELETE FROM VoiceInfo WHERE rowid=2", [])
            .unwrap();
        conn.execute("INSERT INTO Name2Id VALUES('chat-a')", [])
            .unwrap();
        assert_eq!(status(&paths(&p), &identity()), "ambiguous_audio");
    }
    #[test]
    fn schema_absence_is_distinct_from_missing_audio() {
        let fixture = Fixture::new();
        let p = fixture.db("a.db");
        let conn = Connection::open(&p).unwrap();
        conn.execute("DELETE FROM VoiceInfo", []).unwrap();
        assert_eq!(status(&paths(&p), &identity()), "audio_unavailable");
        conn.execute("DROP TABLE VoiceInfo", []).unwrap();
        assert_eq!(status(&paths(&p), &identity()), "unsupported_media_schema");
    }
    #[test]
    fn bounded_metadata_rejects_empty_large_text_and_unknown_headers() {
        let fixture = Fixture::new();
        let p = fixture.db("a.db");
        let conn = Connection::open(&p).unwrap();
        for (expression, expected) in [
            ("NULL", "audio_empty"),
            ("zeroblob(0)", "audio_empty"),
            ("zeroblob(16777217)", "audio_too_large"),
            ("'not a blob'", "unsupported_audio_storage"),
            ("zeroblob(12)", "unsupported_audio_format"),
        ] {
            conn.execute(&format!("UPDATE VoiceInfo SET voice_data={expression}"), [])
                .unwrap();
            assert_eq!(status(&paths(&p), &identity()), expected);
        }
        for bytes in [
            b"\x03#!SILK_V3payload".as_slice(),
            b"\x02#!SILK_V3".as_slice(),
            b"#!SILK_V3".as_slice(),
        ] {
            conn.execute("UPDATE VoiceInfo SET voice_data=?1", [bytes])
                .unwrap();
            assert_eq!(status(&paths(&p), &identity()), "unsupported_audio_format");
        }
    }
    #[test]
    fn raw_export_preserves_prefix_hash_and_overwrite_protection() {
        let fixture = Fixture::new();
        let p = fixture.db("a.db");
        let out = fixture.0.join("voice.silk");
        let found = lookup_paths(&paths(&p), &identity()).unwrap();
        let result = found.export(&out, false).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), raw());
        assert_eq!(result["sha256"], format!("{:x}", Sha256::digest(raw())));
        assert_eq!(result["format"], "wechat_silk");
        assert_eq!(result["decoded"], false);
        assert!(found.export(&out, false).is_err());
        assert_eq!(std::fs::read(&out).unwrap(), raw());
        let conn = Connection::open(p).unwrap();
        let bare = b"#!SILK_V3synthetic-payload";
        conn.execute("UPDATE VoiceInfo SET voice_data=?1", [bare.as_slice()])
            .unwrap();
        let bare_lookup = lookup_paths(
            &paths(&conn.path().map(PathBuf::from).unwrap()),
            &identity(),
        )
        .unwrap();
        assert_eq!(bare_lookup.export(&out, true).unwrap()["format"], "silk");
        assert_eq!(std::fs::read(out).unwrap(), bare);
    }
    #[test]
    fn export_rechecks_mapping_and_blob_bound_before_loading() {
        let fixture = Fixture::new();
        let p = fixture.db("a.db");
        let out = fixture.0.join("voice.silk");
        let found = lookup_paths(&paths(&p), &identity()).unwrap();
        let conn = Connection::open(&p).unwrap();
        conn.execute("UPDATE Name2Id SET user_name='chat-b'", [])
            .unwrap();
        assert!(found.export(&out, false).is_err());
        assert!(!out.exists());
        conn.execute("UPDATE Name2Id SET user_name='chat-a'", [])
            .unwrap();
        conn.execute("INSERT INTO Name2Id VALUES('chat-a')", [])
            .unwrap();
        assert!(found.export(&out, false).is_err());
        assert!(!out.exists());
        conn.execute("DELETE FROM Name2Id WHERE rowid=2", [])
            .unwrap();
        conn.execute("UPDATE VoiceInfo SET voice_data=zeroblob(16777217)", [])
            .unwrap();
        assert!(found.export(&out, false).is_err());
        assert!(!out.exists());
    }
    #[tokio::test]
    async fn missing_database_and_missing_key_have_different_states() {
        let fixture = Fixture::new();
        let db = DbCache::with_dirs(
            fixture.0.clone(),
            fixture.0.join("cache"),
            fixture.0.join("mtimes"),
            Default::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            lookup(&db, &identity()).await.unwrap().metadata["status"],
            "media_database_missing"
        );
        std::fs::create_dir(fixture.0.join("message")).unwrap();
        std::fs::write(
            fixture.0.join("message/media_0.db"),
            b"key absent: do not decrypt",
        )
        .unwrap();
        assert_eq!(
            lookup(&db, &identity()).await.unwrap().metadata["status"],
            "key_unavailable"
        );
    }
}
