use super::output::{emit_warnings, print_response, OutputOpts};
use super::transport;
use crate::ipc::{MessageCursor, Request};
use anyhow::Result;
use std::{collections::HashMap, io::Write, path::PathBuf};

#[derive(serde::Deserialize, serde::Serialize, Default)]
struct State {
    sessions: HashMap<String, i64>,
    #[serde(default)]
    cursors: HashMap<String, MessageCursor>,
}
struct Lock(PathBuf);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub fn cmd_new_messages(limit: usize, explicit: Option<PathBuf>, opts: OutputOpts) -> Result<()> {
    anyhow::ensure!(limit > 0, "limit must be positive");
    let account = std::fs::canonicalize(crate::config::load_config()?.db_dir)?;
    let hash = format!("{:x}", md5::compute(account.to_string_lossy().as_bytes()));
    let path = explicit
        .unwrap_or_else(|| crate::config::cli_dir().join(format!("last_check_{hash}.json")));
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let lock_path = path.with_extension("lock");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .map_err(|_| {
            anyhow::anyhow!(
                "cursor is locked; if its previous reader crashed, remove {}",
                lock_path.display()
            )
        })?;
    let _lock = Lock(lock_path);
    let state = match std::fs::read(&path) {
        Ok(data) => Some(serde_json::from_slice::<State>(&data)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    let (with_meta, debug_source) = opts.request_flags();
    let resp = transport::send(Request::NewMessages {
        state: state.as_ref().map(|s| s.sessions.clone()),
        cursors: state.map(|s| s.cursors).unwrap_or_default(),
        limit,
        with_meta,
        debug_source,
    })?;
    emit_warnings(&resp.data);
    print_response(&resp.data, &opts)?;
    std::io::stdout().flush()?;
    let next = State {
        sessions: serde_json::from_value(resp.data["new_state"].clone())?,
        cursors: serde_json::from_value(resp.data["new_cursors"].clone())?,
    };
    let tmp = path.with_extension("partial");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(&serde_json::to_vec(&next)?)?;
    f.sync_all()?;
    std::fs::rename(tmp, path)?;
    Ok(())
}
