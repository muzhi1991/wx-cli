//! Offline Linux image-key derivation from kvcomm filenames. No process access.
use super::{
    attach_root_for_db_dir, find_v2_template_ciphertexts, verify_aes_key, ImageKeyMaterial,
    ImageKeyProvider,
};
use anyhow::{bail, Context, Result};
pub struct LinuxImageKeyProvider;
impl ImageKeyProvider for LinuxImageKeyProvider {
    fn get_key(&self, wxid: &str) -> Result<ImageKeyMaterial> {
        let db = crate::config::load_config()?.db_dir;
        let templates = find_v2_template_ciphertexts(&attach_root_for_db_dir(&db), 3, 64)?;
        if templates.is_empty() {
            bail!("no local V2 image template");
        }
        let mut ids = vec![wxid.to_owned()];
        if let Some((bare, suffix)) = wxid.rsplit_once('_') {
            if suffix.len() == 4 && suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
                ids.push(bare.to_owned());
            }
        }
        let mut dirs = Vec::new();
        if let Some(explicit) = std::env::var_os("WX_IMAGE_KVCOMM_DIR") {
            dirs.push(std::path::PathBuf::from(explicit));
        }
        for ancestor in db.ancestors().take(6) {
            dirs.push(ancestor.join(".xwechat/net/kvcomm"));
        }
        if let Some(home) = dirs::home_dir() {
            dirs.push(home.join(".xwechat/net/kvcomm"));
        }
        let mut codes = std::collections::BTreeSet::new();
        for dir in dirs {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten().take(4096) {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !name.ends_with(".statistic") {
                    continue;
                }
                let Some(rest) = name.strip_prefix("key_") else {
                    continue;
                };
                let Some((value, _)) = rest.split_once('_') else {
                    continue;
                };
                if let Ok(code) = value.parse::<u32>() {
                    if code > 0 {
                        codes.insert(code);
                    }
                }
            }
        }
        for id in ids {
            for code in &codes {
                let digest = format!("{:x}", md5::compute(format!("{code}{id}")));
                let aes_key = digest.as_bytes()[..16]
                    .try_into()
                    .context("invalid derived image key")?;
                if verify_aes_key(&aes_key, &templates) {
                    return Ok(ImageKeyMaterial {
                        aes_key,
                        xor_key: (code & 255) as u8,
                    });
                }
            }
        }
        bail!("no kvcomm-derived image key matched local V2 data")
    }
}
