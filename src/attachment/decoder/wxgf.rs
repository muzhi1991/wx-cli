//! Narrow single-part, single-picture WXGF decoder verified on Linux 4.1.13.26.
use anyhow::{ensure, Context, Result};
use std::{
    io::Write,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
const MAX_BYTES: usize = 32 * 1024 * 1024;
pub fn extract(data: &[u8]) -> Result<(&[u8], u16, u16)> {
    ensure!(
        (23..=MAX_BYTES).contains(&data.len()) && data[..7] == *b"wxgf\x13\0\x02",
        "unsupported WXGF header"
    );
    let width = u16::from_be_bytes(data[7..9].try_into()?);
    let height = u16::from_be_bytes(data[9..11].try_into()?);
    ensure!(
        width > 0 && height > 0 && width as u64 * height as u64 <= 20_000_000,
        "WXGF dimension limit"
    );
    let mut candidates = Vec::new();
    for start in 23..data.len().min(4096).saturating_sub(5) {
        if data[start..start + 6] != [0, 0, 0, 1, 0x40, 1] {
            continue;
        }
        let size = u32::from_be_bytes(data[start - 4..start].try_into()?) as usize;
        if size > 0 && size <= data.len() - start {
            candidates.push((start, size));
        }
    }
    ensure!(candidates.len() == 1, "unsupported WXGF partition layout");
    let (start, size) = candidates[0];
    ensure!(
        [0, 24].contains(&(data.len() - start - size)),
        "unsupported WXGF trailing partition"
    );
    let stream = &data[start..start + size];
    let mut nals = Vec::new();
    let mut i = 0;
    while i + 3 < stream.len() {
        let length = if stream[i..].starts_with(&[0, 0, 0, 1]) {
            4
        } else if stream[i..].starts_with(&[0, 0, 1]) {
            3
        } else {
            i += 1;
            continue;
        };
        nals.push((i, i + length));
        i += length;
    }
    ensure!(nals.len() <= 2048, "WXGF NAL limit");
    let mut kinds = Vec::new();
    let mut pictures = 0;
    for (index, &(_, a)) in nals.iter().enumerate() {
        let end = nals.get(index + 1).map(|n| n.0).unwrap_or(stream.len());
        ensure!(
            a + 2 <= end && stream[a] & 0x80 == 0 && stream[a + 1] & 7 != 0,
            "invalid HEVC NAL"
        );
        let kind = (stream[a] >> 1) & 63;
        kinds.push(kind);
        if kind <= 31 {
            ensure!(a + 3 <= end, "truncated slice");
            if stream[a + 2] & 0x80 != 0 {
                pictures += 1;
            }
        }
    }
    ensure!(
        [32, 33, 34].iter().all(|n| kinds.contains(n)) && pictures == 1,
        "WXGF is not one complete HEVC picture"
    );
    Ok((stream, width, height))
}
struct Scratch(std::path::PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
pub fn to_png(data: &[u8]) -> Result<Vec<u8>> {
    let (stream, width, height) = extract(data)?;
    let root = crate::config::cache_dir();
    std::fs::create_dir_all(&root)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let dir = root.join(format!("media-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&dir)?;
    let _scratch = Scratch(dir.clone());
    let input = dir.join("input.hevc");
    std::fs::File::create(&input)?.write_all(stream)?;
    let output = dir.join("output.png");
    let mut child = Command::new("ffmpeg")
        .args([
            "-nostdin",
            "-v",
            "error",
            "-xerror",
            "-err_detect",
            "explode",
            "-threads",
            "1",
            "-max_pixels",
            "20000000",
            "-f",
            "hevc",
            "-i",
        ])
        .arg(&input)
        .args(["-frames:v", "1", "-c:v", "png"])
        .arg(&output)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("WXGF conversion requires ffmpeg on PATH")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait()? {
            ensure!(status.success(), "HEVC decode failed");
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("HEVC decode timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    ensure!(
        std::fs::metadata(&output)?.len() <= 101_000_000,
        "PNG output limit"
    );
    let png = std::fs::read(output)?;
    ensure!(
        png.len() >= 24 && png.starts_with(b"\x89PNG\r\n\x1a\n"),
        "invalid decoded PNG"
    );
    ensure!(
        u32::from_be_bytes(png[16..20].try_into()?) == width as u32
            && u32::from_be_bytes(png[20..24].try_into()?) == height as u32,
        "WXGF dimensions differ from decoded PNG"
    );
    Ok(png)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Vec<u8> {
        let mut d = b"wxgf\x13\0\x02\0\x10\0\x10".to_vec();
        d.resize(38, 0);
        let stream = [
            0, 0, 0, 1, 64, 1, 1, 0, 0, 1, 66, 1, 1, 0, 0, 1, 68, 1, 1, 0, 0, 1, 38, 1, 0x80,
        ];
        d.extend_from_slice(&(stream.len() as u32).to_be_bytes());
        d.extend_from_slice(&stream);
        d.extend_from_slice(&[0; 24]);
        d
    }
    #[test]
    fn only_single_picture_layout() {
        let d = sample();
        assert_eq!(extract(&d).unwrap().1, 16);
        let mut bad = d.clone();
        bad.push(1);
        assert!(extract(&bad).is_err());
        let mut bad = d;
        bad[14..20].copy_from_slice(&[0, 0, 0, 1, 64, 1]);
        assert!(extract(&bad).is_ok());
    }
    #[test]
    fn rejects_unbounded_header_and_truncated_partition() {
        assert!(extract(&[]).is_err());
        let mut d = sample();
        d[38..42].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(extract(&d).is_err());
    }
}
