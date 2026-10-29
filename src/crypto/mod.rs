pub mod wal;

use aes::Aes256;
use anyhow::{bail, Result};
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use cbc::Decryptor;
use std::io::{Read, Write};
use std::path::Path;

type Block = aes::cipher::Block<Aes256>;

pub const PAGE_SZ: usize = 4096;
pub const SALT_SZ: usize = 16;
pub const RESERVE_SZ: usize = 80; // IV(16) + HMAC(64)

/// SQLite 文件头魔数（16字节）
pub const SQLITE_HDR: &[u8] = b"SQLite format 3\x00";

type Aes256CbcDec = Decryptor<Aes256>;

/// 解密单个 SQLCipher 4 页
///
/// - `enc_key`: 32字节 AES 密钥
/// - `page_data`: 原始加密页面数据（PAGE_SZ 字节）
/// - `pgno`: 页码（从1开始）
///
/// 返回解密后的完整页面（PAGE_SZ 字节）
pub fn decrypt_page(enc_key: &[u8; 32], page_data: &[u8], pgno: u32) -> Result<Vec<u8>> {
    if page_data.len() < PAGE_SZ {
        bail!("页面数据不足 {} 字节", PAGE_SZ);
    }

    // IV 位于页面末尾 RESERVE_SZ 区域的前16字节
    let iv_offset = PAGE_SZ - RESERVE_SZ;
    let iv: &[u8; 16] = page_data[iv_offset..iv_offset + 16]
        .try_into()
        .expect("IV 长度固定为 16");

    let mut result = vec![0u8; PAGE_SZ];

    if pgno == 1 {
        // 第一页：跳过 salt(16字节)，解密 [SALT_SZ..PAGE_SZ-RESERVE_SZ]
        let enc = &page_data[SALT_SZ..PAGE_SZ - RESERVE_SZ];
        let dec = aes_cbc_decrypt(enc_key, iv, enc)?;
        // 写入 SQLite 文件头
        result[..16].copy_from_slice(SQLITE_HDR);
        // 写入解密数据（从第16字节开始）
        result[16..PAGE_SZ - RESERVE_SZ].copy_from_slice(&dec);
        // 末尾 RESERVE_SZ 字节补零
        // （已经是零，无需显式操作）
    } else {
        // 其他页：解密 [0..PAGE_SZ-RESERVE_SZ]
        let enc = &page_data[..PAGE_SZ - RESERVE_SZ];
        let dec = aes_cbc_decrypt(enc_key, iv, enc)?;
        result[..PAGE_SZ - RESERVE_SZ].copy_from_slice(&dec);
        // 末尾 RESERVE_SZ 字节补零
    }

    Ok(result)
}

/// AES-256-CBC 解密（不去除 padding，SQLCipher 不使用 PKCS#7 padding）
fn aes_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() || data.len() % 16 != 0 {
        bail!("密文长度不是 AES 块大小的倍数: {}", data.len());
    }
    // 将 &[u8] 复制为 Block 数组，避免 unsafe from_raw_parts_mut
    let mut blocks: Vec<Block> = data.chunks_exact(16).map(Block::clone_from_slice).collect();
    Aes256CbcDec::new(key.into(), iv.into()).decrypt_blocks_mut(&mut blocks);
    Ok(blocks.iter().flat_map(|b| b.iter().copied()).collect())
}

/// 完整解密一个 SQLCipher 数据库文件（流式，逐页读写避免全量载入内存）
///
/// 读取 `db_path`，按 PAGE_SZ 分页解密，写入 `out_path`
pub fn hmac_key(key: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    let salt: Vec<u8> = salt.iter().map(|b| b ^ 0x3a).collect();
    let mut out = [0; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(key, &salt, 2, &mut out);
    out
}

/// Authenticate ciphertext, IV and little-endian page number before decrypting.
pub fn authenticated_page(
    key: &[u8; 32],
    mac_key: &[u8; 32],
    page: &[u8],
    pgno: u32,
) -> Result<Vec<u8>> {
    use hmac::{Hmac, Mac};
    if page.len() != PAGE_SZ || pgno == 0 {
        bail!("invalid encrypted page");
    }
    let mut mac = <Hmac<sha2::Sha512> as Mac>::new_from_slice(mac_key)?;
    mac.update(&page[if pgno == 1 { SALT_SZ } else { 0 }..PAGE_SZ - 64]);
    mac.update(&pgno.to_le_bytes());
    mac.verify_slice(&page[PAGE_SZ - 64..])
        .map_err(|_| anyhow::anyhow!("page {} HMAC mismatch", pgno))?;
    let plain = decrypt_page(key, page, pgno)?;
    if pgno == 1 && (plain[16..18] != [0x10, 0] || plain[20] != RESERVE_SZ as u8) {
        bail!("unsupported SQLite cipher profile");
    }
    Ok(plain)
}

pub fn verify_database_key(path: &Path, key: &[u8; 32], salt: Option<&[u8]>) -> Result<()> {
    let mut page = [0; PAGE_SZ];
    std::fs::File::open(path)?.read_exact(&mut page)?;
    if salt.is_some_and(|s| s != &page[..SALT_SZ]) {
        bail!("database salt mismatch");
    }
    authenticated_page(key, &hmac_key(key, &page[..SALT_SZ]), &page, 1)?;
    Ok(())
}

pub fn source_stamp(metadata: &std::fs::Metadata) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    metadata.len().hash(&mut hash);
    metadata.modified().ok().hash(&mut hash);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (
            metadata.dev(),
            metadata.ino(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
            .hash(&mut hash);
    }
    hash.finish()
}

pub fn full_decrypt(db_path: &Path, out_path: &Path, enc_key: &[u8; 32]) -> Result<()> {
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut input = std::fs::File::open(db_path)?;
    let before = input.metadata()?;
    let size = before.len();
    if size == 0 || size % PAGE_SZ as u64 != 0 {
        bail!("empty or partial encrypted database");
    }
    let mut page = [0; PAGE_SZ];
    input.read_exact(&mut page)?;
    let mac_key = hmac_key(enc_key, &page[..SALT_SZ]);
    let first = authenticated_page(enc_key, &mac_key, &page, 1)?;
    let physical = size / PAGE_SZ as u64;
    let declared = u32::from_be_bytes(first[28..32].try_into()?) as u64;
    let valid_count = first[24..28] == first[92..96] && declared > 0 && declared <= physical;
    let logical = if valid_count { declared } else { physical };
    let tmp = out_path.with_extension(format!("partial-{}", std::process::id()));
    let result = (|| -> Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options.open(&tmp)?;
        output.write_all(&first)?;
        for pgno in 2..=physical {
            input.read_exact(&mut page)?;
            if pgno > logical {
                if page.iter().any(|&b| b != 0) {
                    bail!("nonzero data beyond authenticated logical page count");
                }
            } else {
                output.write_all(&authenticated_page(
                    enc_key,
                    &mac_key,
                    &page,
                    u32::try_from(pgno)?,
                )?)?;
            }
        }
        let after = std::fs::metadata(db_path)?;
        if source_stamp(&before) != source_stamp(&after)
            || source_stamp(&before) != source_stamp(&input.metadata()?)
        {
            bail!("database changed during snapshot; retry after checkpoint");
        }
        output.sync_all()?;
        std::fs::rename(&tmp, out_path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
fn read_page(
    input: &mut impl Read,
    page_buf: &mut [u8],
    bytes_remaining: usize,
) -> std::io::Result<usize> {
    let expected = bytes_remaining.min(PAGE_SZ);
    input.read_exact(&mut page_buf[..expected])?;
    if expected < PAGE_SZ {
        page_buf[expected..].fill(0);
    }
    Ok(expected)
}

#[cfg(test)]
mod tests {
    use super::{read_page, PAGE_SZ};
    use std::io::{self, Read};

    struct ChunkedReader {
        chunks: Vec<Vec<u8>>,
        chunk_idx: usize,
        offset: usize,
    }

    impl ChunkedReader {
        fn new(chunks: Vec<Vec<u8>>) -> Self {
            Self {
                chunks,
                chunk_idx: 0,
                offset: 0,
            }
        }
    }

    impl Read for ChunkedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.chunk_idx >= self.chunks.len() {
                return Ok(0);
            }
            let chunk = &self.chunks[self.chunk_idx];
            let remaining = &chunk[self.offset..];
            let n = remaining.len().min(buf.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.offset += n;
            if self.offset == chunk.len() {
                self.chunk_idx += 1;
                self.offset = 0;
            }
            Ok(n)
        }
    }

    #[test]
    fn read_page_reads_across_short_chunks() {
        let mut reader = ChunkedReader::new(vec![vec![1; 32], vec![2; PAGE_SZ - 32]]);
        let mut page_buf = vec![0u8; PAGE_SZ];

        let n = read_page(&mut reader, &mut page_buf, PAGE_SZ).unwrap();

        assert_eq!(n, PAGE_SZ);
        assert_eq!(page_buf[0], 1);
        assert_eq!(page_buf[31], 1);
        assert_eq!(page_buf[32], 2);
        assert_eq!(page_buf[PAGE_SZ - 1], 2);
    }

    #[test]
    fn read_page_zero_pads_last_partial_page() {
        let mut reader = ChunkedReader::new(vec![vec![7; 8], vec![9; 4]]);
        let mut page_buf = vec![0u8; PAGE_SZ];

        let n = read_page(&mut reader, &mut page_buf, 12).unwrap();

        assert_eq!(n, 12);
        assert_eq!(&page_buf[..8], &[7; 8]);
        assert_eq!(&page_buf[8..12], &[9; 4]);
        assert!(page_buf[12..].iter().all(|&b| b == 0));
    }

    #[test]
    fn read_page_errors_on_early_eof() {
        let mut reader = ChunkedReader::new(vec![vec![1; 8]]);
        let mut page_buf = vec![0u8; PAGE_SZ];

        let err = read_page(&mut reader, &mut page_buf, 16).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}

#[cfg(test)]
pub(crate) fn encrypt_test_pages(plain: &[u8], key: &[u8; 32]) -> Vec<u8> {
    use aes::cipher::BlockEncryptMut;
    use hmac::{Hmac, Mac};
    let salt = [0x42u8; 16];
    let mac_key = hmac_key(key, &salt);
    let mut result = Vec::new();
    for (index, p) in plain.chunks_exact(PAGE_SZ).enumerate() {
        let pgno = index as u32 + 1;
        let begin = if pgno == 1 { 16 } else { 0 };
        let end = PAGE_SZ - RESERVE_SZ;
        let iv = [0x24u8; 16];
        let mut page = vec![0; PAGE_SZ];
        if pgno == 1 {
            page[..16].copy_from_slice(&salt);
        }
        let mut blocks: Vec<Block> = p[begin..end]
            .chunks_exact(16)
            .map(Block::clone_from_slice)
            .collect();
        cbc::Encryptor::<Aes256>::new(key.into(), (&iv).into()).encrypt_blocks_mut(&mut blocks);
        for (i, block) in blocks.iter().enumerate() {
            page[begin + i * 16..begin + (i + 1) * 16].copy_from_slice(block);
        }
        page[end..end + 16].copy_from_slice(&iv);
        let mut mac = <Hmac<sha2::Sha512> as Mac>::new_from_slice(&mac_key).unwrap();
        mac.update(&page[begin..PAGE_SZ - 64]);
        mac.update(&pgno.to_le_bytes());
        page[PAGE_SZ - 64..].copy_from_slice(&mac.finalize().into_bytes());
        result.extend_from_slice(&page);
    }
    result
}

#[cfg(test)]
mod authentication_tests {
    use super::*;
    fn page() -> Vec<u8> {
        let mut p = vec![0; PAGE_SZ];
        p[..16].copy_from_slice(SQLITE_HDR);
        p[16..18].copy_from_slice(&[0x10, 0]);
        p[20] = 80;
        p[28..32].copy_from_slice(&1u32.to_be_bytes());
        p
    }
    #[test]
    fn authenticated_roundtrip_rejects_wrong_key_tamper_and_page_number() {
        let plain = page();
        let key = [7; 32];
        let encrypted = encrypt_test_pages(&plain, &key);
        let mac = hmac_key(&key, &encrypted[..16]);
        assert_eq!(
            authenticated_page(&key, &mac, &encrypted, 1).unwrap(),
            plain
        );
        assert!(authenticated_page(&key, &mac, &encrypted, 2).is_err());
        assert!(authenticated_page(
            &[8; 32],
            &hmac_key(&[8; 32], &encrypted[..16]),
            &encrypted,
            1
        )
        .is_err());
        for offset in [20, 4016, 4095] {
            let mut bad = encrypted.clone();
            bad[offset] ^= 1;
            assert!(authenticated_page(&key, &mac, &bad, 1).is_err());
        }
    }
    #[test]
    fn zero_tail_requires_authenticated_page_count_and_preserves_old_output_on_error() {
        let root = std::env::temp_dir().join(format!("wx-auth-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let src = root.join("in");
        let out = root.join("out");
        let key = [7; 32];
        let mut data = encrypt_test_pages(&page(), &key);
        data.resize(PAGE_SZ * 2, 0);
        std::fs::write(&src, &data).unwrap();
        full_decrypt(&src, &out, &key).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), page());
        data[PAGE_SZ + 1] = 1;
        std::fs::write(&src, &data).unwrap();
        assert!(full_decrypt(&src, &out, &key).is_err());
        assert_eq!(std::fs::read(&out).unwrap(), page());
        data.truncate(PAGE_SZ + 3);
        std::fs::write(&src, &data).unwrap();
        assert!(full_decrypt(&src, &out, &key).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}

/// Build a real, disposable SQLite database with SQLCipher's reserve size.
#[cfg(test)]
pub(crate) fn encrypted_test_database(path: &Path, sql: &str, key: &[u8; 32]) {
    let plain = path.with_extension("plain");
    let conn = rusqlite::Connection::open(&plain).unwrap();
    unsafe {
        let mut reserve = 80i32;
        assert_eq!(
            rusqlite::ffi::sqlite3_file_control(
                conn.handle(),
                std::ptr::null(),
                rusqlite::ffi::SQLITE_FCNTL_RESERVE_BYTES,
                &mut reserve as *mut _ as *mut std::ffi::c_void
            ),
            0
        );
    }
    conn.execute_batch("PRAGMA page_size=4096; PRAGMA journal_mode=DELETE; VACUUM;")
        .unwrap();
    conn.execute_batch(sql).unwrap();
    drop(conn);
    let bytes = std::fs::read(&plain).unwrap();
    assert_eq!(bytes[20], 80);
    std::fs::write(path, encrypt_test_pages(&bytes, key)).unwrap();
    std::fs::remove_file(plain).unwrap();
}
