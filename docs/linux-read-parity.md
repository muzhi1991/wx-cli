# Linux read parity: implementation and acceptance

This fork preserves the upstream 18-command CLI and adds a verified Linux 4.1.13.26 read path. Upstream baseline: `anyshu/wxcli@08af894594b4afd468e23e17dbd783f15403f13b`, Apache-2.0. Public repository: https://github.com/muzhi1991/wx-cli.

## Operating boundary

The CLI reads local databases and files, decrypts supported formats, and writes private caches/exports. It does not send messages, click WeChat, acquire UI locks, trigger downloads, automatically fetch CDN URLs, or implement a new monitoring service. A missing local attachment returns a status and `exported: false`; a separate UI workflow can download it before another CLI invocation.

Linux queries use **authenticated main-database checkpoints only**. Every active page is HMAC-SHA512 authenticated before AES-CBC decryption. All-zero preallocation is accepted only beyond a valid authenticated SQLite page count. Partial files, nonzero tails, wrong keys and changed source identities are rejected. The cache checks SQLite integrity; the proprietary `MMFtsTokenizer` prevents the integrity command on FTS databases and is reported separately from page authentication. Source identity includes length, mtime and (Unix) device, inode and ctime. Each database is independently snapshotted; this is not a cross-database atomic snapshot.

Object responses include `snapshot.mode=authenticated_checkpoint`, `wal_applied=false`, `freshness=checkpoint_only`. Some original list-form CLI commands retain their list output. No maximum checkpoint latency is promised. Uncheckpointed writes may be absent, even if the UI already shows them. The old unverified WAL application is not used on Linux.

## Setup and secrets

```sh
export WX_CLI_HOME="$HOME/.wx-cli-account-a"
wx init --db-dir /path/xwechat_files/account/db_storage --keys-file /private/keys.json
wx sessions --json
wx history 'contact name' --json
```

`--keys-file` accepts the upstream relative-path map and schema-v1 vaults (`databases` entries with `database`, `salt_hex`, `raw_key_hex`). Every entry is checked against its exact database salt and authenticated first page. Existing caches are reused without process-memory reads; no keys appear in output. A reused initialized configuration is revalidated. A different explicit `--db-dir` cannot silently reuse another configured account.

Use a separate `WX_CLI_HOME` per account. On Unix, new files use a private umask (directories 0700, files 0600). The supplied vault is read in place and is never rewritten by imports. Plaintext database caches and exports remain sensitive and should be placed on private storage; a tmpfs work directory is suitable for disposable tests.

For a first-time Linux scan, `wx init --db-dir ...` (or explicit `--force`) uses a bounded CipherConfig profile. Only the observed Linux x86-64 executable SHA-256 `2749535f299ba67feb8ef80cab898bb0531fa8f376b16f8a72db706811c84132` is supported. The scanner verifies executable hash, runtime profile constants, process start time and open database account paths; pointer reads stay within initial writable mappings. A scan is limited to 1.5 GiB / 60 seconds, stops when all known databases are authenticated, and does not retry itself. `WX_WECHAT_PID` selects an explicit process; `WX_WECHAT_STARTTIME` pins its identity; `WX_SCAN_CLAIM` creates an exclusive one-attempt claim. Do not grant the normal query daemon ptrace privileges. A dedicated diagnostic container may share only the selected PID namespace with minimal `SYS_PTRACE`/`DAC_READ_SEARCH` capabilities. Reuse its saved keys for future queries.

## Messages and local media

Existing human-readable fields remain. History/search/incremental results additionally contain `local_type` and `details`. The parser preserves full forwarded-record text, typed file metadata, contact cards, video metadata, finder identifiers and media links, articles, quotes and mini-program metadata when recognized. Finder URLs come from `finderFeed`, not the generic unsupported-client help URL. Signed media URLs are metadata, not proof of successful or durable external access. Zstd expansion is bounded to 4 MiB.

```sh
wx attachments 'contact name' --kind image --kind file --kind video --kind sticker --kind voice --json
wx extract '<attachment_id>' -o /private/export.png --json
```

The default attachment kind stays `image`. Image resources require an exact, unique message match; unmarked 32-hex strings and latest-local-id fallback are rejected. `file_id` is the local resource identifier; the legacy `md5` image field is retained for compatibility and is **not** a content digest. Main/bubble/thumbnail availability is distinct from the sender's original upload. Linux V2 keys are derived from existing `.xwechat/net/kvcomm/key_*.statistic` filenames and verified against local V2 data. `WX_IMAGE_KVCOMM_DIR` can specify that directory; statistic contents and process memory are not read.

V2 decryption validates padding and all declared segment lengths. The observed single-part, single-picture WXGF layout is converted to PNG with local `ffmpeg`, with a timeout and dimension limit. Unknown multi-part/animated WXGF is rejected. Existing PDF/files require message content-MD5 and size verification. Ordinary videos require a local matching body; thumbnails do not stand in for a video. The observed encrypted sticker cache format remains unsupported. Raw voice export is verified separately; see [local voice](local-voice.md).

`new-messages` uses a `(timestamp, shard, local_id)` cursor per conversation, isolates default state by account, and accepts `--state-file` for independent consumers. It locks a consumer state file and saves only after successful output/flush. A crash can cause replay; it is not an exactly-once acknowledgment protocol. Same-second pagination and initial global-limit truncation are fixed. It remains a polling query over checkpointed local data, not a reliable event subscription: late messages/history backfill earlier than a cursor and non-atomic cross-database checkpoints can still be missed. An interrupted reader can leave a `.lock` file that must be removed after verifying the reader exited.

## Acceptance evidence (2026-10-29)

Real tests use the already logged-in Linux account through separate containers. Queries use a read-only encrypted snapshot and the existing private vault, no shared PID namespace, no network and no capabilities. All plaintext output is in private tmpfs. No real keys, account identifiers, conversations, portraits, filenames or signed URLs are committed as fixtures.

Status is deliberately separated: **real pass**, **synthetic only**, **awaiting sample**. An empty query is not positive business coverage.

| Command | Real observation | Status |
|---|---|---|
| init | Existing 19-key vault loaded with zero memory reads; one separately authorized Rust scanner recovered/authenticated 19/19 keys, reading 1,039,932,764 bytes | Real pass |
| sessions | 9 sessions with nonzero timestamps from 19 stored session rows | Real pass |
| unread | 3 unread sessions after the user opened chats (4 in the earlier snapshot); no CLI mark-read operation | Real pass |
| history | 25 private-chat, 2 group, 1 file-helper messages; two 5-row pages match full history without overlap; video filter returns 1 video | Real pass |
| search | Known local test phrase matched 1 message; `--in` confines it to the selected chat | Real pass |
| new-messages | An independent cursor seeded at timestamp 0 with `-n 1` returned all 28 messages, equal to the 3 full-history sets, then empty; resuming the prior 20-message private-chat baseline returned exactly the 5 new messages; separate consumer state works | Real pass; same-second multi-shard boundary also synthetic |
| contacts | 33 filtered contact entries from 56 stored rows | Real pass |
| members | 7 members of a real group, plus separate database inventory found 11 members across 2 groups | Real pass |
| stats | Private total 25; group total 2 with 2 distinct senders; 24 hourly buckets | Real pass |
| favorites | 6 entries: 2 images, 3 articles, 1 other; article filter returns 3 and a known article-ID keyword returns the expected 2 | Real pass for these types; text/card/video samples absent |
| sns-notifications | 2 real notifications: 1 like and 1 comment, including actor/feed identifiers and comment text | Real pass |
| sns-feed | 23 stored timeline items; default page returns 20 | Real pass |
| sns-search | Known local text search returned 8 timeline items | Real pass |
| biz-articles | 7 push rows expanded to 13 nonempty HTTP(S) article links | Real pass |
| attachments | Exact image/PDF/video/sticker metadata; image/PDF/video available, sticker cache present but unsupported; earlier snapshot correctly reported video body missing with thumbnail present | Real pass for local availability states |
| extract | V2 main image → WXGF → HEVC → PNG, 2532×1170, 1,536,789 bytes; PDF 376,300 bytes and video 1,903,947 bytes with content-MD5 and size matching their messages; video is HEVC 720×1280, 14.665 s with AAC, and fully decodes in ffmpeg; unavailable/unsupported media exports no file | Real pass for image/PDF/video; sticker body unsupported |
| export | JSON and YAML records equal all 25 history records; Markdown and text exports also completed | Real pass |
| daemon | status/logs, stop → query auto-restart → stop verified in isolated container | Real pass |

The unique scanner sidecar was destroyed after the test, including its tmpfs keys. The preexisting vault was unchanged (root-owned, mode 0600). The original WeChat process retained its start time and container configuration (`Privileged=false`, no added capabilities). After final acceptance, the query sidecar and its plaintext tmpfs, the copied encrypted test snapshot/kvcomm filenames, and the temporary local image preview were removed. No existing WeChat/CUA container was restarted or reconfigured.

Synthetic regression coverage includes page HMAC tampering/wrong keys/page numbers, authenticated zero tails and partial files, cache hits/source changes/bad-page rejection/restart, same-second messages across two chats/two shards with limit one, strict attachment identity, bounded V2/WXGF parsing, and existing upstream parser tests. Linux x86-64 GNU `cargo check`, native build and 121 tests pass (Rust 1.90 container). macOS `cargo check` and 139 tests pass (Rust 1.99.1). Windows MSVC target `cargo check` passes using a Zig C toolchain for native dependencies; no Windows executable link/runtime test is claimed. macOS has no real account runtime acceptance. All test fixtures committed here are synthetic.

The requested supplementary samples are now present and checked: quote reference/title, positive voice duration, location coordinates/label, mini-program appid/pagepath, the persisted system revoke notice, SNS like/comment and downloaded ordinary video. A revoke notice does not recover withdrawn content. Voice metadata and raw BLOB export are verified in the [local voice follow-up](local-voice.md); audio decoding is not claimed. Favorite text/card/video variants, nested-media forwarded records and unknown WXGF layouts lack real samples. Encrypted sticker-cache decryption remains unsupported. None of those variants is claimed as passed.

The later [voice acceptance](local-voice.md) adds `--kind voice`, a twentieth persistent database key, and real raw-audio export coverage. The 19-key scan counts in the original matrix describe the earlier snapshot; the new database required a separate, explicitly authorized one-attempt scan.
