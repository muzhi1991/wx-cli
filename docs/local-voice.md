# Local raw voice export

`attachments --kind voice` lists locally stored voice payloads. `extract` exports the selected database BLOB unchanged. The verified runtime is Linux x86-64 WeChat 4.1.13.26.

```sh
wx attachments 'chat name' --kind voice --json
wx extract '<attachment_id>' -o /private/voice.silk --json
```

The real sample is **WeChat-prefixed SILK**, beginning with `0x02 + #!SILK_V3`. The prefix remains in the exported file. Output reports `format=wechat_silk`, `raw_bytes=true`, `prefix_preserved=true`, `decoded=false`, byte count and SHA-256. This is not WAV/MP3 conversion, playback or transcription. Bare `#!SILK_V3` is recognized by synthetic tests; it has not been observed in this account. Unknown headers are rejected instead of being labelled as a known codec.

## Exact association and bounded reads

1. Locate one type-34 message by conversation, local ID and creation time across known message shards; recover its server ID. A missing or ambiguous message fails.
2. Discover numbered `message/media_<n>.db` files. Each needs its own authenticated cached key. No query or export scans process memory.
3. In each authenticated media snapshot, map the exact conversation through that database's `Name2Id.user_name` to its `rowid`. Require a unique mapping.
4. Require exactly one `VoiceInfo` row across all discovered media shards matching that chat ID, local ID, server ID and creation time. `data_index` is treated as opaque; multiple rows are not concatenated or resolved by choosing the newest.
5. Listing reads only storage type, length and at most 10 header bytes. Export repeats the identity, conversation mapping and SQL length checks before reading the BLOB. Audio is limited to 16 MiB and media discovery to 128 shards.

Export uses exclusive creation unless `--overwrite` is explicit. The reported SHA-256 describes the exported raw bytes. Database-page HMAC protects the source snapshot; the sample's XML `voicemd5` is not a usable digest, so no message-MD5 verification is claimed. Its XML length happens to match this sample's BLOB length, but that observation is not imposed as a universal format rule.

Linux uses checkpointed main databases. A newly arrived message and its media may become visible at different checkpoints; no cross-database atomicity or fixed freshness bound is promised.

## Availability states

An unavailable result has `exported=false` and creates no output file.

| State | Meaning |
|---|---|
| `available` | Exactly one local payload with a recognized header and bounded size |
| `media_database_missing` | No supported numbered media database exists locally |
| `key_unavailable` | A discovered media database lacks its cached key; reported separately from missing audio |
| `unsupported_media_schema` | Required media tables/columns are absent |
| `audio_unavailable` | No exact local voice row matches |
| `ambiguous_audio` | Duplicate conversation mappings or multiple matching rows/shards |
| `audio_empty` | Matching payload is empty or NULL |
| `audio_too_large` | Payload exceeds the 16 MiB limit |
| `unsupported_audio_storage` | Payload is not stored as a BLOB |
| `unsupported_audio_format` | Header is unknown, truncated or an unsupported prefix |

Authentication, I/O and changing-source failures are errors, not successful empty exports. If any discovered media shard lacks a key or has an unsupported schema, the lookup cannot claim uniqueness across all shards and does not return `available` from another shard.

## Real acceptance, 2026-10-29

The initial 19-key vault did not contain the newly observed `message/media_0.db`; none of those keys authenticated its first page. After explicit authorization, one bounded diagnostic scan read **1,068,848,165 bytes**, authenticated **20/20** databases and stopped. The additional key was independently verified and atomically added to the private vault. The original 19 entries stayed unchanged, a private backup was retained, and file/directory fsync and root-owned 0600 permissions were verified. No raw keys enter this repository or logs.

The following reads then ran in a separate container with no network, no capabilities and no shared WeChat PID namespace, using read-only encrypted snapshots and the persistent vault. All 20 cached keys were reloaded with **zero process-memory reads**.

| Evidence | Result |
|---|---|
| Media database authentication | 8 active pages pass HMAC; 6,392 authenticated-header-bounded zero tail pages skipped; SQLite integrity check `ok` |
| Actual tables | `Name2Id(user_name)` and `VoiceInfo(chat_name_id, create_time, local_id, svr_id, voice_data BLOB, data_index TEXT)` |
| Actual association | One conversation mapping and one exact voice row, matching chat/local ID/server ID/time |
| Raw payload | 4,944 bytes, WeChat SILK prefix; XML declares 3,120 ms and length 4,944 |
| CLI list and extract | One available voice; exported bytes equal the independently selected database BLOB; SHA-256 equals its independently computed digest; prefix preserved; output mode 0600 |
| Existing output | Rejected without `--overwrite`; unchanged bytes; explicit overwrite succeeds |
| Missing-key case | A separate private 19-key test configuration returns `key_unavailable` and creates no output |
| Compatibility | Voice history filter works; default attachments still selects images |

No audio decoding or duration measurement was performed. Additional voice codecs, sender/device variants, and multi-part layouts remain unverified. The voice feature adds seven synthetic regressions covering identity mismatches, duplicate rows/shards/mappings, schema absence, empty/oversized/wrong-type/unknown-header payloads, changed mappings before export, bounded reads, prefix preservation, output hash and overwrite protection. Linux GNU check/build and 121 tests pass; macOS check and 139 tests pass; Windows MSVC target check passes. Real-account runtime acceptance is Linux only.

Both diagnostic containers were removed after acceptance, including every plaintext database and audio export in tmpfs and the encrypted test snapshot. The original WeChat process retained its PID/start time and container configuration; its UI and login were not changed. The updated 20-key vault remains root-owned mode 0600 for future reads.
