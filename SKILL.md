---
name: wx-cli
description: "Read local WeChat databases, conversations, contacts and existing attachments with the muzhi1991 wx-cli fork."
---

# wx-cli fork

Build the source from https://github.com/muzhi1991/wx-cli on `main` with `cargo build --release`. The upstream npm package, curl installer and releases do not include this fork. Do not install them to obtain these Linux changes. No release is published by this task.

Read [README.md](README.md) and [Linux acceptance](docs/linux-read-parity.md) for actual compatibility and missing samples. Verified runtime is Linux x86-64 WeChat 4.1.13.26; other platforms have compilation checks only.

Prefer existing database keys:

```sh
export WX_CLI_HOME=/private/wx-account-a
wx init --db-dir /path/xwechat_files/account/db_storage --keys-file /private/keys.json
wx sessions --json
wx history 'chat' --json
wx attachments 'chat' --kind image --kind file --kind video --kind sticker --json
wx extract '<attachment_id>' -o /private/output --json
```

Imports accept the original key map and schema-v1 vault; validate each database first page, reuse keys thereafter, and never print key material. Use a separate state directory per account. Never copy account keys or conversations into public fixtures/logs. Database queries do not require ptrace. A fresh Linux init scan is bounded and version pinned; only use it when needed and authorized, with a dedicated minimum-privilege diagnostic environment. Never rescan merely to refresh messages.

All original 18 commands remain available; discover exact options with `wx --help` and `wx COMMAND --help`. Local checkpoint data may lag the UI. Respect `snapshot.wal_applied=false`, `freshness=checkpoint_only`, unknown-shard warnings and `exported: false`. Empty output does not prove a feature works with real data. This fork does not guarantee a fixed visibility delay.

`new-messages --state-file /private/consumer.json` isolates consumers and paginates with a compound cursor. Save/acknowledgment is limited to successful CLI output, not downstream processing. It is a polling query, not a reliable event subscription; do not promise no losses for late/backfilled history.

No sending, automatic replies, UI clicking, control locks, UI-triggered downloads, or automatic CDN fetching belong to this CLI. Missing media must remain a declared state until an independently authorized UI workflow downloads it. The observed encrypted sticker cache and voice extraction are unsupported; do not return a thumbnail as the original video or call WXGF bytes a JPEG/HEVC stream.
