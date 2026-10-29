# Explicit key maintenance

`keys` operates on the existing configuration's `db_dir` and `keys_file`. Initialize the account first and use the same `WX_CLI_HOME` as its queries. It does not create another profile or service, export keys, or refresh automatically.

```sh
wx keys status --json
wx keys refresh --database message/media_0.db --json
wx keys refresh --json
```

Default output is YAML. `status` enumerates local `.db` files and checks each cached key against its exact first-page HMAC, including the stored salt for schema-v1 vaults. It does not read process memory, decrypt complete databases, start a daemon or modify files. A valid first page does not replace the full page authentication and integrity checks performed by queries.

Example status:

```json
{"databases":20,"valid":19,"missing":["message/media_0.db"],"invalid":[]}
```

`missing` means the file has no key entry; `invalid` means its entry is malformed or does not authenticate the current first page. Read failures, source identity changes and unsupported plaintext SQLite files are errors, not invalid-key reports. Unsafe relative paths, duplicate normalized entries, symlink database paths and symlink/hard-linked key files are rejected. Database paths are relative to `db_dir`; `..` and absolute paths are not accepted. Enumeration is bounded to 4,096 databases and 16 directory levels; the key file is limited to 16 MiB.

## Refresh behavior

Refresh first performs the same status checks. With `--database`, only that existing database can be selected; otherwise it selects all missing/invalid databases. If all selected keys are valid, the result has `saved=false`, `scan_performed=false`, `updated=[]`, `restart_required=false`: no scan, backup, write or daemon stop occurs, even if another unselected database lacks a key.

A refresh that needs new keys is supported only by the verified Linux x86-64 WeChat 4.1.13.26 scanner. Other platforms can run status and valid-key no-ops, but refuse a required scan. The Linux scanner retains its executable hash/account/process identity checks, 1.5 GiB / 60-second bounds and optional exclusive `WX_SCAN_CLAIM`; it stops when all selected databases are found. See [scanner setup](linux-read-parity.md#setup-and-secrets) for the supported executable and isolated diagnostic privileges. There is no automatic retry. Do not grant a normal query daemon process-memory access.

Every selected database must independently authenticate before anything is saved. A scan error, absent target, duplicate target, wrong key or salt, changing source, or concurrent key-file update aborts without replacing the original key file. Returned keys for unrelated databases are ignored.

The update preserves schema-v1 vaults, string maps, object maps and mixed existing entries, including unknown fields and unrelated database entries. It does not change the configuration path. Formatting may change in the updated JSON; the backup preserves the exact original bytes.

Saving uses a same-directory exclusive `.lock`, a private `.backup.<pid>-<timestamp>` and a temporary file. Both data files are fsynced before atomic replacement, followed by directory fsync. The original file's identity and bytes are rechecked before replacement. On Unix, backup and replacement are mode 0600 and retain the original uid/gid, including when refresh runs under sudo. If ownership cannot be preserved, the original is not replaced. A killed refresher may leave a lock; verify it has exited before removing the lock. Keep backup files private.

When elevating privileges, explicitly retain the intended `WX_CLI_HOME` so the same account configuration and daemon are selected. After a successful save, refresh stops only that wx daemon; its next query loads the updated keys. It never stops or restarts WeChat. Output includes `saved=true`, `updated`, `backup_file`, `daemon_stopped`, `restart_required` and `directory_synced`. If stopping the daemon fails, keys remain saved and `restart_required=true` tells the caller to restart the wx daemon. A directory-fsync failure similarly reports a durability warning with `saved=true`; neither condition warrants another key scan.

## Acceptance, 2026-10-29

Real tests ran in an independent container with no network, no capabilities and no shared WeChat PID namespace. Its 20 encrypted database snapshots and original persistent vault were mounted read-only; writable test state was private tmpfs.

| Real check | Result |
|---|---|
| Current vault | `databases=20`, `valid=20`, empty missing/invalid arrays |
| Full and selected valid refresh | No-op; no process-memory reads, scan claim, backup, daemon or vault mutation |
| Private copy with one media key removed | `valid=19`, exactly that database in `missing` |
| Valid selected target while another key is missing | No-op; no scan |
| Private copy with one media key corrupted | `valid=19`, exactly that database in `invalid` |
| Invalid relative target | Rejected before scanning |

The original vault was not edited. No real process scan was repeated for this feature. The scanner itself has the earlier [real voice-key recovery evidence](local-voice.md); its new target filter and all saving/failure paths are covered by synthetic encrypted databases and injected scanner results, rather than being described as a new real refresh success.

Synthetic checks cover valid/missing/invalid classification, zero-scan no-ops, exact target filtering, path and plaintext errors, schema/string/object preservation, missing/duplicate/wrong scanner results, concurrent edits and existing locks, exact backup bytes, permissions/ownership failures, and reloading the saved key before the daemon-stop callback. A stop failure explicitly keeps `saved=true`. A separate root-only test verifies that a successful update preserves a non-root source owner's uid/gid and mode 0600 for both replacement and backup; it ran with only `CHOWN` and `DAC_OVERRIDE` capabilities and no account data mounted.

Linux GNU check/build and **131 tests pass**, with the root-only ownership test separately **1 passed**. macOS check and **148 tests pass** (root-only test skipped). Windows MSVC target check passes using the existing Zig C toolchain; no Windows link/runtime or real-account acceptance is claimed. All committed fixtures are synthetic.

Independent review repeated the 20-key status and both no-op refreshes and confirmed unchanged vault bytes, inode, ownership, permissions, timestamps and directory entries. The test container, its anonymous volume and private tmpfs, and the encrypted snapshot were removed after acceptance. The original WeChat container remains running with its original process start time and configuration; the original vault remains root-owned mode 0600.
