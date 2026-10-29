# wx-cli：本地微信只读 CLI

这是 [muzhi1991/wx-cli](https://github.com/muzhi1991/wx-cli) 维护的 Linux 读取适配 fork，基于 `anyshu/wxcli@08af894`，保留 Apache-2.0 许可证和原有 18 个顶层命令。

本轮真实验证范围为 **Linux x86-64 微信 4.1.13.26**。macOS/Windows 已做编译检查，未做真实账号运行验收。完整结果、未覆盖样本和限制见 [Linux 验收矩阵](docs/linux-read-parity.md)。

## 从本 fork 构建

```sh
git clone https://github.com/muzhi1991/wx-cli.git
cd wx-cli
git checkout main
cargo build --release
# 可执行文件：target/release/wx
```

需要 Rust 工具链及平台 C 编译工具；SQLite 随构建编译。WXGF 主图转 PNG 还需要本机 `ffmpeg`。本 fork 尚未发布 release 或 npm 包；原版 npm、curl 安装器及旧 release 不包含本轮适配。不要以包版本号 `0.3.0` 区分原版和 fork，应记录构建 commit。

## 复用现有密钥

```sh
export WX_CLI_HOME="$HOME/.wx-cli-account-a"
./target/release/wx init \
  --db-dir /path/xwechat_files/account/db_storage \
  --keys-file /private/keys.json
./target/release/wx sessions --json
./target/release/wx history '聊天名称' --json
```

支持原版 key map 和 schema-v1 vault。导入时验证每库 salt 与首页 HMAC；之后查询不扫描进程、不改传入 vault。首次取钥才使用受 ELF 版本、进程身份、账号和字节/时间上限约束的 Linux scanner；详见[配置与权限](docs/linux-read-parity.md#setup-and-secrets)。不同账号使用独立 `WX_CLI_HOME`，明文缓存与导出文件也应放在私有目录。

新增数据库或密钥失效时，使用独立的 `keys` 维护命令：

```sh
wx keys status --json
wx keys refresh --database message/media_0.db --json
# 不指定 --database 时，只补齐当前缺失或失效的库
wx keys refresh --json
```

`status` 只读本地数据库首页并验证 HMAC；`refresh` 对有效目标直接返回，不扫描进程。需要补钥时，仅 Linux 已验证版本支持一次有界扫描，全部目标认证成功后才备份并原子更新当前配置的密钥文件，保留原格式、未知字段和 Unix 属主，随后停止当前 wx daemon 以便下次查询重载。查询不会自动补钥。详见[密钥维护与验收](docs/key-maintenance.md)。

Linux 读取的是**已 checkpoint 的本地主库**：逐页 HMAC、完整性检查、文件身份校验；不应用旧版不可靠 WAL。输出中的 `wal_applied=false` 与 `freshness=checkpoint_only` 表示新消息可能尚未可见，不保证约一分钟或任何固定延迟。

## 命令

原有命令继续保留：`init`、`sessions`、`unread`、`history`、`search`、`new-messages`、`contacts`、`members`、`stats`、`favorites`、`sns-notifications`、`sns-feed`、`sns-search`、`biz-articles`、`attachments`、`extract`、`export`、`daemon`。每个命令的参数见 `wx <command> --help`；多数查询支持 `--json`，默认 YAML。

另有 `keys status` / `keys refresh` 用于当前账号的显式密钥维护。

```sh
wx search '关键词' --in '聊天名称' --json
wx history '聊天名称' --type video -n 20 --json
wx attachments '聊天名称' --kind image --kind file --kind video --kind sticker --kind voice --json
wx extract '<attachment_id>' -o /private/output.png --json
wx export '聊天名称' --format json -o /private/history.json
wx new-messages --state-file /private/consumer-a.json -n 200 --json
wx daemon status
wx daemon stop
```

`history` 等保留原摘要，同时补充机器可读 `details`。本地图片支持严格 V2 解密及已验证单图 WXGF→PNG；普通文件/视频必须有本地文件并通过消息 MD5 校验。缺失文件返回明确状态；已观察到的加密表情缓存仍不支持解密。`extract` 缺文件时返回 `exported: false`，不会隐式下载。

语音支持从认证的 `media_*.db` 精确关联并导出原始字节，保留微信 SILK 前缀，返回 SHA-256；不转换为 WAV/MP3。新增媒体库缺 key 时明确返回 `key_unavailable`，查询不会自动扫描进程。详见[本地语音导出与真实验收](docs/local-voice.md)。

`new-messages` 修正同秒分页漏读，提供按账号和消费者隔离的复合游标，输出成功后才保存状态。它仍是本地主库轮询，不是可靠事件订阅；迟到历史回补、跨库 checkpoint 和进程崩溃下的重放需要调用方处理。

本项目只负责数据库读取和本地文件读取/解密/导出，不发送消息、不操作微信 UI、不触发下载、不默认访问 CDN、不提供新的自动回复或监控服务。后续 UI 工作流可先下载，再调用本 CLI 导出。

## 开发与来源

遵守 [AGENTS.md](AGENTS.md) 的本机及跨平台检查要求。合成测试不替代真实数据验收；无真实样本的功能在矩阵中单独标记。仓库不包含账号数据库、密钥、真实聊天或媒体 fixture。

- [Linux 实现、真实验收与未覆盖项](docs/linux-read-parity.md)
- [Agent 使用指南](SKILL.md)
- [上游历史使用文档](docs/upstream-readme.md)（仅参考，安装地址和实时性描述不代表本 fork）
- [Apache-2.0 许可证](LICENSE)
