# quicport 仕様書

## 概要

`quicport` は QUIC プロトコルを使用したポートフォワーディング / トンネリングツールです。
リモートサーバー上のポートへのアクセスを、クライアント側のローカルポートに転送します。

## ユースケース

### Remote Port Forwarding (RPF) - リモートポートフォワーディング

```
[外部クライアント] --> [サーバー:9022/tcp] --QUIC--> [クライアント] --> [ローカルサービス:22/tcp]
```

例: NAT 配下にある SSH サーバーを、インターネット経由でアクセス可能にする。

### Local Port Forwarding (LPF) - ローカルポートフォワーディング

```
[ローカルクライアント] --> [クライアント:9022/tcp] --QUIC--> [サーバー] --> [リモートサービス:22/tcp]
```

例: リモートネットワーク内の SSH サーバーに、ローカルポートを通じてアクセスする。

### SSH ProxyCommand モード

```
[SSH Client] <-> stdin/stdout <-> [ssh-proxy] <-> QUIC Tunnel <-> [Server] <-> [Remote SSH (port 22)]
```

例: SSH の ProxyCommand として使用し、QUIC トンネル経由で SSH 接続を行う。

## コマンドライン仕様

### 共通オプション

サーバー・クライアント両方で使用可能なグローバルオプション:

| オプション | 必須 | 説明 |
|-----------|------|------|
| `--log-format` | No | ログ出力形式。`console`（デフォルト）または `json`。環境変数 `QUICPORT_LOG_FORMAT` でも指定可。control-plane が data-plane を自動起動する際にも継承される |
| `--log-output` | No | ログ出力先ファイルパス。指定時はファイルに追記モードで出力。未指定時のデフォルトは stdout（ssh-proxy モードでは stderr）。環境変数 `QUICPORT_LOG_OUTPUT` でも指定可 |

**例:**

```bash
# JSON 形式でログ出力（構造化ログ、監視ツール連携向け）
quicport --log-format json server --listen 0.0.0.0:9000

# 環境変数で指定
QUICPORT_LOG_FORMAT=json quicport control-plane --control-plane-addr 127.0.0.1:9000 --data-plane-addr 0.0.0.0:9000

# ログをファイルに出力
quicport --log-output /var/log/quicport.log control-plane --control-plane-addr 127.0.0.1:9000 --data-plane-addr 0.0.0.0:9000
```

### コントロールプレーンモード (control-plane)

```bash
quicport control-plane --control-plane-addr <cp_address>:<port> --data-plane-addr <dp_address>:<port> --privkey <server_private_key> --client-pubkeys <authorized_public_keys>
```

**オプション:**

| オプション | 必須 | 説明 |
|-----------|------|------|
| `--control-plane-addr` | No | コントロールプレーン HTTP IPC サーバーのアドレスとポート（デフォルト: `127.0.0.1:39000`） |
| `--data-plane-addr` | No | データプレーン QUIC リッスンアドレスとポート（デフォルト: `0.0.0.0:39000`） |
| `--private-api-listen` | No | Private API サーバーのアドレスとポート（デフォルト: `127.0.0.1:<listen_port>`） |
| `--no-public-api` | No | Public API サーバーを無効化 |
| `--no-auto-dataplane` | No | データプレーンを自動起動しない（systemd-run 等で別途起動する場合に使用） |
| `--privkey` | Yes** | サーバーの秘密鍵（Base64 形式、相互認証用）。環境変数 `QUICPORT_PRIVKEY` でも指定可 |
| `--privkey-file` | Yes** | サーバーの秘密鍵ファイルパス。環境変数 `QUICPORT_PRIVKEY_FILE` でも指定可 |
| `--client-pubkeys` | Yes* | 認可するクライアントの公開鍵（Base64 形式）。複数指定はカンマ区切り。環境変数 `QUICPORT_CLIENT_PUBKEYS` でも指定可 |
| `--client-pubkeys-file` | Yes* | 公開鍵を読み込むファイルパス。1 行 1 鍵。環境変数 `QUICPORT_CLIENT_PUBKEYS_FILE` でも指定可 |
| `--psk` | No | 事前共有キー。環境変数 `QUICPORT_PSK` でも指定可 |
| `--quic-keep-alive` | No | QUIC keep-alive interval（秒）。NAT テーブル維持のための ping 送信間隔（デフォルト: `5`）。環境変数 `QUICPORT_QUIC_KEEP_ALIVE` でも指定可 |
| `--quic-idle-timeout` | No | QUIC max idle timeout（秒）。この時間応答がなければ接続をクローズ（デフォルト: `90`）。環境変数 `QUICPORT_QUIC_IDLE_TIMEOUT` でも指定可 |

\* `--client-pubkeys` または `--client-pubkeys-file` のいずれかが必須（`--psk` を使用する場合を除く）
\** X25519 認証（`--client-pubkeys` / `--client-pubkeys-file`）使用時は `--privkey` または `--privkey-file` が必須（相互認証のため）

> **PSK 自動生成:** 認証オプション（`--psk`, `--client-pubkeys`, `--client-pubkeys-file`）が何も指定されていない場合、
> PSK が自動生成され `~/.config/quicport/psk` に保存されます。次回以降の起動では既存の PSK を読み込みます。

**例:**

```bash
# 相互認証（サーバー秘密鍵 + クライアント公開鍵）
quicport control-plane --data-plane-addr 0.0.0.0:9000 \
  --privkey "8JWfeRFI8New0ie+oUTNKDyaHMJOk+EAq4w3wG8HR3U=" \
  --client-pubkeys "IexqQqW8ngM33aoJWqheXfW+11hL6A3h6kpO8uNl9Ws="

# ファイルから読み込み
quicport control-plane --data-plane-addr 0.0.0.0:9000 \
  --privkey-file /etc/quicport/server.key \
  --client-pubkeys-file /etc/quicport/authorized_keys

# 複数のクライアント公開鍵を指定（カンマ区切り）
quicport control-plane --data-plane-addr 0.0.0.0:9000 \
  --privkey "SERVER_PRIVATE_KEY" \
  --client-pubkeys "key1,key2,key3"
```

### クライアントモード

クライアントは 2 つのモードをサポートしています:

- **Remote Port Forwarding (RPF)**: `--remote-source` + `--local-destination`
- **Local Port Forwarding (LPF)**: `--local-source` + `--remote-destination`

#### RPF (Remote Port Forwarding)

サーバー側でポートをリッスンし、クライアント側のローカルサービスに転送します。

```bash
quicport client --server <server_address>:<port> --remote-source <port>[/protocol] --local-destination [addr:]<port>[/protocol] [auth options]
```

#### LPF (Local Port Forwarding)

クライアント側でポートをリッスンし、サーバー経由でリモートサービスに転送します。

```bash
quicport client --server <server_address>:<port> --local-source <port>[/protocol] --remote-destination [addr:]<port>[/protocol] [auth options]
```

**オプション:**

| オプション | 必須 | 説明 |
|-----------|------|------|
| `--server`, `-s` | Yes | 接続先サーバーのアドレスとポート |
| **RPF オプション** |||
| `--remote-source`, `-r` | RPF 時 | サーバー側で開くポート（例: `9022`, `9022/tcp`）。`--local-source` と排他 |
| `--local-destination`, `-l` | RPF 時 | 転送先のアドレスとポート（例: `22`, `22/tcp`, `192.168.1.100:22`）。`--remote-destination` と排他 |
| **LPF オプション** |||
| `--local-source`, `-L` | LPF 時 | クライアント側で開くポート（例: `9022`, `9022/tcp`）。`--remote-source` と排他 |
| `--remote-destination`, `-R` | LPF 時 | サーバー経由での転送先（例: `22`, `22/tcp`, `192.168.1.100:22`）。`--local-destination` と排他 |
| **認証オプション** |||
| `--privkey` | Yes* | X25519 秘密鍵（Base64 形式）。環境変数 `QUICPORT_PRIVKEY` でも指定可 |
| `--privkey-file` | Yes* | 秘密鍵を読み込むファイルパス。環境変数 `QUICPORT_PRIVKEY_FILE` でも指定可 |
| `--server-pubkey` | Yes** | 期待するサーバーの公開鍵（Base64 形式、相互認証用）。環境変数 `QUICPORT_SERVER_PUBKEY` でも指定可 |
| `--server-pubkey-file` | Yes** | サーバーの公開鍵ファイルパス。環境変数 `QUICPORT_SERVER_PUBKEY_FILE` でも指定可 |
| `--psk` | No | 事前共有キー。環境変数 `QUICPORT_PSK` でも指定可 |
| `--insecure` | No | サーバー証明書検証をスキップ（テスト用、本番環境では非推奨） |
| **再接続オプション** |||
| `--reconnect` | No | 接続断時に自動再接続を有効化（デフォルト: true） |
| `--reconnect-max-attempts` | No | 最大再接続試行回数。0 = 無制限（デフォルト: 0） |
| `--reconnect-delay` | No | 初期再接続待機時間（秒）。エクスポネンシャルバックオフで最大 60 秒まで増加（デフォルト: 1） |
| **QUIC オプション** |||
| `--quic-keep-alive` | No | QUIC keep-alive interval（秒）。NAT テーブル維持のための ping 送信間隔（デフォルト: `5`）。環境変数 `QUICPORT_QUIC_KEEP_ALIVE` でも指定可 |
| `--quic-idle-timeout` | No | QUIC max idle timeout（秒）。この時間応答がなければ接続をクローズ（デフォルト: `90`）。環境変数 `QUICPORT_QUIC_IDLE_TIMEOUT` でも指定可 |

\* `--privkey` または `--privkey-file` のいずれかが必須（`--psk` を使用する場合を除く）
\** X25519 認証（`--privkey` / `--privkey-file`）使用時は `--server-pubkey` または `--server-pubkey-file` が必須（MITM 攻撃防止のため）

**--local-destination / --remote-destination の形式:**

| 形式 | 例 | 解釈 |
|------|-----|------|
| `port` | `22` | `127.0.0.1:22/tcp` |
| `port/protocol` | `22/tcp` | `127.0.0.1:22/tcp` |
| `addr:port` | `192.168.1.100:22` | `192.168.1.100:22/tcp` |
| `addr:port/protocol` | `192.168.1.100:22/tcp` | `192.168.1.100:22/tcp` |
| `[ipv6]:port` | `[::1]:22` | `[::1]:22/tcp` |

**例 (RPF - Remote Port Forwarding):**

```bash
# 相互認証（クライアント秘密鍵 + サーバー公開鍵）
quicport client -s quicport.foobar.com:9000 \
  --remote-source 9022 \
  --local-destination 22 \
  --privkey "mBJ3XsDyuJxqU2bk0XEa+rUH+XD1lYwMlx9xH8ZTMUg=" \
  --server-pubkey "l0NT7qgtfJhpWMH3dKDFm/PqmlBBpuEivWJQ7vqsJ1A="

# ローカルネットワーク上の別のサーバーに転送
quicport client -s quicport.foobar.com:9000 \
  --remote-source 9022 \
  --local-destination 192.168.1.100:22 \
  --psk "secret"

# ファイルから読み込み
quicport client -s quicport.foobar.com:9000 -r 9022 -l 22 \
  --privkey-file ~/.quicport/client.key \
  --server-pubkey-file ~/.quicport/server.pub
```

**例 (LPF - Local Port Forwarding):**

```bash
# ローカルポートをリモートサービスに転送
quicport client -s quicport.foobar.com:9000 \
  --local-source 9022 \
  --remote-destination 22 \
  --psk "secret"

# リモートネットワーク内の別のサーバーに転送
quicport client -s quicport.foobar.com:9000 \
  --local-source 9022 \
  --remote-destination 192.168.1.100:22 \
  --psk "secret"

# UDP トンネリング（例: DNS）
quicport client -s quicport.foobar.com:9000 \
  --local-source 5353/udp \
  --remote-destination 8.8.8.8:53/udp \
  --psk "secret"
```

### SSH ProxyCommand モード (ssh-proxy)

SSH の ProxyCommand として使用し、stdin/stdout を QUIC トンネル経由でリモートサービスに接続します。

```bash
quicport ssh-proxy --server <server_address>:<port> --remote-destination [addr:]<port> [auth options]
```

**オプション:**

| オプション | 必須 | 説明 |
|-----------|------|------|
| `--server`, `-s` | Yes | 接続先サーバーのアドレスとポート |
| `--remote-destination`, `-R` | Yes | リモート転送先（例: `22`, `192.168.1.100:22`） |
| **認証オプション** |||
| `--privkey` | Yes* | X25519 秘密鍵（Base64 形式）。環境変数 `QUICPORT_PRIVKEY` でも指定可 |
| `--privkey-file` | Yes* | 秘密鍵を読み込むファイルパス。環境変数 `QUICPORT_PRIVKEY_FILE` でも指定可 |
| `--server-pubkey` | Yes** | 期待するサーバーの公開鍵（Base64 形式）。環境変数 `QUICPORT_SERVER_PUBKEY` でも指定可 |
| `--server-pubkey-file` | Yes** | サーバーの公開鍵ファイルパス。環境変数 `QUICPORT_SERVER_PUBKEY_FILE` でも指定可 |
| `--psk` | No | 事前共有キー。環境変数 `QUICPORT_PSK` でも指定可 |
| `--insecure` | No | サーバー証明書検証をスキップ（テスト用、本番環境では非推奨） |
| **再接続オプション** |||
| `--reconnect` | No | 接続断時に自動再接続を有効化（デフォルト: true） |
| `--reconnect-max-attempts` | No | 最大再接続試行回数。0 = 無制限（デフォルト: 0） |
| `--reconnect-delay` | No | 初期再接続待機時間（秒）（デフォルト: 1） |
| **QUIC オプション** |||
| `--quic-keep-alive` | No | QUIC keep-alive interval（秒）。NAT テーブル維持のための ping 送信間隔（デフォルト: `5`）。環境変数 `QUICPORT_QUIC_KEEP_ALIVE` でも指定可 |
| `--quic-idle-timeout` | No | QUIC max idle timeout（秒）。この時間応答がなければ接続をクローズ（デフォルト: `90`）。環境変数 `QUICPORT_QUIC_IDLE_TIMEOUT` でも指定可 |

\* `--privkey` または `--privkey-file` のいずれかが必須（`--psk` を使用する場合を除く）
\** X25519 認証使用時は `--server-pubkey` または `--server-pubkey-file` が必須

**例:**

```bash
# 基本的な使い方
ssh -o ProxyCommand='quicport ssh-proxy --server example.com:39000 --psk secret --remote-destination 22' ubuntu@example.com

# SSH の %h と %p を使用
ssh -o ProxyCommand='quicport ssh-proxy --server %h:39000 --psk secret --remote-destination %p' ubuntu@example.com

# X25519 認証
ssh -o ProxyCommand='quicport ssh-proxy --server %h:39000 --privkey KEY --server-pubkey PUBKEY --remote-destination %p' ubuntu@example.com

# ~/.ssh/config に設定
Host myserver
    HostName example.com
    User ubuntu
    ProxyCommand quicport ssh-proxy --server %h:39000 --psk secret --remote-destination %p
```

**注意事項:**

- **ログ出力は stderr**: stdout は SSH プロトコルデータ専用のため、ログは stderr に出力されます
- **非対話モード**: TOFU の未知ホスト確認は行えません。事前に `quicport client` で known_hosts に登録するか、`--insecure` を使用してください
- **プロトコル**: 内部的には LPF (Local Port Forwarding) プロトコルを使用します

### データプレーンモード (data-plane)

QUIC 接続ハンドラとして動作するデータプレーンを起動します。
通常はコントロールプレーン（`quicport control-plane`）から起動されますが、直接起動も可能です。

```bash
quicport data-plane [OPTIONS]
```

**オプション:**

| オプション | 必須 | 説明 |
|-----------|------|------|
| `--listen`, `-l` | No | QUIC リッスンアドレス（デフォルト: `0.0.0.0:39000`） |
| `--drain-timeout` | No | DRAIN 状態のタイムアウト秒数（デフォルト: `0` = 無限） |
| `--control-plane-url` | Yes | コントロールプレーンの HTTP API URL（HTTP IPC 接続用） |
| `--quic-keep-alive` | No | QUIC keep-alive interval（秒）。NAT テーブル維持のための ping 送信間隔（デフォルト: `5`）。環境変数 `QUICPORT_QUIC_KEEP_ALIVE` でも指定可 |
| `--quic-idle-timeout` | No | QUIC max idle timeout（秒）。この時間応答がなければ接続をクローズ（デフォルト: `90`）。環境変数 `QUICPORT_QUIC_IDLE_TIMEOUT` でも指定可 |

**動作:**

データプレーンは `--control-plane-url` で指定したコントロールプレーンに HTTP IPC で接続し、認証設定を取得します。
通常はコントロールプレーン（`quicport control-plane`）から自動的に起動されるため、直接起動する必要はありません。

**例:**

```bash
# HTTP IPC でコントロールプレーンに接続してデータプレーンを起動
quicport data-plane --listen 0.0.0.0:39000 --control-plane-url http://127.0.0.1:39000
```

### 制御コマンド (ctl)

実行中のデータプレーンを管理するためのコマンドです。

```bash
quicport ctl <COMMAND>
```

**サブコマンド:**

| コマンド | 説明 |
|----------|------|
| `status` | 全データプレーンの状態を表示 |
| `drain --dp-id <DP_ID>` | 特定のデータプレーンに DRAIN を送信 |

**共通オプション:**

| オプション | 必須 | 説明 |
|-----------|------|------|
| `--control-plane-addr` | No | コントロールプレーンの接続先アドレス（デフォルト: `127.0.0.1:39000`） |

**drain オプション:**

| オプション | 必須 | 説明 |
|-----------|------|------|
| `--dp-id` / `-d` | Yes | ドレイン対象のデータプレーン ID（16 進数形式、例: `0x3039`） |

**例:**

```bash
# 全データプレーンの状態を確認
quicport ctl status

# 特定のデータプレーンをドレイン
quicport ctl drain --dp-id 0x3039

# コントロールプレーンのアドレスを指定
quicport ctl status --control-plane-addr 127.0.0.1:39001
```

**出力例 (status):**

```
Data Planes:
PID        State        Connections  Bytes Sent      Bytes Received
----------------------------------------------------------------
12345      ACTIVE       3            10485760        5242880
12346      DRAINING     1            524288          262144
```

## アーキテクチャ

### データプレーン/コントロールプレーン分離

quicport はサーバー再起動時の接続維持を実現するため、データプレーンとコントロールプレーンを分離したアーキテクチャを採用しています。

#### cgroup 分離アーキテクチャ

コントロールプレーン (cp) とデータプレーン (dp) は **異なる cgroup** で動作します。
これにより、cp が終了しても dp は独立して動作を継続できます。

```
+------------------------------------------------------------------+
| systemd (quicport.service)                                       |
|   └─ ExecStart: /path/to/quicport.sh                             |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
| quicport.sh (シェルスクリプト)                                     |
|   1. systemd-run で data-plane を別 cgroup に起動                 |
|   2. exec で control-plane に置き換わる（PID 引き継ぎ）            |
+------------------------------------------------------------------+
          |                                   |
          v                                   v
+------------------------+    +------------------------------------+
| cgroup A (systemd)     |    | cgroup B (systemd-run)             |
| +--------------------+ |    | +--------------------------------+ |
| | Control Plane      | |    | | Data Plane                     | |
| | (quicport cp)      |<-----| | (quicport dp)                  | |
| |                    | |    | |                                | |
| | - 認証ポリシー管理  | |    | | - QUIC 終端                     | |
| | - API サーバー     | |    | | - 認証実行                      | |
| | - dp の管理        | |    | | - データ転送                    | |
| +--------------------+ |    | | - SO_REUSEPORT で LISTEN       | |
+------------------------+    | +--------------------------------+ |
                              +------------------------------------+
```

**プラットフォーム非依存設計:**

- quicport バイナリ自体はプラットフォーム固有の機能（systemd-run, cgroup 等）に依存しない
- プラットフォーム依存の部分はシェルスクリプトに切り出す
- **Linux (systemd)**: `quicport.sh` で systemd-run を使用した cgroup 分離
- **UNIX (非 systemd)**: control-plane が data-plane を自動起動（setsid で独立セッション化）。graceful restart は eBPF 非対応のため非サポート
- **Windows**: 自動起動は未サポート。手動で cp と dp を別々に起動

**責務分離:**

| コンポーネント | 責務 |
|--------------|------|
| **シェルスクリプト** | systemd-run での dp 起動、exec での cp 起動 |
| **コントロールプレーン** | 認証ポリシー管理、API サーバー、HTTP IPC での dp 管理 |
| **データプレーン** | QUIC 終端、クライアント認証、TCP/UDP 接続維持、データ転送 |

**systemd 環境での起動例 (quicport-starter):**

```bash
#!/bin/bash
# quicport-starter スクリプト概要
# 設定例:
#   QUICPORT_DP_ADDR=0.0.0.0:39000       # DP QUIC リッスンアドレス
#   QUICPORT_CP_ADDR=127.0.0.1:39000      # CP HTTP IPC アドレス
#   QUICPORT_CP_URL=http://127.0.0.1:39000

# 1. データプレーンを別 cgroup で起動（HTTP IPC モード）
systemd-run --slice=user.slice --unit="quicport-dp-$$.service" \
  quicport data-plane \
    --listen "${QUICPORT_DP_ADDR}" \
    --control-plane-url "${QUICPORT_CP_URL}"

# 2. コントロールプレーンを起動（PID を引き継ぎ）
exec quicport control-plane \
  --control-plane-addr "${QUICPORT_CP_ADDR}" \
  --data-plane-addr "${QUICPORT_DP_ADDR}" \
  ...
```

#### UNIX 上での自動 data-plane 起動（非 systemd 環境）

systemd がない環境（macOS 等）では、control-plane が data-plane プロセスを自動的に起動します。
`--no-auto-dataplane` オプションで無効化できます。

**起動メカニズム（`start_dataplane()` / `src/control_plane.rs`）:**

1. `std::env::current_exe()` で実行中バイナリのパスを取得（同一バイナリを再利用）
2. 以下の引数で子プロセスを構築:
   - `--log-format <format>`: CP の値をそのまま継承（**唯一継承されるグローバルオプション**）
   - `data-plane` サブコマンド
   - `--listen <dp_listen_addr>`: CP の `--data-plane-addr` で指定されたアドレス
   - `--control-plane-url http://127.0.0.1:<cp_port>`: **常にループバック**。`<cp_port>` は CP の `--control-plane-addr` のポート
3. `pre_exec` で `libc::setsid()` を呼び出し、独立したセッションを作成
   - 親プロセス（CP）が終了しても DP は動作を継続
4. `spawn()` で子プロセスを起動（stdin=null, stdout/stderr=inherit）
5. PID ベースで DP の HTTP IPC 登録を待機（500ms 間隔、最大 20 回 = 10 秒）

**制約:**
- UNIX のみサポート（`#[cfg(unix)]`）。Windows では未実装
- `--log-output` は継承されない（DP は stdout に出力）
- `--control-plane-url` は常に `http://127.0.0.1:<cp_port>` 固定（外部 IF は使用しない）

```
control-plane                           data-plane (子プロセス)
    |                                        |
    |-- current_exe() でパス取得              |
    |-- setsid() + spawn() ---------------->|
    |                                        |-- HTTP IPC で CP に接続
    |                                        |-- 登録リクエスト送信
    |<-- PID ベースで登録確認 (最大10秒) ------|
    |                                        |
    |   [CP 終了しても DP は継続動作]          |
```

#### 起動シーケンス

```
systemd                quicport.sh              data-plane              control-plane
   |                        |                        |                        |
   |-- ExecStart ---------->|                        |                        |
   |                        |                        |                        |
   |                        |-- systemd-run -------->|                        |
   |                        |   (別 cgroup で起動)    |                        |
   |                        |                        |                        |
   |                        |                        |-- cp への接続をリトライ -->|
   |                        |                        |   (cp 起動待ち)          |
   |                        |                        |                        |
   |                        |-- exec --------------->|                        |
   |                        |   (PID 引き継ぎ)        |                        |
   |                        |                        |                        |
   |<-- systemd は cp を追跡 -------------------------|                        |
   |                        |                        |                        |
   |                        |                        |<-- 接続成功 -------------|
   |                        |                        |                        |
   |                        |                        |-- ACTIVE 状態に遷移 ---->|
   |                        |                        |                        |
   |                        |                        |-- SO_REUSEPORT で LISTEN |
   |                        |                        |                        |
```

1. systemd が `quicport.sh` を起動
2. シェルスクリプトが `systemd-run` で dp を別 cgroup に起動
3. dp は cp への接続を試行（cp 起動まで接続リトライ）
4. シェルスクリプトが `exec` で cp に置き換わる（systemd から直接 cp が見える）
5. dp が cp への接続に成功し、ACTIVE 状態に遷移
6. dp が SO_REUSEPORT で QUIC ポートを LISTEN 開始

#### 終了シーケンス（graceful shutdown）

```
systemd                control-plane            data-plane
   |                        |                        |
   |-- SIGTERM ------------>|                        |
   |                        |                        |
   |                        |-- Drain コマンド送信 -->|
   |                        |   (HTTP IPC 経由)       |
   |                        |                        |
   |                        |-- コマンド配信待機 -----|  (最大 5 秒)
   |                        |   (dp が受信するまで)    |
   |                        |                        |
   |                        |                        |-- 新規接続の受付を停止
   |                        |                        |-- DRAINING 状態に遷移
   |                        |                        |
   |                        |-- プロセス終了          |
   |                        |                        |
   |<-- cp 終了を検知 -------|                        |
   |                        |                        |
   |                        |                        |-- 既存コネクション処理継続
   |                        |                        |   (別 cgroup なので独立動作)
   |                        |                        |
   |                        |                        |-- 全コネクション終了
   |                        |                        |-- または drain_timeout 経過
   |                        |                        |
   |                        |                        |-- プロセス終了
   |                        |                        |
```

1. systemd から cp に SIGTERM
2. cp から dp に Drain コマンドを送信（HTTP IPC 経由）
3. cp は dp がコマンドを受信するまで待機（最大 5 秒）
4. dp が新規接続の受付を停止し、DRAINING 状態に遷移
5. cp がプロセス終了
6. dp は別 cgroup で独立して動作を継続
7. dp は既存コネクションをすべて処理完了（または drain_timeout 経過）後に終了

**DRAINING 状態での動作:**

- 新規 TCP/UDP 接続の受付を拒否
- 新規 QUIC ストリームの受付を拒否
- 既存のリレータスク（データ転送）は継続
- すべてのリレータスクが完了するまで待機してから終了

#### 再起動シーケンス（systemctl restart）

```
systemd                旧 cp                     旧 dp                    新 cp + dp
   |                     |                         |                          |
   |-- SIGTERM --------->|                         |                          |
   |                     |                         |                          |
   |                     |-- graceful-shutdown --->|                          |
   |                     |                         |                          |
   |                     |                         |-- DRAINING               |
   |                     |                         |                          |
   |                     |-- プロセス終了           |                          |
   |                     |                         |                          |
   |-- ExecStart (quicport.sh) ------------------------------------------>|
   |                     |                         |                          |
   |                     |                         |      新 dp が SO_REUSEPORT で
   |                     |                         |      同一ポートを LISTEN
   |                     |                         |                          |
   |                     |                         |-- 既存コネクション処理 -->|
   |                     |                         |   (DRAINING 継続)         |
   |                     |                         |                          |
   |                     |                         |-- 全コネクション終了      |
   |                     |                         |-- プロセス終了            |
   |                     |                         |                          |
```

- 新規接続は新しい dp が処理
- 旧 dp は DRAINING 状態で既存コネクションのみ処理
- SO_REUSEPORT により新旧 dp が同一ポートで共存可能

**複数 DRAINING データプレーンの許容:**

連続した restart により、複数の DRAINING データプレーンが同時に存在することを許容する。
各 DRAINING データプレーンは独立して動作し、それぞれの接続数が 0 になったら自動終了する。
コントロールプレーンは全データプレーンをメモリ内（HashMap）で管理する。

**データプレーンの状態遷移:**

```
STARTING --> ACTIVE --> DRAINING --> TERMINATED
    |           |           |
    |           +-----------+  (drain_timeout 経過)
    |                       |
    +-----------------------+  (shutdown コマンド)
```

| 状態 | 説明 |
|-----|------|
| `STARTING` | 起動中、cp への接続リトライ |
| `ACTIVE` | 通常稼働中、新規接続受付可能 |
| `DRAINING` | ドレイン中、新規接続拒否、既存接続のみ処理 |
| `TERMINATED` | 終了済み |

#### エラーハンドリング

| 状況 | 動作 |
|------|------|
| データプレーンクラッシュ | コントロールプレーンが stale 検出で検知し、新しいインスタンスを起動 |
| バックエンド接続失敗 | クライアントにエラーを返し、該当接続をクローズ |
| 認証失敗 | 制御ストリームをクローズし、接続を終了 |
| DRAIN タイムアウト | 残りの接続を強制切断して終了（デフォルト: drain_timeout=0 で無限待機、すなわち全接続完了まで待つ） |
| コントロールプレーン切断 | 最後に受信したポリシーで動作継続し、CP 復旧時に自動再登録 |

#### dp_id / server_id の生成と登録

データプレーンは起動時に一意の ID を生成し、コントロールプレーンに登録します（`src/data_plane.rs`）。

**ID の形式:**

- **server_id**: `u32` 型。値の範囲は `1..65535`（0 は eBPF map のデフォルト ACTIVE DP 用に予約、65536 は `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` の上限）
- **dp_id**: server_id の 16 進数文字列表現（`format!("{:#06x}", server_id)` → 例: `0x3039`）
- server_id は QUIC Connection ID に埋め込まれ（`[server_id: 4B][counter: 4B]`）、eBPF ルーティングに使用される
- CID の有効期限は 24 時間に設定されている（graceful restart を考慮）
- dp_id は HTTP IPC API や CLI での識別子として使用される

**生成アルゴリズム:**

```
server_id = (rand::random::<u32>() % 65535) + 1
```

**登録フロー:**

```
data-plane                              control-plane
    |                                        |
    |-- server_id をランダム生成              |
    |-- SendStatus(dp_id, ...) ------------->|
    |                                        |
    |   [成功: 200 OK]                        |
    |<-- { auth_policy, config } ------------|
    |                                        |
    |   [dp_id 重複: 409 Conflict]            |
    |<-- DP_ID_DUPLICATE --------------------|
    |-- 新しい server_id を再生成             |
    |-- SendStatus(new_dp_id, ...) --------->|
    |   (最大 10 回リトライ)                   |
    |                                        |
    |   [CP 接続失敗: ネットワークエラー等]     |
    |-- 1 秒待機後にリトライ                   |
    |-- SendStatus(dp_id, ...) ------------->|
    |   (最大 30 回リトライ)                   |
```

**リトライポリシー:**

| エラー種別 | リトライ上限 | 間隔 | 動作 |
|-----------|------------|------|------|
| dp_id 重複（409 Conflict / `DP_ID_DUPLICATE`） | 10 回 | 即座 | 新しい server_id を再生成して再試行 |
| CP 接続失敗（ネットワークエラー等） | 30 回 | 1 秒 | 同じ server_id で再試行 |

**定常運用時の再登録:**

- 登録成功後、DP は 5 秒間隔で CP にステータスを送信
- CP から 404 Not Found が返った場合（CP 再起動等）、自動的に再登録を試行

#### eBPF パケットルーティング（Linux）

- quicport は Linux 環境で `BPF_PROG_TYPE_SK_REUSEPORT` ベースの eBPF プログラムを使用し、QUIC Connection ID に基づいてパケットを正しい DP プロセスにルーティングする
- `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` マップで server_id → ソケットの対応を管理
- Connection ID フォーマット: `[server_id: 4B][counter: 4B]` (8 bytes, Big Endian)
- マップとプログラムは `/sys/fs/bpf/quicport/` にピン留めされ、graceful restart 時に新旧プロセス間で共有される

##### eBPF アタッチ順序の制約

`SO_ATTACH_REUSEPORT_EBPF` は `bind()` の **前に** 呼び出す必要がある。`bind()` 後にアタッチした場合、一部のカーネルでは既存の reuseport グループにプログラムが適用されない。

ソケット作成からエンドポイント構築までの正しい手順（`src/data_plane.rs`）:

1. `create_unbound_udp_socket()` — 未バインドソケット作成（`SO_REUSEPORT` 付き）
2. `attach_to_socket()` — eBPF プログラムをアタッチ（**bind 前**）
3. `bind_udp_socket()` — ソケットをバインド
4. `create_server_endpoint_with_socket()` — QUIC Endpoint 作成

##### デフォルト ACTIVE DP ルーティング (key=0)

新規 QUIC コネクション（Initial パケット）の Destination CID はクライアントが生成したランダム値であるため、eBPF の `server_id` ルックアップが失敗する。この場合、カーネルの SO_REUSEPORT デフォルト（ハッシュベース分散）にフォールスルーすると、DRAINING な DP にも新規接続が届く可能性がある。

これを防ぐため、`socket_map` の **key=0 をデフォルト ACTIVE DP エントリ**として使用する:

**key=0 fallback が適用されるのは Initial パケット（最初のパケット）のみ。** コネクション確立後の流れは以下の通り:

1. **Initial パケット**: クライアントが生成したランダムな Destination CID → `server_id` 抽出失敗 → **key=0 fallback で ACTIVE DP にルーティング**
2. **ハンドシェイク中**: DP が自身の `server_id` を埋め込んだ CID（`[server_id:4B][counter:4B]`）をクライアントに発行
3. **以降のパケット**: クライアントは DP 発行の CID を Destination CID として使用 → eBPF が `server_id` を正しく抽出 → **key={server_id} で該当 DP に直接ルーティング**

この仕組みにより、graceful restart 時に旧 DP の既存接続は旧 DP の `server_id` 入りの CID でルーティングされ続け、新規接続だけが key=0 経由で新 DP に向かう。

**DP 側の実装:**

- **登録**: DP 起動時に `register_server(sid, socket)` の直後に `register_default_active(socket)` で key=0 に自身のソケットを登録（`MapFlags::ANY` で常に上書き）
- **eBPF fallback**: `extract_server_id()` 失敗時、または `bpf_sk_select_reuseport()` 失敗時に key=0 で再ルックアップ
- **DRAINING 遷移時**: key=0 は削除しない（新 DP が上書き登録するまで保持）
- **Drop 時**: key=0 を削除（ソケット無効化による stale 防止）
- **CP stale cleanup**: ACTIVE な DP が 0 台の場合、key=0 も削除

| シナリオ | 動作 |
|---------|------|
| ACTIVE 1 台のみ | key=0 → ACTIVE DP。新規接続は確実にそこへ |
| ACTIVE 1 + DRAINING 1 | key=0 → ACTIVE DP（新 DP が上書き済み）。既存接続は CID ベースルーティング |
| 全 DP DRAINING（ACTIVE なし） | key=0 は最後の ACTIVE だった DP を指す → CP cleanup で key=0 削除 → カーネルデフォルト |
| ACTIVE DP クラッシュ | key=0 のソケットは無効 → `bpf_sk_select_reuseport` 失敗 → カーネルデフォルト。CP stale cleanup で key=0 も削除 |

##### なぜ eBPF が必要か

- QUIC は UDP 上のプロトコルであり、TCP のように `accept()` が connected fd を返さない
- 複数プロセスが SO_REUSEPORT で同一ポートに BIND する場合、到着パケットを Connection ID に基づいて正しいプロセスに振り分けるカーネルレベルのパケットステアリングが必要
- Classic BPF (cBPF) では `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` にアクセスできず、マップのピン留めもできないため代替不可
- macOS にはカーネルレベルの UDP パケットステアリング手段が存在しないため、macOS では graceful restart を非サポート

##### eBPF 利用不可・アタッチ失敗時のフォールバック（Linux）

Linux 環境であっても、eBPF が利用できない、またはロード・アタッチに失敗する場合がある。データプレーンはこのケースを検出し、カーネルのデフォルト `SO_REUSEPORT` 動作（ハッシュベース分散）にフォールバックする（`src/data_plane.rs`）。

**フォールバックが発生する条件と挙動:**

| 条件 | ログレベル | 挙動 |
|------|-----------|------|
| `/sys/fs/bpf` が存在しない（`is_ebpf_available()` = false） | INFO | eBPF を使用せず、カーネルデフォルト `SO_REUSEPORT` で動作 |
| `EbpfRouter::load()` 失敗（権限不足、カーネル非対応等） | WARN | カーネルデフォルト `SO_REUSEPORT` にフォールバック。**graceful restart 時の接続リセットの可能性を警告** |
| `attach_to_socket()` 失敗（`setsockopt(SO_ATTACH_REUSEPORT_EBPF)` エラー） | WARN | カーネルデフォルト `SO_REUSEPORT` にフォールバック。**graceful restart 時の接続リセットの可能性を警告** |

**フォールバック時の影響:**

- **単一 DP 運用時**: 影響なし。パケットは唯一の DP に配送される
- **graceful restart 時（複数 DP 共存）**: カーネルの `SO_REUSEPORT` ハッシュベース分散により、既存の QUIC 接続のパケットが新 DP に誤配送される可能性がある。これにより **既存接続がリセットされる** 場合がある
- **フォールバック状態でもデータプレーンは正常に起動・動作する**（eBPF はあくまで graceful restart 時の接続維持を改善するためのオプション機能）

**フォールバック判定のフロー（`src/data_plane.rs`）:**

```text
Linux?
├── Yes
│   └── is_ebpf_available()?
│       ├── Yes
│       │   └── EbpfRouter::load()
│       │       ├── Ok → attach_to_socket()
│       │       │         ├── Ok → eBPF ルーティング有効 ✓
│       │       │         └── Err → WARN + SO_REUSEPORT フォールバック ⚠
│       │       └── Err → WARN + SO_REUSEPORT フォールバック ⚠
│       └── No → INFO + SO_REUSEPORT フォールバック
└── No (macOS 等)
    └── SO_REUSEPORT のみ（eBPF 非対応）
```

> **運用上の注意**: Linux 環境で graceful restart を安全に行うには、eBPF が正常に動作している必要がある。フォールバックが発生している場合、ログに警告メッセージ `"Falling back to kernel default SO_REUSEPORT behavior. This may cause connection resets during graceful restart."` が出力されるため、監視対象に含めることを推奨する。

##### eBPF map のライフサイクル管理

- **エントリ追加**: DP が起動時に `register_server(server_id, socket)` で自身のエントリを追加（ソケット fd が必要なため DP でのみ実行可能）
- **エントリ削除（正常終了）**: DP が `EbpfRouter::drop()` で自身のエントリを削除
- **エントリ削除（異常終了フォールバック）**: CP がバックグラウンドタスクで定期的に stale エントリを検出・削除
  - DP の `last_active`（最終ハートビート時刻）が設定可能なタイムアウト（デフォルト 300 秒）を超過した場合、stale と判定
  - CP がピン留めされた eBPF map を開き、該当 server_id のエントリを削除
  - チェック間隔: 10 秒

##### 必要な権限

- `CAP_BPF`: eBPF プログラムのロード
- `CAP_NET_ADMIN`: ソケットへのアタッチ
- `/sys/fs/bpf` への書き込み権限（ピン留め用）

#### HTTP IPC 通信

コントロールプレーンとデータプレーン間の通信には HTTP/JSON API を使用します（RPC スタイル）。

```
┌─────────────────────────────────────────────────────────────────────┐
│ HTTP IPC アーキテクチャ                                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Data Plane                       Control Plane                     │
│       │                               │                             │
│       │ ──POST /dp/SendStatus───────> │ (初回=登録 / 以降=5秒周期)  │
│       │ <─── { dp_id, auth_policy } ─ │                             │
│       │                               │                             │
│       │ ──POST /dp/ReceiveCommand───> │ (長ポーリング)              │
│       │ <─── { commands: [...] } ──── │                             │
│       │                               │                             │
│  CLI / 外部                                                         │
│       │                               │                             │
│       │ ──POST /admin/DrainDataPlane> │ (管理操作)                  │
│       │ <─── { status: draining } ─── │                             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**HTTP IPC のメリット:**

- デバッグのしやすさ（curl で確認可能）
- プロトコルの標準化（HTTP/JSON）
- 外部連携の容易さ

**タイムアウト設定:**

| 項目 | 値 | 説明 |
|------|-----|------|
| サーバー側 wait_timeout | 30 秒 | コマンドがない場合、30 秒後に空レスポンスを返す |
| クライアント HTTP タイムアウト | 35 秒 | サーバーの wait_timeout より少し長く |
| TCP キープアライブ | 15 秒間隔 | 接続が切れないようにキープアライブ |

#### Control Plane 自動再登録機能

data-plane は control-plane が再起動した場合、自動的に新しい control-plane に再登録します。

```
data-plane                    旧 control-plane              新 control-plane
     |                              |                              |
     |-- ReceiveCommand ---------->|                              |
     |                              |                              |
     |                              X (cp 終了)                    |
     |                              |                              |
     |-- ReceiveCommand -------->  X (接続エラー)                 |
     |                              |                              |
     |   (リトライ)                  |                              |
     |                              |                              |
     |                              |                      新 cp 起動
     |                              |                              |
     |-- ReceiveCommand ----------X---------------------->|       |
     |   (404 NOT_FOUND)            |                      |       |
     |                              |                      |       |
     |-- SendStatus (初回登録) ------------------------------>|    |
     |<-- { dp_id, auth_policy } --------------------------       |
     |                              |                              |
     |-- SendStatus (状態更新) ---------------------------------->|
     |   (現在の状態を報告)           |                              |
     |                              |                              |
     |-- ReceiveCommand (継続) ---------------------------------->|
     |                              |                              |
```

**動作詳細:**

1. data-plane は ReceiveCommand で control-plane からコマンドを取得
2. control-plane が終了すると、接続エラーまたは 404 NOT_FOUND が返る
3. 404 NOT_FOUND を検出した場合、data-plane は自動的に再登録を試行
4. 再登録成功後、現在の状態（ACTIVE または DRAINING）を Status イベントで報告
5. **DRAINING 状態は維持される**（古い data-plane が ACTIVE に戻らないようにする）

**状態維持の重要性:**

- DRAINING 状態の data-plane が再登録後も DRAINING のままであることで、graceful shutdown が正しく機能
- 新しい control-plane は再登録された data-plane の状態を正しく認識可能

### トランスポート層

```
+-------------------+     QUIC Connection      +-------------------+
|                   |  (UDP port 9000)         |                   |
|  quicport Client  | <======================> |  quicport Server  |
|                   |                          |                   |
+-------------------+                          +-------------------+
        |                                              |
        | TCP/UDP                                      | TCP/UDP
        | (local:22)                                   | (remote:9022)
        v                                              v
+-------------------+                          +-------------------+
|  Local Service    |                          | External Clients  |
|  (e.g., sshd)     |                          |                   |
+-------------------+                          +-------------------+
```

### QUIC トランスポート

**全てのトラフィックに QUIC Stream を使用します。**

#### ALPN プロトコル識別子

QUIC 接続の TLS ハンドシェイク時に、ALPN (Application-Layer Protocol Negotiation) として `quicport/1` を使用します。

```
ALPN: quicport/1
```

- サーバー・クライアントの両方が `quicport/1` を ALPN に設定します
- これにより、同一ポートで他の QUIC アプリケーション（HTTP/3 等）と共存する場合でも、quicport のトラフィックを正しく識別できます
- バージョン番号 `/1` は、将来のプロトコル非互換変更時にインクリメントされます

| ローカルプロトコル | QUIC トランスポート |
|-------------------|---------------------|
| TCP | QUIC Stream |
| UDP | QUIC Stream |

> **設計判断:** TCP/UDP ともに QUIC Stream でトンネリングします。
>
> **QUIC Datagram を採用しない理由:**
> - Datagram は MTU 制限があり、大きなパケットを送信できない
> - L7 トンネリングでは MTU を制御する手段がない
> - フラグメンテーションを実装すると順序制御が必要になり、Stream を再実装するのと同等の複雑さになる
>
> **QUIC Stream のメリット:**
> - 任意サイズのデータを扱える（自動フラグメンテーション）
> - 順序保証・再送制御が組み込み
> - 複数 Stream 間で Head-of-Line Blocking が軽減される
> - SSH トンネル (TCP over TCP) より効率的な輻輳制御

### 認証方式

> **設計判断:** TLS-PSK ではなくアプリケーション層での認証プロトコルを採用しています。
>
> **TLS-PSK を採用しなかった理由:**
> - QUIC の TLS 実装に使用している [rustls](https://github.com/rustls/rustls) が外部 PSK（External PSK）をサポートしていない
> - rustls の [Issue #174](https://github.com/rustls/rustls/issues/174) "Status of PSK Support?" は 2018 年からオープンのまま
> - TLS-PSK サポートの PR (PR #2424) は 2025 年 6 月に abandon（放棄）された
>
> **現在のアプローチ:**
> - QUIC (rustls) は自己署名証明書でトランスポート暗号化のみを提供
> - 認証はアプリケーション層で独自プロトコル（PSK または X25519）を実装
> - 認証完了後のデータ転送は QUIC の TLS 1.3 暗号化のみ（二重暗号化なし）
>
> **セキュリティ上の影響:**
> - TLS-PSK と同等のセキュリティ特性を提供（HMAC-SHA256、エフェメラル DH、Forward Secrecy）
> - WireGuard 等と同様に、TLS に依存しない独自認証プロトコルを採用するアプローチ

**X25519 公開鍵認証**（WireGuard スタイル）を採用しています。相互認証に対応しています。

#### 認証モデル

- **サーバー**: 秘密鍵（`--privkey`）+ 認可されたクライアントの公開鍵リスト（`--client-pubkeys`）
- **クライアント**: 秘密鍵（`--privkey`）+ 期待するサーバーの公開鍵（`--server-pubkey`）

#### 鍵フォーマット

WireGuard と同じ形式を採用:
- 32 バイトの Curve25519 鍵を Base64 エンコード
- 例: `IexqQqW8ngM33aoJWqheXfW+11hL6A3h6kpO8uNl9Ws=`

#### 認証フロー（相互認証）

```
Client                                  Server
  |                                       |
  |--- "QUICPORT_AUTH" (13 bytes) ------>|
  |--- Client Public Key (32 bytes) ---->|
  |--- Client Challenge (32 bytes) ----->|
  |                                       |
  |         Check if pubkey is authorized |
  |                                       |
  |<-- Server Public Key (32 bytes) -----|
  |<-- Server Ephemeral Pubkey (32 bytes)|
  |<-- Server Challenge (32 bytes) ------|
  |<-- Server Response (32 bytes) -------|
  |                                       |
  |    Verify: server_pub == expected     |
  |    shared_static = X25519(client_priv, server_pub)
  |    Verify: server_response == HMAC(shared_static, client_challenge)
  |                                       |
  |    shared_eph = X25519(client_priv, server_eph)
  |    client_response = HMAC(shared_eph, server_challenge)
  |                                       |
  |--- Client Response (32 bytes) ------>|
  |                                       |
  |    shared = X25519(eph_priv, client_pub)
  |    Verify HMAC (constant-time)        |
```

#### セキュリティ特性

- **相互認証**: クライアントとサーバーがお互いを認証
- **Forward Secrecy**: サーバーは接続ごとにエフェメラル鍵ペアを生成
- **タイミング攻撃対策**: HMAC 検証に定数時間比較（`subtle::ConstantTimeEq`）を使用
- **暗号学的ハッシュ**: HMAC-SHA256 によるレスポンス計算
- **MITM 攻撃対策**: クライアントがサーバーの公開鍵を検証

#### 認証要件（X25519 使用時）

- **サーバー**: `--privkey` の指定が必須（相互認証のため）
- **クライアント**: `--server-pubkey` の指定が必須（MITM 攻撃防止のため）

### PSK 認証

事前共有鍵（PSK）による認証も利用可能です。
鍵管理の観点から X25519 公開鍵認証を推奨しますが、PSK も HMAC-SHA256 とエフェメラル DH により安全に実装されています。

#### PSK 自動生成

サーバー起動時に認証オプション（`--psk`, `--client-pubkeys`, `--client-pubkeys-file`）が何も指定されていない場合、
PSK が自動生成されます:

1. `~/.config/quicport/psk` が存在すれば、既存の PSK を読み込む
2. 存在しなければ、32 バイトのランダムデータを生成し、Base64 エンコードして保存

これにより、初回起動時でも認証なしでサーバーが公開されることはありません。

#### PSK 認証フロー

```
Client                                  Server
  |                                       |
  |--- "QUICPORT_PSK" (12 bytes) -------->|
  |--- Timestamp (8 bytes, BE) ---------->|
  |--- Client Ephemeral Pubkey (32 bytes)->|
  |--- Client Auth HMAC (32 bytes) ------>|  HMAC(PSK, timestamp || client_eph_pub)
  |                                       |
  |         Verify timestamp within 30s   |
  |         Verify Client Auth HMAC       |
  |                                       |
  |<-- Server Ephemeral Pubkey (32 bytes)-|
  |<-- Server Challenge (32 bytes) -------|
  |<-- Server Auth HMAC (32 bytes) -------|  HMAC(PSK, challenge || server_eph_pub)
  |                                       |
  |    Verify Server Auth HMAC            |
  |    shared = X25519(client_eph_priv, server_eph_pub)
  |                                       |
  |--- Client DH Response (32 bytes) ---->|  HMAC(shared, server_challenge)
  |                                       |
  |    shared = X25519(server_eph_priv, client_eph_pub)
  |    Verify DH Response (constant-time) |
```

#### PSK 認証のセキュリティ特性

- **HMAC-SHA256**: 暗号学的に安全なハッシュ関数を使用
- **タイムスタンプ検証**: 30 秒以内のクロック差を許容（リプレイ攻撃対策）
- **相互認証**: クライアントとサーバーがお互いを認証
- **Forward Secrecy**: 接続ごとにエフェメラル X25519 鍵ペアを生成
- **定数時間比較**: タイミング攻撃対策

### TOFU (Trust On First Use) 証明書検証

クライアントは SSH と同様の TOFU 方式でサーバー証明書を検証します。

#### 動作

1. **初回接続時**: サーバー証明書のフィンガープリントを表示し、ユーザーに確認を求める
2. **承認された場合**: フィンガープリントを `known_hosts` ファイルに保存
3. **再接続時**: 保存されたフィンガープリントと照合し、一致すれば自動的に接続
4. **証明書変更時**: MITM 攻撃の可能性を警告し、ユーザーに確認を求める

#### 出力例

```
The authenticity of host '127.0.0.1:39000' can't be established.
Certificate details:
  SHA256 Fingerprint: FA:A3:D5:0A:0A:62:1C:DF:60:93:49:85:45:B6:C4:E7:...
  Subject: CN=rcgen self signed cert
  Issuer: CN=rcgen self signed cert
  Valid from: Jan  1 00:00:00 1975 +00:00
  Valid until: Jan  1 00:00:00 4096 +00:00

Are you sure you want to continue connecting? [y/N]: y
Warning: Permanently added '127.0.0.1:39000' to the list of known hosts
         (/Users/user/.local/share/quicport/known_hosts:4).
```

#### 証明書変更時の警告

```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
...
```

### ファイル配置

quicport は以下のディレクトリにファイルを配置します（XDG Base Directory Specification 準拠）:

| パス | 用途 |
|------|------|
| `~/.config/quicport/server.crt` | サーバー証明書（DER 形式） |
| `~/.config/quicport/server.key` | サーバー秘密鍵（DER 形式、パーミッション 0600） |
| `~/.config/quicport/psk` | 自動生成された PSK（Base64 形式、32 バイト） |
| `~/.local/share/quicport/known_hosts` | クライアントの既知ホスト一覧 |

#### サーバー証明書の永続化

- サーバー起動時、既存の証明書ファイルがあれば読み込み
- なければ自己署名証明書を新規生成して保存
- これにより、サーバー再起動後もクライアントの TOFU 検証が正常に動作

#### known_hosts フォーマット

```
# quicport known_hosts file
# Format: host:port fingerprint

127.0.0.1:39000 FA:A3:D5:0A:0A:62:1C:DF:60:93:49:85:45:B6:C4:E7:...
example.com:9000 AB:CD:EF:...
```

### 接続維持とタイムアウト

- **QUIC トランスポート層の keep-alive** を使用
- デフォルト 5 秒間隔で keep-alive パケットを自動送信（`--quic-keep-alive` で変更可能）
- **Idle timeout**: デフォルト 90 秒間応答がなければ接続をクローズ（`--quic-idle-timeout` で変更可能）
  - クライアントが強制終了された場合でも、最大 idle timeout 以内にサーバーが接続切断を検出

### グレースフルシャットダウン

クライアントは以下のシグナルを受信すると、グレースフルシャットダウンを実行します:

- **SIGINT** (Ctrl+C)
- **SIGTERM** (Docker/systemd などからの終了要求)

シャットダウン時の動作:
1. `SessionClose` メッセージをサーバーに送信
2. QUIC コネクションを正常にクローズ
3. サーバーは即座に TCP リスナーを解放し、ポートを再利用可能に

```
Client                          Server
  |                               |
  |-- SessionClose (Stream 0) -->|
  |                               |
  |      "Client requested session close, releasing port X"
  |                               |
  |<-- Connection Close ---------|
  |                               |
```

### ポート再利用

- サーバーは TCP リスナーに `SO_REUSEADDR` オプションを設定
- クライアント切断後、即座に同じポートで再接続可能

## プロトコル仕様

### 制御メッセージ

クライアントとサーバー間の制御メッセージは QUIC Stream 0 で送受信します。

#### メッセージフォーマット

```
+----------------+----------------+------------------+
| Message Type   | Payload Length | Payload          |
| (1 byte)       | (2 bytes, BE)  | (variable)       |
+----------------+----------------+------------------+
```

#### メッセージタイプ

番号体系:
- `0x0X`: Local Port Forwarding (LPF)
- `0x2X`: Remote Port Forwarding (RPF)
- `0x4X`: Session Control
- `0x6X`: Connection Control

| Type | 名前 | 方向 | 説明 |
|------|------|------|------|
| **LPF (Local Port Forwarding)** ||||
| 0x01 | LocalForwardRequest | Client → Server | ローカルフォワードリクエスト |
| 0x02 | LocalForwardResponse | Server → Client | ローカルフォワードレスポンス |
| 0x03 | LocalNewConnection | Client → Server | 新しいローカル接続の通知 |
| **RPF (Remote Port Forwarding)** ||||
| 0x21 | RemoteForwardRequest | Client → Server | ポート開放リクエスト |
| 0x22 | RemoteForwardResponse | Server → Client | ポート開放レスポンス |
| 0x23 | RemoteNewConnection | Server → Client | 新しい TCP/UDP 接続の通知 |
| **セッション制御** ||||
| 0x41 | SessionClose | 双方向 | QUIC セッション終了 |
| **接続制御** ||||
| 0x61 | ConnectionClose | 双方向 | 個別接続の終了通知 |

#### RemoteForwardRequest ペイロード

```
+----------------+----------------+------------------------+
| Remote Port    | Protocol       | Local Destination      |
| (2 bytes, BE)  | (1 byte)       | (remaining, UTF-8)     |
+----------------+----------------+------------------------+

Protocol:
  0x01 = TCP
  0x02 = UDP

Local Destination:
  クライアント側の転送先を示す文字列（サーバーのログ用メタデータ）
  例: "22", "192.168.1.100:22/tcp"
```

#### RemoteForwardResponse ペイロード

```
+----------------+-------------------+
| Status         | Message (UTF-8)   |
| (1 byte)       | (remaining bytes) |
+----------------+-------------------+

Status:
  0x00 = Success
  0x01 = Port in use
  0x02 = Permission denied
  0x03 = Internal error
```

#### LocalForwardRequest ペイロード (0x05)

```
+----------------+--------------------+------------------------+-------------------+
| Protocol       | Remote Dest Length | Remote Destination     | Local Source      |
| (1 byte)       | (2 bytes, BE)      | (variable, UTF-8)      | (remaining, UTF-8)|
+----------------+--------------------+------------------------+-------------------+

Protocol:
  0x01 = TCP
  0x02 = UDP

Remote Destination:
  サーバー側の転送先アドレス
  例: "192.168.1.100:22", "127.0.0.1:22"

Local Source:
  クライアント側のリッスンポート（サーバーのログ用メタデータ）
  例: "9022/tcp"
```

#### LocalForwardResponse ペイロード (0x06)

```
+----------------+-------------------+
| Status         | Message (UTF-8)   |
| (1 byte)       | (remaining bytes) |
+----------------+-------------------+

Status:
  0x00 = Success
  0x01 = Port in use
  0x02 = Permission denied
  0x03 = Internal error
```

#### RemoteNewConnection ペイロード (0x10) - RPF

```
+------------------+------------------+
| Connection ID    | Protocol         |
| (4 bytes, BE)    | (1 byte)         |
+------------------+------------------+

Protocol:
  0x01 = TCP
  0x02 = UDP
```

**RPF モード:** サーバーが新しい外部接続を受け付けた際にクライアントへ通知します。
- **Connection ID:** 論理的な接続識別子（管理用）
- クライアントは QUIC Stream の先頭 4 バイトから Connection ID を読み取ります

> **注意:** Connection ID は QUIC Stream のヘッダー（先頭 4 バイト、big-endian）にも書き込まれます。
> これにより、RemoteNewConnection メッセージと Stream の到着順序に依存せずに接続を識別できます。

#### LocalNewConnection ペイロード (0x13) - LPF

```
+------------------+------------------+
| Connection ID    | Protocol         |
| (4 bytes, BE)    | (1 byte)         |
+------------------+------------------+

Protocol:
  0x01 = TCP
  0x02 = UDP
```

**LPF モード:** クライアントがローカルポートで新しい接続を受け付けた際にサーバーへ通知します。
- **Connection ID:** 論理的な接続識別子（管理用）
- クライアントは QUIC Stream を開き、先頭 4 バイトに Connection ID を書き込みます

#### ConnectionClose ペイロード

```
+------------------+------------------+
| Connection ID    | Reason           |
| (4 bytes, BE)    | (1 byte)         |
+------------------+------------------+

Reason:
  0x00 = Normal close
  0x01 = Connection refused
  0x02 = Timeout
  0x03 = Error
```

**双方向での使用:**

| 方向 | トリガー | 動作 |
|------|---------|------|
| Server → Client | 外部クライアントが TCP 接続を切断 | クライアントにローカル接続の終了を通知 |
| Client → Server | ローカルサービスが TCP 接続を切断 | サーバーが該当の QUIC Stream と TCP 接続をクローズ |

### データ転送 (QUIC Stream)

各 TCP/UDP 接続に対して **専用の QUIC Stream** を開きます。

#### Stream の割り当て

| Stream ID | 用途 |
|-----------|------|
| 0 | 制御メッセージ専用 |
| 1, 2, 3, ... | データ転送用（接続ごとに1つ） |

#### Stream データフォーマット

Stream は双方向のバイトストリームなので、メッセージ境界を明示する必要があります。

```
+------------------+------------------+
| Length           | Payload          |
| (4 bytes, BE)    | (variable)       |
+------------------+------------------+
```

- **Length:** ペイロードのバイト数
- **Payload:** 生のデータ

> **注意:** TCP トンネリングの場合、Length フレーミングは必須ではありません（ストリームをそのまま中継可能）。
> UDP トンネリングの場合、パケット境界を保持するため Length が必要です。

#### TCP トンネリングの動作

1. サーバーが外部 TCP 接続を受け付ける
2. クライアントへ RemoteNewConnection を通知（Stream 0 経由）
3. サーバーが新しい QUIC Stream を開く
4. クライアントはローカル TCP 接続を確立
5. 双方向でデータを中継（Length フレーミングなし、バイトストリームをそのまま転送）

#### UDP トンネリングの動作

UDP はコネクションレスなため、送信元アドレス (IP:port) で「仮想接続」を管理します。

1. サーバーが UDP パケットを受信
2. 送信元アドレス+ポートで「仮想接続」を識別
3. 新規の送信元の場合:
   - RemoteNewConnection を通知（Stream 0 経由）
   - 新しい QUIC Stream を開く
4. Length-prefixed framing でパケット境界を保持して送信:
   ```
   +------------------+------------------+
   | Length           | Payload          |
   | (4 bytes, BE)    | (variable)       |
   +------------------+------------------+
   ```
5. クライアントはローカル UDP ソケットに転送
6. ローカルからの応答も同じ framing でサーバーに返送
7. サーバーは元の送信元アドレスに応答を返す

## シーケンス図

### RPF (Remote Port Forwarding) 接続確立

```
Client                          Server                      External Client
   |                               |                               |
   |------- QUIC Handshake ------->|                               |
   |    (with X25519 mutual auth)  |                               |
   |                               |                               |
   |--- RemoteForwardRequest (9022/tcp) --->|  (via Stream 0)               |
   |                               |                               |
   |<-- RemoteForwardResponse (Success) ----|  (via Stream 0)               |
   |                               |                               |
   |                               |<----- TCP Connect (9022) -----|
   |                               |                               |
   |<-- RemoteNewConnection (Stream 0) --|  conn_id=1, protocol=TCP      |
   |                               |                               |
   |<-- Open Stream 1 -------------|  データ転送用 + conn_id ヘッダー |
   |                               |                               |
   |--- Connect to local:22 ------>|                               |
   |                               |                               |
   |<====== Stream 1 (Data) ======>|<========= Data Relay ========>|
   |                               |                               |
```

> **注意:** サーバーは RemoteNewConnection 送信後、即座にデータ転送を開始します。
> クライアントはローカル接続を確立してから Stream の読み取りを開始するため、QUIC フロー制御により
> クライアントの準備が整うまでサーバーからの送信は自動的に抑制されます。

### LPF (Local Port Forwarding) 接続確立

```
Local Client                    Client                          Server                      Remote Service
      |                            |                               |                               |
      |                            |------- QUIC Handshake ------->|                               |
      |                            |    (with X25519 mutual auth)  |                               |
      |                            |                               |                               |
      |                            |--- LocalForwardRequest ------>|  remote_dest="192.168.1.100:22"
      |                            |    (via Stream 0)             |                               |
      |                            |                               |                               |
      |                            |<-- LocalForwardResponse ------|  (via Stream 0)               |
      |                            |                               |                               |
      |                            |    Start TCP listener on :9022|                               |
      |                            |                               |                               |
      |---- TCP Connect (9022) --->|                               |                               |
      |                            |                               |                               |
      |                            |--- LocalNewConnection ------->|  conn_id=1, protocol=TCP      |
      |                            |    (via Stream 0)             |                               |
      |                            |                               |                               |
      |                            |--- Open Stream 1 ------------>|  + conn_id ヘッダー            |
      |                            |                               |                               |
      |                            |                               |--- TCP Connect to :22 ------->|
      |                            |                               |                               |
      |<====== Data ======>========|======= Stream 1 (Data) ======>|<========= Data Relay ========>|
      |                            |                               |                               |
```

> **LPF と RPF の主な違い:**
> - **LPF:** クライアントがローカルでリッスンし、QUIC Stream を開く（クライアント → サーバー）
> - **RPF:** サーバーがリモートでリッスンし、QUIC Stream を開く（サーバー → クライアント）

### TCP 接続のライフサイクル

```
External Client                 Server                          quicport Client
      |                            |                                   |
      |---- TCP SYN -------------->|                                   |
      |<--- TCP SYN-ACK -----------|                                   |
      |---- TCP ACK -------------->|                                   |
      |                            |                                   |
      |                            |-- RemoteNewConnection (Stream 0) ------>|
      |                            |   (conn_id=N, protocol=TCP)       |
      |                            |                                   |
      |                            |-- Open Stream N (conn_id header)->|
      |                            |                                   |
      |                            |                     Connect to local:22
      |                            |                                   |
      |---- TCP Data ------------->|======= Stream N (Data) ==========>|
      |                            |      (QUIC フロー制御で同期)        |
      |<--- TCP Data --------------|<====== Stream N (Data) ===========|
      |                            |                                   |
      |---- TCP FIN -------------->|-- ConnectionClose (Stream 0) ---->|
      |                            |   (conn_id=N)                     |
      |                            |                                   |
      |                            |-- Close Stream N ---------------->|
      |                            |                                   |
```

> **注意:** サーバーは RemoteNewConnection 送信後、即座に Stream を開いてデータ転送を開始します。
> クライアントがローカル接続を確立するまで Stream の読み取りを行わないため、
> QUIC フロー制御により送信側（サーバー）も自動的にブロックされます。
> これにより、データロスなく同期が取れます。

### UDP パケットのライフサイクル

```
External Client                 Server                          quicport Client
      |                            |                                   |
      |---- UDP Packet ----------->|                                   |
      |    (src=1.2.3.4:5678)      |                                   |
      |                            |                                   |
      |                            |-- RemoteNewConnection (Stream 0) ------>|
      |                            |   (conn_id=N, protocol=UDP)       |
      |                            |                                   |
      |                            |-- Open Stream N (conn_id header)->|
      |                            |                                   |
      |                            |                     Bind local UDP socket
      |                            |                     Connect to local:53
      |                            |                                   |
      |                            |== Stream N ([len][payload]) =====>|
      |                            |      (Length-prefixed framing)    |
      |                            |                     UDP send to local:53
      |                            |                                   |
      |                            |                     UDP recv from local:53
      |                            |<= Stream N ([len][payload]) ======|
      |                            |                                   |
      |<--- UDP Packet ------------|                                   |
      |    (dst=1.2.3.4:5678)      |                                   |
      |                            |                                   |
```

> **注意:** UDP は送信元アドレス (IP:port) で「仮想接続」を識別します。
> 同じ送信元からの後続パケットは既存の QUIC Stream を再利用します。
> 仮想接続は、QUIC Stream がクローズされた時点でクリーンアップされます。

## セキュリティ考慮事項

1. **鍵の管理**
   - 秘密鍵はファイル経由での読み込みを推奨（`--privkey-file`）
   - 秘密鍵ファイルのパーミッションは 600 を推奨
   - 環境変数でも指定可能だが、プロセスリストに露出しない点で安全

2. **公開鍵認可リスト**
   - サーバー側で `--client-pubkeys-file` を使用し、認可された公開鍵を管理
   - 1 行 1 鍵の形式で、コメント行（`#` で始まる行）をサポート

3. **相互認証**
   - サーバー側: `--privkey` でサーバー秘密鍵を指定し、クライアントがサーバーを認証可能に
   - クライアント側: `--server-pubkey` でサーバー公開鍵を指定し、MITM 攻撃を防止
   - 相互認証を有効にすることを強く推奨

4. **ポート制限**
   - サーバー側で開放可能なポート範囲を制限するオプションを検討
   - Well-known ポート (1-1023) の開放には特別な権限が必要

5. **レート制限**
   - 同時接続数の制限
   - 帯域制限の検討

6. **HTTP IPC セキュリティ**
   - HTTP IPC サーバーは localhost (127.0.0.1) のみでリッスン
   - IPC 自体には認証機構なし（localhost 信頼モデル）
   - データプレーンとコントロールプレーンは同一マシン上で動作する前提

## 非機能要件

### 非同期 I/O

Tokio ランタイムをブロックしないよう、以下の設計方針を採用:

- **ブロッキング I/O の分離**: 標準入力からのユーザー入力（TOFU プロンプトなど）は `tokio::task::spawn_blocking` で専用スレッドに委譲
- **理由**: メインの非同期タスク（QUIC 接続、データ転送）がブロックされることを防止

### IPv6 サポート

IPv6 アドレスを正しく扱うための設計:

- **アドレス表記**: IPv6 アドレスは `[addr]:port` 形式でフォーマット（例: `[::1]:9000`）
- **バインドアドレス自動選択**: 接続先の IP バージョンに応じてクライアントのバインドアドレスを自動選択
  - IPv4 サーバー → `0.0.0.0:0` にバインド
  - IPv6 サーバー → `[::]:0` にバインド

### ログ出力

- **出力先**: `--log-output` オプション（環境変数 `QUICPORT_LOG_OUTPUT`）でファイルパスを指定可能。指定時はファイルに追記モードで出力
  - 未指定時: 通常は stdout、ssh-proxy モードでは stderr
  - ssh-proxy では stdout が SSH プロトコルデータ専用のため stderr を使用
- **理由**: systemd などのプロセス管理ツールとの連携、ログ集約ツールでの扱いやすさ
- **フォーマット**: `--log-format` オプションで `console`（人間向け）または `json`（構造化ログ）を選択可能
- **フォーマット継承**: control-plane が data-plane を自動起動する際、`--log-format` の値を引き継ぐ。CP を `--log-format json` で起動すると、DP も JSON 形式でログ出力する
- **ログレベル**: 環境変数 `RUST_LOG` で制御（デフォルト: `info`）
- **ルートスパン**: 全ログに `pid`（プロセス ID）と `subcommand`（実行中のサブコマンド名）がスパン属性として付与される。複数プロセス運用時のログ識別に有用

### ファイル操作

- **アトミック書き込み**: 証明書・秘密鍵などの重要ファイルは一時ファイル経由でアトミックに書き込み
- **ファイルロック**: 複数プロセスからの同時アクセスを防ぐため `flock` による排他ロックを使用
- **パーミッション**: 秘密鍵ファイルは 0600 で作成（Unix のみ）

### 接続管理

- **Keep-alive**: QUIC トランスポート層でデフォルト 5 秒間隔の keep-alive を送信（`--quic-keep-alive` で変更可能）
- **Idle timeout**: デフォルト 90 秒間応答がなければ接続をクローズ（`--quic-idle-timeout` で変更可能）
- **グレースフルシャットダウン**: SIGINT/SIGTERM でクリーンな終了処理を実行

## API サーバー

コントロールプレーンモードでは 2 つの HTTP API サーバーが起動します。

### Private API サーバー

localhost からのみアクセス可能な管理用 API です。

- **リッスンアドレス**: `127.0.0.1:<control_plane_addr_port>`（CP と同じポート番号、TCP）
- **カスタムアドレス**: `--private-api-listen`

| エンドポイント | メソッド | 説明 |
|---------------|---------|------|
| `/healthcheck` | GET | ヘルスチェック |
| `/metrics` | GET | Prometheus 形式のメトリクス |
| `/api/v1/dp/SendStatus` | POST | 状態送信・登録（HTTP IPC） |
| `/api/v1/dp/ReceiveCommand` | POST | コマンド受信・長ポーリング（HTTP IPC） |
| `/api/v1/admin/ListDataPlanes` | POST | 全データプレーン一覧 |
| `/api/v1/admin/GetDataPlaneStatus` | POST | データプレーン状態取得 |
| `/api/v1/admin/DrainDataPlane` | POST | データプレーンをドレイン |
| `/api/v1/admin/ShutdownDataPlane` | POST | データプレーンをシャットダウン |
| `/api/v1/admin/GetConnections` | POST | 接続一覧取得 |

### Public API サーバー

インターネットからアクセス可能なヘルスチェック専用 API です。

- **リッスンアドレス**: `<data_plane_addr_ip>:<data_plane_addr_port + 1>`（DP ポート + 1、TCP）
- **無効化**: `--no-public-api`

| エンドポイント | メソッド | 説明 |
|---------------|---------|------|
| `/healthcheck` | GET | ヘルスチェック |

### GET /healthcheck

サーバーが正常に稼働しているかを確認します。

**レスポンス例:**

```json
{
  "status": "SERVING"
}
```

### GET /metrics

Prometheus 形式でサーバーの稼働状況を返します（Private API のみ）。

**レスポンス例:**

```
# HELP quicport_uptime_seconds Server uptime in seconds
# TYPE quicport_uptime_seconds gauge
quicport_uptime_seconds 3600

# HELP quicport_connections_total Total number of connections since server start
# TYPE quicport_connections_total counter
quicport_connections_total 150

# HELP quicport_connections_active Current number of active connections
# TYPE quicport_connections_active gauge
quicport_connections_active 3

# HELP quicport_bytes_sent_total Total bytes sent to clients
# TYPE quicport_bytes_sent_total counter
quicport_bytes_sent_total 10485760

# HELP quicport_bytes_received_total Total bytes received from clients
# TYPE quicport_bytes_received_total counter
quicport_bytes_received_total 5242880

# HELP quicport_auth_psk_success_total Total number of successful PSK authentications
# TYPE quicport_auth_psk_success_total counter
quicport_auth_psk_success_total 50

# HELP quicport_auth_psk_failed_total Total number of failed PSK authentications
# TYPE quicport_auth_psk_failed_total counter
quicport_auth_psk_failed_total 3

# HELP quicport_auth_x25519_success_total Total number of successful X25519 authentications
# TYPE quicport_auth_x25519_success_total counter
quicport_auth_x25519_success_total 45

# HELP quicport_auth_x25519_failed_total Total number of failed X25519 authentications
# TYPE quicport_auth_x25519_failed_total counter
quicport_auth_x25519_failed_total 2
```

| メトリクス | タイプ | 説明 |
|-----------|--------|------|
| `quicport_uptime_seconds` | gauge | サーバー稼働時間（秒） |
| `quicport_connections_total` | counter | 累計接続数 |
| `quicport_connections_active` | gauge | 現在アクティブな接続数 |
| `quicport_bytes_sent_total` | counter | サーバーからクライアントへの送信バイト数 |
| `quicport_bytes_received_total` | counter | クライアントからサーバーへの受信バイト数 |
| `quicport_auth_psk_success_total` | counter | PSK 認証成功回数 |
| `quicport_auth_psk_failed_total` | counter | PSK 認証失敗回数 |
| `quicport_auth_x25519_success_total` | counter | X25519 認証成功回数 |
| `quicport_auth_x25519_failed_total` | counter | X25519 認証失敗回数 |

### HTTP IPC エンドポイント詳細

コントロールプレーンとデータプレーン間の通信に使用する HTTP IPC エンドポイントです。
すべてのエンドポイントは POST メソッドを使用する RPC ライクな設計です。

#### DataPlaneConfig フィールド一覧

CP から DP に配信される設定（`SendStatusResponse.config` および `SetConfig` コマンド）のフィールド一覧です。

| フィールド | 型 | デフォルト | 説明 |
|-----------|-----|-----------|------|
| `listen_addr` | `SocketAddr` | `0.0.0.0:39000` | QUIC リッスンアドレス |
| `drain_timeout` | `u64` | `0`（無制限） | DRAIN 状態のタイムアウト（秒）。0 はタイムアウトなし |
| `idle_connection_timeout` | `u64` | `3600`（1 時間） | アイドル接続のタイムアウト（秒） |
| `server_id` | `Option<u32>` | `None` | サーバー ID（eBPF ルーティング用）。QUIC Connection ID の先頭 4 バイトに埋め込まれる。None の場合は従来の接続 ID カウンターを使用 |
| `enable_ebpf_routing` | `bool` | `false` | eBPF ルーティングの有効化。true の場合、eBPF プログラムで QUIC パケットを Connection ID に基づいてルーティングする（Linux + ebpf feature が必要） |
| `stale_dp_timeout` | `u64` | `300`（5 分） | stale データプレーン検出タイムアウト（秒）。CP が DP の `last_active` をチェックし、この値を超過した DP を stale と判定して eBPF map エントリを削除する |
| `quic_keep_alive_secs` | `u64` | `5` | QUIC keep-alive interval（秒）。NAT テーブル維持のために定期的に ping を送信する間隔 |
| `quic_idle_timeout_secs` | `u64` | `90` | QUIC max idle timeout（秒）。この時間応答がなければ接続をクローズする |

#### DP 用 API

##### POST /api/v1/dp/SendStatus

状態送信（登録・更新・コマンド応答すべて統合）。
毎回全状態を冪等に送信することで、CP 再起動後も状態を復旧可能。
**5 秒間隔**で定期送信される。

- 初回呼び出し: DP 登録（auth_policy と config がレスポンスに含まれる）
- 以降の呼び出し: 状態更新 + コマンド応答（5 秒周期）

**リクエスト:**

```json
{
  "dp_id": "0x3039",
  "pid": 12345,
  "listen_addr": "0.0.0.0:39000",
  "state": "ACTIVE",
  "active_connections": 5,
  "bytes_sent": 1024,
  "bytes_received": 2048,
  "started_at": 1234567890,
  "ack_cmd_id": "cmd_001",
  "ack_status": "completed"
}
```

**レスポンス:**

```json
{
  "dp_id": "0x3039",
  "auth_policy": {
    "type": "psk",
    "psk": "secret"
  },
  "config": {
    "listen_addr": "0.0.0.0:39000",
    "drain_timeout": 0,
    "idle_connection_timeout": 3600,
    "server_id": 12345,
    "enable_ebpf_routing": false,
    "stale_dp_timeout": 300,
    "quic_keep_alive_secs": 5,
    "quic_idle_timeout_secs": 90
  }
}
```

##### POST /api/v1/dp/ReceiveCommand

コマンドの長ポーリング取得（デフォルト 30 秒タイムアウト）。

**リクエスト:**

```json
{
  "dp_id": "0x3039",
  "wait_timeout_secs": 30
}
```

**レスポンス:**

```json
{
  "commands": [
    {
      "id": "cmd_001",
      "type": "Drain"
    },
    {
      "id": "cmd_002",
      "type": "SetConfig",
      "listen_addr": "0.0.0.0:39000",
      "drain_timeout": 60,
      "idle_connection_timeout": 3600,
      "server_id": 12345,
      "enable_ebpf_routing": false,
      "stale_dp_timeout": 300,
      "quic_keep_alive_secs": 5,
      "quic_idle_timeout_secs": 90
    }
  ]
}
```

#### 管理用 API

##### POST /api/v1/admin/ListDataPlanes

全データプレーンの一覧を取得。

**リクエスト:**

```json
{}
```

**レスポンス:**

```json
{
  "dataplanes": [
    {
      "dp_id": "0x3039",
      "pid": 12345,
      "state": "ACTIVE",
      "active_connections": 5,
      "bytes_sent": 1024,
      "bytes_received": 2048
    }
  ]
}
```

##### POST /api/v1/admin/GetDataPlaneStatus

特定データプレーンの詳細状態を取得。

**リクエスト:**

```json
{
  "dp_id": "0x3039"
}
```

**レスポンス:**

```json
{
  "dp_id": "0x3039",
  "pid": 12345,
  "state": "ACTIVE",
  "active_connections": 5,
  "bytes_sent": 1024,
  "bytes_received": 2048,
  "started_at": 1234567890
}
```

##### POST /api/v1/admin/DrainDataPlane

データプレーンをドレイン状態に移行。

**リクエスト:**

```json
{
  "dp_id": "0x3039"
}
```

**レスポンス:**

```json
{
  "status": "draining"
}
```

##### POST /api/v1/admin/ShutdownDataPlane

データプレーンをシャットダウン。

**リクエスト:**

```json
{
  "dp_id": "0x3039"
}
```

**レスポンス:**

```json
{
  "status": "shutdown_initiated"
}
```

##### POST /api/v1/admin/GetConnections

特定データプレーンの接続一覧を取得。

**リクエスト:**

```json
{
  "dp_id": "0x3039"
}
```

**レスポンス:**

```json
{
  "connections": [
    {
      "id": 1,
      "remote_addr": "192.168.1.100:50000",
      "protocol": "TCP",
      "bytes_sent": 1024,
      "bytes_received": 2048
    }
  ]
}
```

**手動テスト例:**

```bash
# データプレーン一覧確認
curl -X POST http://127.0.0.1:39000/api/v1/admin/ListDataPlanes \
  -H "Content-Type: application/json" \
  -d '{}'

# 特定データプレーンの状態確認
curl -X POST http://127.0.0.1:39000/api/v1/admin/GetDataPlaneStatus \
  -H "Content-Type: application/json" \
  -d '{"dp_id": "0x3039"}'

# データプレーンをドレイン
curl -X POST http://127.0.0.1:39000/api/v1/admin/DrainDataPlane \
  -H "Content-Type: application/json" \
  -d '{"dp_id": "0x3039"}'

# 接続一覧
curl -X POST http://127.0.0.1:39000/api/v1/admin/GetConnections \
  -H "Content-Type: application/json" \
  -d '{"dp_id": "0x3039"}'
```

## 技術スタック

- **言語:** Rust
- **QUIC 実装:** [quinn](https://github.com/quinn-rs/quinn)
- **非同期ランタイム:** tokio
- **CLI パーサー:** clap
- **ログ:** tracing
- **暗号:** x25519-dalek, hmac, sha2
- **ソケット:** socket2 (SO_REUSEADDR 設定用)
- **HTTP API:** [axum](https://github.com/tokio-rs/axum)

## 制限事項（v1.0）

- 1 クライアント接続につき 1 ポートフォワーディングのみ
- 設定ファイル未対応（コマンドライン引数のみ）

## 将来の拡張予定

### 実装済み

- [x] データプレーン/コントロールプレーン分離（グレースフルリスタート対応）

### 未実装

- [ ] 複数ポートフォワーディング対応
- [ ] 設定ファイル対応 (TOML/YAML)
- [ ] Web UI での接続状況モニタリング
- [ ] 鍵生成コマンド (`quicport keygen`)
- [ ] UDP 仮想接続のアイドルタイムアウト
