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
| `--log-format` | No | ログ出力形式。`console`（デフォルト）または `json`。環境変数 `QUICPORT_LOG_FORMAT` でも指定可 |

**例:**

```bash
# JSON 形式でログ出力（構造化ログ、監視ツール連携向け）
quicport --log-format json server --listen 0.0.0.0:9000

# 環境変数で指定
QUICPORT_LOG_FORMAT=json quicport server --listen 0.0.0.0:9000
```

### サーバーモード

```bash
quicport server --listen <bind_address>:<port> --privkey <server_private_key> --client-pubkeys <authorized_public_keys>
```

**オプション:**

| オプション | 必須 | 説明 |
|-----------|------|------|
| `--listen`, `-l` | No | QUIC コネクションを待ち受けるアドレスとポート（デフォルト: `0.0.0.0:39000`） |
| `--api-listen` | No | API サーバーを待ち受けるアドレスとポート（デフォルト: `0.0.0.0:39001`） |
| `--no-api` | No | API サーバーを無効化 |
| `--privkey` | Yes** | サーバーの秘密鍵（Base64 形式、相互認証用）。環境変数 `QUICPORT_PRIVKEY` でも指定可 |
| `--privkey-file` | Yes** | サーバーの秘密鍵ファイルパス。環境変数 `QUICPORT_PRIVKEY_FILE` でも指定可 |
| `--client-pubkeys` | Yes* | 認可するクライアントの公開鍵（Base64 形式）。複数指定はカンマ区切り。環境変数 `QUICPORT_CLIENT_PUBKEYS` でも指定可 |
| `--client-pubkeys-file` | Yes* | 公開鍵を読み込むファイルパス。1 行 1 鍵。環境変数 `QUICPORT_CLIENT_PUBKEYS_FILE` でも指定可 |
| `--psk` | No | 事前共有キー。環境変数 `QUICPORT_PSK` でも指定可 |

\* `--client-pubkeys` または `--client-pubkeys-file` のいずれかが必須（`--psk` を使用する場合を除く）
\** X25519 認証（`--client-pubkeys` / `--client-pubkeys-file`）使用時は `--privkey` または `--privkey-file` が必須（相互認証のため）

> **PSK 自動生成:** 認証オプション（`--psk`, `--client-pubkeys`, `--client-pubkeys-file`）が何も指定されていない場合、
> PSK が自動生成され `~/.config/quicport/psk` に保存されます。次回以降の起動では既存の PSK を読み込みます。

**例:**

```bash
# 相互認証（サーバー秘密鍵 + クライアント公開鍵）
quicport server --listen 0.0.0.0:9000 \
  --privkey "8JWfeRFI8New0ie+oUTNKDyaHMJOk+EAq4w3wG8HR3U=" \
  --client-pubkeys "IexqQqW8ngM33aoJWqheXfW+11hL6A3h6kpO8uNl9Ws="

# ファイルから読み込み
quicport server --listen 0.0.0.0:9000 \
  --privkey-file /etc/quicport/server.key \
  --client-pubkeys-file /etc/quicport/authorized_keys

# 複数のクライアント公開鍵を指定（カンマ区切り）
quicport server --listen 0.0.0.0:9000 \
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
通常はコントロールプレーン（`quicport server`）から起動されますが、直接起動も可能です。

```bash
quicport data-plane [OPTIONS]
```

**オプション:**

| オプション | 必須 | 説明 |
|-----------|------|------|
| `--listen`, `-l` | No | QUIC リッスンアドレス（デフォルト: `0.0.0.0:39000`） |
| `--drain-timeout` | No | DRAIN 状態のタイムアウト秒数（デフォルト: `300`） |

**認証設定（環境変数）:**

データプレーンは認証設定を環境変数から取得します：

| 環境変数 | 説明 |
|---------|------|
| `QUICPORT_DP_AUTH_TYPE` | 認証タイプ（`psk` または `x25519`） |
| `QUICPORT_DP_PSK` | PSK 認証時の事前共有キー |
| `QUICPORT_DP_SERVER_PRIVKEY` | X25519 認証時のサーバー秘密鍵（Base64） |
| `QUICPORT_DP_CLIENT_PUBKEYS` | X25519 認証時の許可されたクライアント公開鍵（カンマ区切り、Base64） |

**例:**

```bash
# PSK 認証でデータプレーンを直接起動
QUICPORT_DP_AUTH_TYPE=psk QUICPORT_DP_PSK="secret" quicport data-plane --listen 0.0.0.0:39000

# X25519 認証でデータプレーンを起動
QUICPORT_DP_AUTH_TYPE=x25519 \
  QUICPORT_DP_SERVER_PRIVKEY="SERVER_PRIVKEY" \
  QUICPORT_DP_CLIENT_PUBKEYS="CLIENT_PUBKEY1,CLIENT_PUBKEY2" \
  quicport data-plane
```

### 制御コマンド (ctl)

実行中のデータプレーンを管理するためのコマンドです。

```bash
quicport ctl <COMMAND>
```

**サブコマンド:**

| コマンド | 説明 |
|----------|------|
| `graceful-restart` | 全ての ACTIVE なデータプレーンに DRAIN を送信 |
| `status` | 全データプレーンの状態を表示 |
| `drain --pid <PID>` | 特定のデータプレーンに DRAIN を送信 |

**例:**

```bash
# 全データプレーンの状態を確認
quicport ctl status

# グレースフルリスタート（全データプレーンをドレイン）
quicport ctl graceful-restart

# 特定のデータプレーンをドレイン
quicport ctl drain --pid 12345
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

```
                                    +-----------------------+
                                    |   Control Plane       |
                                    |   (quicport server)   |
                                    |                       |
                                    |  - 認証ポリシー管理    |
                                    |  - プロセス管理        |
                                    |  - API サーバー       |
                                    +-----------+-----------+
                                                |
                                                | IPC (TCP 127.0.0.1)
                                                |
+-------------------+                 +---------v---------+                 +-------------------+
|                   |    QUIC         |   Data Plane      |    QUIC         |                   |
|  quicport Client  | <=============> |   (独立プロセス)   | <=============> |  quicport Client  |
|                   |                 |                   |                 |                   |
+-------------------+                 |  - QUIC 終端      |                 +-------------------+
                                      |  - 認証実行       |
                                      |  - データ転送     |
                                      +-------------------+
```

**責務分離:**

| コンポーネント | 責務 |
|--------------|------|
| **コントロールプレーン** | 認証ポリシー管理、プロセス管理、API サーバー、グレースフルリスタート |
| **データプレーン** | QUIC 終端、クライアント認証、TCP/UDP 接続維持、データ転送 |

**グレースフルリスタートのフロー:**

1. 新しいデータプレーンを起動（SO_REUSEPORT で同一ポートで LISTEN）
2. 古いデータプレーンに DRAIN コマンドを送信
3. 古いデータプレーンは新規接続を拒否し、既存接続のみ処理
4. 全接続が終了するか、タイムアウト（デフォルト 300 秒）後に終了

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
| `STARTING` | 起動中、初期化処理 |
| `ACTIVE` | 通常稼働中、新規接続受付可能 |
| `DRAINING` | ドレイン中、新規接続拒否、既存接続のみ処理 |
| `TERMINATED` | 終了済み |

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
| `~/.local/state/quicport/dataplanes/dp-<pid>.port` | データプレーン IPC ポート番号（TCP 127.0.0.1） |
| `~/.local/state/quicport/dataplanes/dp-<pid>.state` | データプレーン状態ファイル（JSON 形式） |

#### データプレーン管理ファイル

データプレーンは `~/.local/state/quicport/dataplanes/` ディレクトリで管理されます:

- **ポートファイル** (`dp-<pid>.port`): IPC 用 TCP ポート番号（127.0.0.1 で待ち受け）
- **状態ファイル** (`dp-<pid>.state`): データプレーンの現在の状態を JSON 形式で記録

状態ファイルの例:

```json
{
  "state": "Active",
  "pid": 12345,
  "active_connections": 3,
  "bytes_sent": 10485760,
  "bytes_received": 5242880,
  "started_at": 1705639200
}
```

データプレーン終了時、これらのファイルは自動的にクリーンアップされます。

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
- 5 秒間隔で keep-alive パケットを自動送信
- **Idle timeout**: 10 秒間応答がなければ接続をクローズ
  - クライアントが強制終了された場合でも、最大 10 秒以内にサーバーが接続切断を検出

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

- **出力先**: 通常は stdout、ssh-proxy モードでは stderr
  - ssh-proxy では stdout が SSH プロトコルデータ専用のため stderr を使用
- **理由**: systemd などのプロセス管理ツールとの連携、ログ集約ツールでの扱いやすさ
- **フォーマット**: `--log-format` オプションで `console`（人間向け）または `json`（構造化ログ）を選択可能
- **ログレベル**: 環境変数 `RUST_LOG` で制御（デフォルト: `info`）

### ファイル操作

- **アトミック書き込み**: 証明書・秘密鍵などの重要ファイルは一時ファイル経由でアトミックに書き込み
- **ファイルロック**: 複数プロセスからの同時アクセスを防ぐため `flock` による排他ロックを使用
- **パーミッション**: 秘密鍵ファイルは 0600 で作成（Unix のみ）

### 接続管理

- **Keep-alive**: QUIC トランスポート層で 5 秒間隔の keep-alive を送信
- **Idle timeout**: 10 秒間応答がなければ接続をクローズ
- **グレースフルシャットダウン**: SIGINT/SIGTERM でクリーンな終了処理を実行

## API サーバー

サーバーモードでは HTTP API サーバーが並列起動し、ヘルスチェックや Prometheus 形式のメトリクスを提供します。

### エンドポイント

| エンドポイント | メソッド | 説明 |
|---------------|---------|------|
| `/healthcheck` | GET | ヘルスチェック |
| `/metrics` | GET | Prometheus 形式のメトリクス |

### GET /healthcheck

サーバーが正常に稼働しているかを確認します。

**レスポンス例:**

```json
{
  "status": "SERVING"
}
```

### GET /metrics

Prometheus 形式でサーバーの稼働状況を返します。

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
