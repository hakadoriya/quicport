# quicport 仕様書

## 概要

`quicport` は QUIC プロトコルを使用したポートフォワーディング / トンネリングツールです。
リモートサーバー上のポートへのアクセスを、クライアント側のローカルポートに転送します。

## ユースケース

```
[外部クライアント] --> [サーバー:9022/tcp] --QUIC--> [クライアント:22/tcp]
```

例: NAT 配下にある SSH サーバーを、インターネット経由でアクセス可能にする。

## コマンドライン仕様

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

```bash
quicport client --server <server_address>:<port> --remote-source <port>[/protocol] --local-destination [addr:]<port>[/protocol] --privkey <private_key> --server-pubkey <server_public_key>
```

**オプション:**

| オプション | 必須 | 説明 |
|-----------|------|------|
| `--server`, `-s` | Yes | 接続先サーバーのアドレスとポート |
| `--remote-source`, `-r` | Yes | サーバー側で開くポート（例: `9022`, `9022/tcp`）。プロトコル省略時は TCP |
| `--local-destination`, `-l` | Yes | 転送先のアドレスとポート（例: `22`, `22/tcp`, `192.168.1.100:22`）。アドレス省略時は `127.0.0.1`、プロトコル省略時は TCP |
| `--privkey` | Yes* | X25519 秘密鍵（Base64 形式）。環境変数 `QUICPORT_PRIVKEY` でも指定可 |
| `--privkey-file` | Yes* | 秘密鍵を読み込むファイルパス。環境変数 `QUICPORT_PRIVKEY_FILE` でも指定可 |
| `--server-pubkey` | Yes** | 期待するサーバーの公開鍵（Base64 形式、相互認証用）。環境変数 `QUICPORT_SERVER_PUBKEY` でも指定可 |
| `--server-pubkey-file` | Yes** | サーバーの公開鍵ファイルパス。環境変数 `QUICPORT_SERVER_PUBKEY_FILE` でも指定可 |
| `--psk` | No | 事前共有キー。環境変数 `QUICPORT_PSK` でも指定可 |
| `--insecure` | No | サーバー証明書検証をスキップ（テスト用、本番環境では非推奨） |

\* `--privkey` または `--privkey-file` のいずれかが必須（`--psk` を使用する場合を除く）
\** X25519 認証（`--privkey` / `--privkey-file`）使用時は `--server-pubkey` または `--server-pubkey-file` が必須（MITM 攻撃防止のため）

**--local-destination の形式:**

| 形式 | 例 | 解釈 |
|------|-----|------|
| `port` | `22` | `127.0.0.1:22/tcp` |
| `port/protocol` | `22/tcp` | `127.0.0.1:22/tcp` |
| `addr:port` | `192.168.1.100:22` | `192.168.1.100:22/tcp` |
| `addr:port/protocol` | `192.168.1.100:22/tcp` | `192.168.1.100:22/tcp` |
| `[ipv6]:port` | `[::1]:22` | `[::1]:22/tcp` |

**例:**

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

## アーキテクチャ

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
- 5 秒間隔で keep-alive パケットを自動送信
- **Idle timeout**: 10 秒間応答がなければ接続をクローズ
  - クライアントが強制終了された場合でも、最大 10 秒以内にサーバーが接続切断を検出
- プロトコルレベルの Heartbeat メッセージ（0x03）は将来の拡張用に予約

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

| Type | 名前 | 方向 | 説明 |
|------|------|------|------|
| 0x01 | PortRequest | Client → Server | ポート開放リクエスト |
| 0x02 | PortResponse | Server → Client | ポート開放レスポンス |
| 0x03 | Heartbeat | 双方向 | 接続維持（※現在は QUIC keep-alive を使用、将来拡張用に予約） |
| 0x04 | SessionClose | 双方向 | QUIC セッション終了 |
| 0x10 | NewConnection | Server → Client | 新しい TCP/UDP 接続の通知 |
| 0x11 | (予約) | - | 将来の拡張用に予約 |
| 0x12 | ConnectionClose | 双方向 | 個別接続の終了通知 |

#### PortRequest ペイロード

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

#### PortResponse ペイロード

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

#### NewConnection ペイロード

```
+------------------+------------------+
| Connection ID    | Protocol         |
| (4 bytes, BE)    | (1 byte)         |
+------------------+------------------+

Protocol:
  0x01 = TCP
  0x02 = UDP
```

サーバーが新しい外部接続を受け付けた際にクライアントへ通知します。
- **Connection ID:** 論理的な接続識別子（管理用）
- クライアントは QUIC Stream の先頭 4 バイトから Connection ID を読み取ります

> **注意:** Connection ID は QUIC Stream のヘッダー（先頭 4 バイト、big-endian）にも書き込まれます。
> これにより、NewConnection メッセージと Stream の到着順序に依存せずに接続を識別できます。

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
2. クライアントへ NewConnection を通知（Stream 0 経由）
3. サーバーが新しい QUIC Stream を開く
4. クライアントはローカル TCP 接続を確立
5. 双方向でデータを中継（Length フレーミングなし、バイトストリームをそのまま転送）

#### UDP トンネリングの動作

UDP はコネクションレスなため、送信元アドレス (IP:port) で「仮想接続」を管理します。

1. サーバーが UDP パケットを受信
2. 送信元アドレス+ポートで「仮想接続」を識別
3. 新規の送信元の場合:
   - NewConnection を通知（Stream 0 経由）
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

### 接続確立

```
Client                          Server                      External Client
   |                               |                               |
   |------- QUIC Handshake ------->|                               |
   |    (with X25519 mutual auth)  |                               |
   |                               |                               |
   |--- PortRequest (9022/tcp) --->|  (via Stream 0)               |
   |                               |                               |
   |<-- PortResponse (Success) ----|  (via Stream 0)               |
   |                               |                               |
   |                               |<----- TCP Connect (9022) -----|
   |                               |                               |
   |<-- NewConnection (Stream 0) --|  conn_id=1, protocol=TCP      |
   |                               |                               |
   |<-- Open Stream 1 -------------|  データ転送用 + conn_id ヘッダー |
   |                               |                               |
   |--- Connect to local:22 ------>|                               |
   |                               |                               |
   |<====== Stream 1 (Data) ======>|<========= Data Relay ========>|
   |                               |                               |
```

> **注意:** サーバーは NewConnection 送信後、即座にデータ転送を開始します。
> クライアントはローカル接続を確立してから Stream の読み取りを開始するため、QUIC フロー制御により
> クライアントの準備が整うまでサーバーからの送信は自動的に抑制されます。

### TCP 接続のライフサイクル

```
External Client                 Server                          quicport Client
      |                            |                                   |
      |---- TCP SYN -------------->|                                   |
      |<--- TCP SYN-ACK -----------|                                   |
      |---- TCP ACK -------------->|                                   |
      |                            |                                   |
      |                            |-- NewConnection (Stream 0) ------>|
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

> **注意:** サーバーは NewConnection 送信後、即座に Stream を開いてデータ転送を開始します。
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
      |                            |-- NewConnection (Stream 0) ------>|
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
> 一定時間パケットがない場合、仮想接続はタイムアウトでクリーンアップされます。

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
```

| メトリクス | タイプ | 説明 |
|-----------|--------|------|
| `quicport_uptime_seconds` | gauge | サーバー稼働時間（秒） |
| `quicport_connections_total` | counter | 累計接続数 |
| `quicport_connections_active` | gauge | 現在アクティブな接続数 |
| `quicport_bytes_sent_total` | counter | サーバーからクライアントへの送信バイト数 |
| `quicport_bytes_received_total` | counter | クライアントからサーバーへの受信バイト数 |

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

- [ ] 複数ポートフォワーディング対応
- [ ] 設定ファイル対応 (TOML/YAML)
- [ ] Web UI での接続状況モニタリング
- [ ] 鍵生成コマンド (`quicport keygen`)
