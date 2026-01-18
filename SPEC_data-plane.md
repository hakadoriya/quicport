# データプレーン設計仕様書

## 概要

データプレーンは、QUIC 接続とバックエンド TCP 接続を維持するデーモンです。コントロールプレーン（quicport control-plane）とは別プロセスとして動作し、コントロールプレーンの再起動・終了後も独立して動作を継続します。

## 目的

- QUIC 接続およびバックエンド接続（SSH 等）の維持
- コントロールプレーンからの独立性（コントロールプレーン終了後も継続）
- グレースフルリスタートによるゼロダウンタイムデプロイ
- データプレーンとコントロールプレーンの分離

## アーキテクチャ

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Client Side                                                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  [SSH Client] ←TCP→ [quicport client :39022] ←───QUIC───→                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                                      │
                                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Server Side                                                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ データプレーン (quicport data-plane)                                  │   │
│  │  - QUIC 接続の終端                                                   │   │
│  │  - バックエンド TCP 接続の管理                                        │   │
│  │  - データ転送                                                        │   │
│  │  - SO_REUSEPORT でグレースフルリスタート対応                          │   │
│  │  - コントロールプレーン終了後も独立動作                               │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                         ↑                                                    │
│                         │ Unix Socket (制御用 IPC、任意)                    │
│                         ↓                                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ コントロールプレーン (quicport control-plane)                                │   │
│  │  - データプレーンの起動・管理                                        │   │
│  │  - 認証ポリシーの配布                                                │   │
│  │  - 設定管理                                                          │   │
│  │  - API サーバー                                                      │   │
│  │  - モニタリング                                                       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## コンポーネント

### データプレーン (quicport data-plane)

| 責務 | 説明 |
|------|------|
| QUIC 終端 | クライアントからの QUIC 接続を処理 |
| 認証実行 | コントロールプレーンから受け取ったポリシーに基づき認証 |
| バックエンド接続 | SSH 等への TCP 接続を確立・維持 |
| データ転送 | QUIC ↔ TCP 間のデータ中継 |
| 独立動作 | コントロールプレーン終了後も継続動作 |
| グレースフル終了 | DRAIN モードで既存接続を処理しつつ終了 |

### コントロールプレーン (quicport control-plane)

| 責務 | 説明 |
|------|------|
| プロセス管理 | データプレーンの起動・グレースフルリスタート |
| 認証ポリシー | PSK/X25519 認証情報の管理と配布 |
| 設定管理 | 設定ファイルの読み込みと配布 |
| API サーバー | 管理用 REST API の提供 |
| モニタリング | 接続状態、メトリクスの収集 |

## プロセス管理

### プロセス登録

データプレーンは起動時に自身を登録:

```
~/.local/state/quicport/dataplanes/
├── dp-12345.sock         # データプレーン PID 12345 の制御ソケット
├── dp-12345.state        # 状態ファイル (JSON: state, connections, etc.)
└── dp-67890.sock         # データプレーン PID 67890
```

### systemd 連携

```ini
[Unit]
Description=quicport control-plane

[Service]
Type=simple
ExecStart=/usr/local/bin/quicport control-plane
ExecReload=/usr/local/bin/quicport ctl graceful-restart
# stop はコントロールプレーンのみ終了、データプレーンは残留
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

| 操作 | コントロールプレーン | データプレーン |
|------|---------------------|----------------|
| `systemctl start quicport` | 起動、データプレーン起動 | 起動 (ACTIVE) |
| `systemctl stop quicport` | DRAIN 指示後に終了 | DRAINING → 全接続終了後に自動終了 |
| `systemctl reload quicport` | 新データプレーン起動 + 旧に DRAIN 指示 | 旧: DRAINING、新: ACTIVE |
| `systemctl restart quicport` | stop → start | 旧: DRAINING → 自動終了、新: ACTIVE |

### 起動シーケンス

```
1. コントロールプレーン起動
2. ~/.local/state/quicport/dataplanes/ をスキャン
3. 発見したデータプレーンに接続:
   ├─ ACTIVE → 接続して使用
   └─ DRAINING → 接続してモニタリング（終了を監視）
4. ACTIVE なデータプレーンがない場合:
   └─ 新規データプレーン起動
5. 全データプレーンに認証ポリシー等を配布
6. 通常稼働開始
```

### データプレーン起動

データプレーンは setsid() で独立したセッションとして起動され、
親プロセス（コントロールプレーン）の終了に影響されない。

### 複数 DRAINING データプレーンの許容

連続した restart/reload により、複数の DRAINING データプレーンが同時に存在することを許容する。

**例: 2 回連続で restart した場合**

```
~/.local/state/quicport/dataplanes/
├── dp-1000.sock    # DRAINING (1回目の restart で残留)
├── dp-1000.state   # {"state": "DRAINING", "connections": 5}
├── dp-2000.sock    # DRAINING (2回目の restart で残留)
├── dp-2000.state   # {"state": "DRAINING", "connections": 3}
├── dp-3000.sock    # ACTIVE (最新)
└── dp-3000.state   # {"state": "ACTIVE", "connections": 10}
```

**動作:**

- 各 DRAINING データプレーンは独立して動作
- それぞれの接続数が 0 になったら自動終了
- 終了時にソケットファイルと状態ファイルを削除
- コントロールプレーンは全データプレーンをモニタリング

### グレースフルリスタート (systemctl reload)

```
時刻    コントロールプレーン         データプレーン(OLD)      データプレーン(NEW)
───────────────────────────────────────────────────────────────────────────────
T0      [稼働中]                     [ACTIVE]

T1      [reload 受信]
        ├─ 新データプレーン起動 ─────────────────────────→ [起動]
        │                                                  [ACTIVE]
        │                                                  (SO_REUSEPORT)

T2      ├─ DRAIN 指示 ──────────→ [DRAINING]
        │                          - 新規接続拒否
        │                          - 既存接続のみ処理

T3      [完了]                       [既存接続処理]          [新規接続受付]

T4                                   [接続数: 0]
                                     [自動終了]
```

### コントロールプレーン終了時 (systemctl stop)

```
時刻    コントロールプレーン         データプレーン
───────────────────────────────────────────────────────────────────────────────
T0      [稼働中]                     [ACTIVE]

T1      [stop 受信]
        ├─ SIGTERM 受信
        ├─ DRAIN 指示 ──────────→ [DRAINING]
        └─ 終了                      - 新規接続拒否
                                     - 既存接続処理継続

T2      [終了]                       [DRAINING 継続]
                                     - コントロールプレーン不在でも動作
                                     - 認証ポリシーは保持済み

T3                                   [接続数: 0]
                                     [自動終了]
```

### データプレーンの状態

```rust
enum DataPlaneState {
    /// 起動中、初期化処理
    Starting,
    /// 通常稼働中、新規接続受付可能
    Active,
    /// ドレイン中、新規接続拒否、既存接続のみ処理
    Draining,
    /// 終了済み
    Terminated,
}
```

### データプレーンのライフサイクル

```
                    ┌─────────────────────────────────┐
                    │                                 │
                    ▼                                 │
[起動] ──→ [ACTIVE] ──DRAIN指示──→ [DRAINING] ──→ [終了]
                │                        │
                │                        └── 全接続終了時に自動終了
                │
                └── コントロールプレーン終了後も継続
```

## IPC 通信

### 通信方式

- Unix Domain Socket
- パス: `~/.local/state/quicport/control-<pid>.sock`（データプレーン の PID を含む）

### プロトコル

#### quicport control-plane → データプレーン (制御コマンド)

| コマンド | 説明 |
|----------|------|
| `SET_AUTH_POLICY` | 認証ポリシーを設定（PSK、X25519 公開鍵等） |
| `SET_CONFIG` | 設定を更新 |
| `DRAIN` | DRAIN モードに移行（新規接続拒否） |
| `SHUTDOWN` | 即座にシャットダウン |
| `GET_STATUS` | 状態を取得（接続数、状態等） |
| `GET_CONNECTIONS` | アクティブ接続の一覧を取得 |

#### データプレーン → quicport control-plane (イベント)

| イベント | 説明 |
|----------|------|
| `READY` | 初期化完了、接続受付可能 |
| `STATUS` | 状態レポート（定期送信） |
| `CONNECTION_OPENED` | 新規接続確立 |
| `CONNECTION_CLOSED` | 接続終了 |
| `AUTH_REQUEST` | 認証判断の問い合わせ（将来の拡張用） |
| `DRAINED` | 全接続終了、終了準備完了 |

### メッセージフレーミング

```
+----------------+----------------+------------------+
| Length (4byte) | Type (1byte)   | Payload (JSON)   |
| big-endian     |                | (Length - 1)     |
+----------------+----------------+------------------+
```

## SO_REUSEPORT によるグレースフルリスタート

### 仕組み

1. 複数プロセスが同じポートで LISTEN 可能
2. カーネルが新規接続を各プロセスに分散
3. DRAIN モードの古いプロセスは accept() を停止
4. 新規接続は自動的に新しいプロセスへ

### 注意点

- Linux 3.9+ / macOS 10.12+ が必要
- QUIC (UDP) でも SO_REUSEPORT は有効
- 古いプロセスへの新規パケット到着を完全に防ぐことはできない
  - → QUIC の Connection ID で適切なプロセスにルーティングする仕組みが必要（将来の拡張）

## 認証フロー

```
[Client] ──QUIC handshake──→ [データプレーン]
                                    │
                                    │ (認証ポリシーは事前に受信済み)
                                    │
                                    ├─ PSK 検証 or X25519 検証
                                    │
                             [認証成功/失敗]
                                    │
                                    │ CONNECTION_OPENED イベント
                                    ↓
                            [quicport control-plane]
                             (ログ、メトリクス)
```

## 設定項目

### データプレーン 設定

| 項目 | デフォルト値 | 説明 |
|------|--------------|------|
| `listen_addr` | `0.0.0.0:39000` | QUIC リッスンアドレス |
| `control_socket` | `~/.local/state/quicport/control-<pid>.sock` | 制御用 Unix Socket |
| `drain_timeout` | `0` (無限) | DRAIN 状態のタイムアウト（強制終了、0 = 無限） |
| `idle_connection_timeout` | `3600` (秒) | アイドル接続のタイムアウト |

### コントロールプレーン設定

| 項目 | デフォルト値 | 説明 |
|------|--------------|------|
| `data_plane_restart_delay` | `1` (秒) | リスタート時の新旧プロセス切り替え遅延 |
| `data_plane_health_interval` | `5` (秒) | ヘルスチェック間隔 |

## 状態管理

### データプレーンが管理するデータ

```rust
struct DataPlaneInternalState {
    /// プロセス状態
    state: DataPlaneState,
    /// QUIC エンドポイント
    quic_endpoint: Endpoint,
    /// アクティブな QUIC 接続
    quic_connections: HashMap<ConnectionId, QuicConnection>,
    /// バックエンド TCP 接続
    backend_connections: HashMap<u32, BackendConnection>,
    /// 認証ポリシー（コントロールプレーンから受信）
    auth_policy: AuthPolicy,
}

struct BackendConnection {
    conn_id: u32,
    quic_connection_id: ConnectionId,
    remote_addr: SocketAddr,
    protocol: Protocol,
    tcp_stream: TcpStream,
    created_at: Instant,
    last_activity: Instant,
    bytes_sent: u64,
    bytes_received: u64,
}
```

## エラーハンドリング

| 状況 | 動作 |
|------|------|
| データプレーン クラッシュ | quicport control-plane が検知し、新しいインスタンスを起動 |
| バックエンド接続失敗 | クライアントにエラーを返す |
| 認証失敗 | QUIC 接続を閉じる |
| DRAIN タイムアウト | 残りの接続を強制切断して終了 |
| コントロールプレーン切断 | 最後に受信したポリシーで動作継続 |

## セキュリティ

- Unix Socket のパーミッション: `0600`
- データプレーン と quicport control-plane は同じユーザーで実行
- 認証情報はコントロールプレーン経由でのみ設定
- QUIC の TLS 証明書・秘密鍵は データプレーン が保持

## バイナリ構成

| バイナリ | 説明 |
|----------|------|
| `quicport` | メインバイナリ。サブコマンドで動作を切り替え |
| `quicport control-plane` | コントロールプレーン + データプレーン起動 |
| `quicport data-plane` | データプレーン（通常は server から起動される） |
| `quicport client` | クライアント（変更なし） |
| `quicport ctl` | 制御コマンド（graceful-restart 等） |

## 将来の拡張

1. **Connection ID ベースのルーティング** - 複数データプレーン間での接続移行
2. **ホットリロード** - バイナリ更新なしでの設定変更
3. **クラスタリング** - 複数サーバーでの負荷分散
4. **メトリクス強化** - Prometheus 形式でのメトリクス公開

## 関連ドキュメント

- [SPEC.ja.md](./SPEC.ja.md) - quicport 全体の設計仕様
- [README.md](./README.md) - プロジェクト概要
