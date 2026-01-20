//! quicport - QUIC-based port forwarding / tunneling library
//!
//! このライブラリは QUIC プロトコルを使用したポートフォワーディング機能を提供します。
//!
//! # 主要コンポーネント
//!
//! - [`control_plane`] - コントロールプレーン実装（データプレーン管理）
//! - [`data_plane`] - データプレーン実装（QUIC/TCP/UDP 接続管理）
//! - [`client`] - QUIC クライアント実装
//! - [`api`] - HTTP API サーバー（ヘルスチェック、メトリクス）
//! - [`protocol`] - 制御プロトコル定義
//! - [`quic`] - QUIC/TLS 関連ユーティリティ
//! - [`ipc`] - プロセス間通信プロトコル
//!
//! # アーキテクチャ
//!
//! ```text
//! [Client] ←QUIC→ [データプレーン] ←TCP/UDP→ [Backend]
//!                       ↑
//!                       │ IPC (TCP on localhost)
//!                       ↓
//!               [コントロールプレーン]
//! ```
//!
//! データプレーンとコントロールプレーンを分離することで、
//! コントロールプレーン再起動時も既存の接続を維持できます。
//!
//! # 使用例
//!
//! ## サーバー起動
//!
//! ```no_run
//! use quicport::control_plane;
//! use quicport::ipc::AuthPolicy;
//! use quicport::statistics::ServerStatistics;
//! use std::net::SocketAddr;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let listen: SocketAddr = "0.0.0.0:39000".parse()?;
//!     let auth_policy = AuthPolicy::Psk { psk: "secret".to_string() };
//!     let statistics = Arc::new(ServerStatistics::new());
//!     control_plane::run_with_api(listen, auth_policy, statistics, None, false).await
//! }
//! ```
//!
//! ## クライアント起動
//!
//! ```no_run
//! use quicport::client::{self, ClientAuthConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let auth = ClientAuthConfig::Psk { psk: "secret".to_string() };
//!     let reconnect = client::ReconnectConfig::default();
//!     // 第6引数は reconnect 設定
//!     client::run_remote_forward_with_reconnect("127.0.0.1:39000", "8080/tcp", "80/tcp", auth, false, reconnect).await
//! }
//! ```

pub mod api;
pub mod client;
pub mod control_plane;
pub mod data_plane;
pub mod ipc;
pub mod protocol;
pub mod quic;
pub mod statistics;

// 便利な再エクスポート
pub use client::ClientAuthConfig;
