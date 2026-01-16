//! サーバー統計情報
//!
//! サーバーの稼働状況（接続数、転送量など）を追跡するための構造体とメソッドを提供します。
//! Prometheus 形式でのメトリクスエクスポートに対応しています。

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// サーバー統計情報を保持する構造体
///
/// すべてのフィールドは Atomic 型で、複数スレッドから安全にアクセス可能です。
pub struct ServerStatistics {
    /// サーバー開始時刻
    start_time: Instant,
    /// 累計接続数
    total_connections: AtomicU64,
    /// 現在アクティブな接続数
    active_connections: AtomicU64,
    /// 送信バイト数の累計
    bytes_sent: AtomicU64,
    /// 受信バイト数の累計
    bytes_received: AtomicU64,
}

impl ServerStatistics {
    /// 新しい統計情報インスタンスを作成
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }

    /// 新しい接続が開始されたときに呼び出す
    ///
    /// 累計接続数とアクティブ接続数を増加させます。
    pub fn connection_opened(&self) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// 接続が終了したときに呼び出す
    ///
    /// アクティブ接続数を減少させます。
    pub fn connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// 送信バイト数を加算
    pub fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 受信バイト数を加算
    pub fn add_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Prometheus 形式でメトリクスを出力
    pub fn to_prometheus(&self) -> String {
        let uptime = self.start_time.elapsed().as_secs();
        let total_connections = self.total_connections.load(Ordering::Relaxed);
        let active_connections = self.active_connections.load(Ordering::Relaxed);
        let bytes_sent = self.bytes_sent.load(Ordering::Relaxed);
        let bytes_received = self.bytes_received.load(Ordering::Relaxed);

        let mut output = String::new();

        // uptime
        writeln!(output, "# HELP quicport_uptime_seconds Server uptime in seconds").unwrap();
        writeln!(output, "# TYPE quicport_uptime_seconds gauge").unwrap();
        writeln!(output, "quicport_uptime_seconds {}", uptime).unwrap();

        // connections total
        writeln!(
            output,
            "# HELP quicport_connections_total Total number of connections since server start"
        )
        .unwrap();
        writeln!(output, "# TYPE quicport_connections_total counter").unwrap();
        writeln!(output, "quicport_connections_total {}", total_connections).unwrap();

        // connections active
        writeln!(
            output,
            "# HELP quicport_connections_active Current number of active connections"
        )
        .unwrap();
        writeln!(output, "# TYPE quicport_connections_active gauge").unwrap();
        writeln!(output, "quicport_connections_active {}", active_connections).unwrap();

        // bytes sent
        writeln!(
            output,
            "# HELP quicport_bytes_sent_total Total bytes sent to clients"
        )
        .unwrap();
        writeln!(output, "# TYPE quicport_bytes_sent_total counter").unwrap();
        writeln!(output, "quicport_bytes_sent_total {}", bytes_sent).unwrap();

        // bytes received
        writeln!(
            output,
            "# HELP quicport_bytes_received_total Total bytes received from clients"
        )
        .unwrap();
        writeln!(output, "# TYPE quicport_bytes_received_total counter").unwrap();
        writeln!(output, "quicport_bytes_received_total {}", bytes_received).unwrap();

        output
    }
}

impl Default for ServerStatistics {
    fn default() -> Self {
        Self::new()
    }
}
