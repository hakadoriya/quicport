//! サーバー統計情報
//!
//! サーバーの稼働状況（トンネル数、転送量など）を追跡するための構造体とメソッドを提供します。
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
    /// 累計トンネル数
    total_tunnels: AtomicU64,
    /// 現在アクティブなトンネル数
    active_tunnels: AtomicU64,
    /// 送信バイト数の累計
    bytes_sent: AtomicU64,
    /// 受信バイト数の累計
    bytes_received: AtomicU64,

    // 認証メトリクス（方式別）
    /// PSK 認証成功回数
    auth_psk_success: AtomicU64,
    /// PSK 認証失敗回数
    auth_psk_failed: AtomicU64,
    /// X25519 認証成功回数
    auth_x25519_success: AtomicU64,
    /// X25519 認証失敗回数
    auth_x25519_failed: AtomicU64,
}

impl ServerStatistics {
    /// 新しい統計情報インスタンスを作成
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            total_tunnels: AtomicU64::new(0),
            active_tunnels: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            auth_psk_success: AtomicU64::new(0),
            auth_psk_failed: AtomicU64::new(0),
            auth_x25519_success: AtomicU64::new(0),
            auth_x25519_failed: AtomicU64::new(0),
        }
    }

    /// 新しいトンネルが開始されたときに呼び出す
    ///
    /// 累計トンネル数とアクティブトンネル数を増加させます。
    pub fn tunnel_opened(&self) {
        self.total_tunnels.fetch_add(1, Ordering::Relaxed);
        self.active_tunnels.fetch_add(1, Ordering::Relaxed);
    }

    /// トンネルが終了したときに呼び出す
    ///
    /// アクティブトンネル数を減少させます。
    pub fn tunnel_closed(&self) {
        self.active_tunnels.fetch_sub(1, Ordering::Relaxed);
    }

    /// 送信バイト数を加算
    pub fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 受信バイト数を加算
    pub fn add_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// PSK 認証成功時にインクリメント
    pub fn auth_psk_success(&self) {
        self.auth_psk_success.fetch_add(1, Ordering::Relaxed);
    }

    /// PSK 認証失敗時にインクリメント
    pub fn auth_psk_failed(&self) {
        self.auth_psk_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// X25519 認証成功時にインクリメント
    pub fn auth_x25519_success(&self) {
        self.auth_x25519_success.fetch_add(1, Ordering::Relaxed);
    }

    /// X25519 認証失敗時にインクリメント
    pub fn auth_x25519_failed(&self) {
        self.auth_x25519_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Prometheus 形式でメトリクスを出力
    pub fn to_prometheus(&self) -> String {
        let uptime = self.start_time.elapsed().as_secs();
        let total_tunnels = self.total_tunnels.load(Ordering::Relaxed);
        let active_tunnels = self.active_tunnels.load(Ordering::Relaxed);
        let bytes_sent = self.bytes_sent.load(Ordering::Relaxed);
        let bytes_received = self.bytes_received.load(Ordering::Relaxed);
        let auth_psk_success = self.auth_psk_success.load(Ordering::Relaxed);
        let auth_psk_failed = self.auth_psk_failed.load(Ordering::Relaxed);
        let auth_x25519_success = self.auth_x25519_success.load(Ordering::Relaxed);
        let auth_x25519_failed = self.auth_x25519_failed.load(Ordering::Relaxed);

        let mut output = String::new();

        // uptime
        writeln!(
            output,
            "# HELP quicport_uptime_seconds Server uptime in seconds"
        )
        .unwrap();
        writeln!(output, "# TYPE quicport_uptime_seconds gauge").unwrap();
        writeln!(output, "quicport_uptime_seconds {}", uptime).unwrap();

        // tunnels total
        writeln!(
            output,
            "# HELP quicport_tunnels_total Total number of tunnels since server start"
        )
        .unwrap();
        writeln!(output, "# TYPE quicport_tunnels_total counter").unwrap();
        writeln!(output, "quicport_tunnels_total {}", total_tunnels).unwrap();

        // tunnels active
        writeln!(
            output,
            "# HELP quicport_tunnels_active Current number of active tunnels"
        )
        .unwrap();
        writeln!(output, "# TYPE quicport_tunnels_active gauge").unwrap();
        writeln!(output, "quicport_tunnels_active {}", active_tunnels).unwrap();

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

        // auth PSK success
        writeln!(
            output,
            "# HELP quicport_auth_psk_success_total Total number of successful PSK authentications"
        )
        .unwrap();
        writeln!(output, "# TYPE quicport_auth_psk_success_total counter").unwrap();
        writeln!(
            output,
            "quicport_auth_psk_success_total {}",
            auth_psk_success
        )
        .unwrap();

        // auth PSK failed
        writeln!(
            output,
            "# HELP quicport_auth_psk_failed_total Total number of failed PSK authentications"
        )
        .unwrap();
        writeln!(output, "# TYPE quicport_auth_psk_failed_total counter").unwrap();
        writeln!(output, "quicport_auth_psk_failed_total {}", auth_psk_failed).unwrap();

        // auth X25519 success
        writeln!(
            output,
            "# HELP quicport_auth_x25519_success_total Total number of successful X25519 authentications"
        )
        .unwrap();
        writeln!(output, "# TYPE quicport_auth_x25519_success_total counter").unwrap();
        writeln!(
            output,
            "quicport_auth_x25519_success_total {}",
            auth_x25519_success
        )
        .unwrap();

        // auth X25519 failed
        writeln!(
            output,
            "# HELP quicport_auth_x25519_failed_total Total number of failed X25519 authentications"
        )
        .unwrap();
        writeln!(output, "# TYPE quicport_auth_x25519_failed_total counter").unwrap();
        writeln!(
            output,
            "quicport_auth_x25519_failed_total {}",
            auth_x25519_failed
        )
        .unwrap();

        output
    }
}

impl Default for ServerStatistics {
    fn default() -> Self {
        Self::new()
    }
}
