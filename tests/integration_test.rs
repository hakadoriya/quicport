//! quicport 統合テスト
//!
//! このテストスイートは、quicport のエンドツーエンド機能をテストします:
//! - PSK 認証
//! - X25519 相互認証
//! - ポートフォワーディング（データリレー）
//! - グレースフルシャットダウン
//! - 複数接続の処理

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

/// テスト用の一意なポート番号を取得
///
/// `portpicker` を使用して実際に利用可能なポートを取得する。
/// これにより並列実行時のポート競合を防ぐ。
fn get_test_port() -> u16 {
    portpicker::pick_unused_port().expect("No available port")
}

/// テスト用鍵（Base64 形式）
mod test_keys {
    /// クライアント秘密鍵
    pub const CLIENT_PRIVKEY: &str = "mBJ3XsDyuJxqU2bk0XEa+rUH+XD1lYwMlx9xH8ZTMUg=";
    /// クライアント公開鍵
    pub const CLIENT_PUBKEY: &str = "IexqQqW8ngM33aoJWqheXfW+11hL6A3h6kpO8uNl9Ws=";
    /// サーバー秘密鍵
    pub const SERVER_PRIVKEY: &str = "8JWfeRFI8New0ie+oUTNKDyaHMJOk+EAq4w3wG8HR3U=";
    /// サーバー公開鍵
    pub const SERVER_PUBKEY: &str = "l0NT7qgtfJhpWMH3dKDFm/PqmlBBpuEivWJQ7vqsJ1A=";
    /// テスト用 PSK
    pub const TEST_PSK: &str = "test-psk-for-integration-tests";
}

/// quicport バイナリへのパス
///
/// `CARGO_BIN_EXE_<name>` は Cargo が統合テスト実行時に自動的に設定する環境変数。
/// バイナリが存在しない場合は自動的にビルドされる。
fn quicport_binary() -> &'static str {
    env!("CARGO_BIN_EXE_quicport")
}

/// プロセスが起動するまで待機
fn wait_for_server_ready(addr: &str, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

/// quicport サーバーを起動するヘルパー
struct TestServer {
    process: Child,
    #[allow(dead_code)]
    listen_addr: String,
}

impl TestServer {
    /// PSK 認証でサーバーを起動
    fn start_with_psk(port: u16, psk: &str) -> Self {
        let listen_addr = format!("127.0.0.1:{}", port);
        eprintln!("[TestServer] Starting with PSK: listen={}", listen_addr);

        let process = Command::new(quicport_binary())
            .args(["server", "--listen", &listen_addr, "--no-api", "--psk", psk])
            .stdout(Stdio::inherit()) // 標準出力を継承してログを見る
            .stderr(Stdio::inherit()) // 標準エラーを継承してログを見る
            .spawn()
            .expect("Failed to start quicport server");

        // サーバーが起動するまで待機
        thread::sleep(Duration::from_millis(500));

        Self {
            process,
            listen_addr,
        }
    }

    /// X25519 相互認証でサーバーを起動
    fn start_with_x25519(port: u16, server_privkey: &str, client_pubkey: &str) -> Self {
        let listen_addr = format!("127.0.0.1:{}", port);
        let process = Command::new(quicport_binary())
            .args([
                "server",
                "--listen",
                &listen_addr,
                "--no-api",
                "--privkey",
                server_privkey,
                "--client-pubkeys",
                client_pubkey,
            ])
            .stdout(Stdio::inherit()) // 標準出力を継承してログを見る
            .stderr(Stdio::inherit()) // 標準エラーを継承してログを見る
            .spawn()
            .expect("Failed to start quicport server");

        // サーバーが起動するまで待機
        thread::sleep(Duration::from_millis(500));

        Self {
            process,
            listen_addr,
        }
    }

    #[allow(dead_code)]
    fn addr(&self) -> &str {
        &self.listen_addr
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // SIGTERM を送信してクリーンアップ
        #[cfg(unix)]
        unsafe {
            libc::kill(self.process.id() as i32, libc::SIGTERM);
        }
        #[cfg(not(unix))]
        {
            let _ = self.process.kill();
        }
        let _ = self.process.wait();
    }
}

/// quicport クライアントを起動するヘルパー
struct TestClient {
    process: Child,
}

impl TestClient {
    /// PSK 認証でクライアントを起動
    fn start_with_psk(server_addr: &str, remote_port: u16, local_port: u16, psk: &str) -> Self {
        eprintln!(
            "[TestClient] Starting with PSK: server={}, remote={}, local={}",
            server_addr, remote_port, local_port
        );

        let process = Command::new(quicport_binary())
            .args([
                "client",
                "-s",
                server_addr,
                "--remote-source",
                &format!("{}/tcp", remote_port),
                "--local-destination",
                &format!("{}/tcp", local_port),
                "--psk",
                psk,
                "--insecure", // テスト用: 証明書検証をスキップ
            ])
            .stdout(Stdio::inherit()) // 標準出力を継承してログを見る
            .stderr(Stdio::inherit()) // 標準エラーを継承してログを見る
            .spawn()
            .expect("Failed to start quicport client");

        // クライアントがサーバーに接続し、トンネルを確立するまで待機
        thread::sleep(Duration::from_secs(2));

        Self { process }
    }

    /// X25519 相互認証でクライアントを起動
    fn start_with_x25519(
        server_addr: &str,
        remote_port: u16,
        local_port: u16,
        client_privkey: &str,
        server_pubkey: &str,
    ) -> Self {
        let process = Command::new(quicport_binary())
            .args([
                "client",
                "-s",
                server_addr,
                "--remote-source",
                &format!("{}/tcp", remote_port),
                "--local-destination",
                &format!("{}/tcp", local_port),
                "--privkey",
                client_privkey,
                "--server-pubkey",
                server_pubkey,
                "--insecure", // テスト用: 証明書検証をスキップ
            ])
            .stdout(Stdio::inherit()) // 標準出力を継承してログを見る
            .stderr(Stdio::inherit()) // 標準エラーを継承してログを見る
            .spawn()
            .expect("Failed to start quicport client");

        // クライアントがサーバーに接続し、トンネルを確立するまで待機
        thread::sleep(Duration::from_secs(2));

        Self { process }
    }

    /// SIGTERM を送信してグレースフルシャットダウン
    #[cfg(unix)]
    fn send_sigterm(&self) {
        unsafe {
            libc::kill(self.process.id() as i32, libc::SIGTERM);
        }
    }

    #[cfg(not(unix))]
    fn send_sigterm(&mut self) {
        let _ = self.process.kill();
    }
}

impl Drop for TestClient {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            unsafe {
                libc::kill(self.process.id() as i32, libc::SIGTERM);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = self.process.kill();
        }
        let _ = self.process.wait();
    }
}

/// ローカルサービス（エコーサーバー）をシミュレート
struct LocalService {
    listener: TcpListener,
}

impl LocalService {
    fn new(port: u16) -> Self {
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr).expect("Failed to bind local service");
        listener
            .set_nonblocking(false)
            .expect("Failed to set blocking mode");
        Self { listener }
    }

    /// 接続を受け入れてエコーバック
    ///
    /// 受信したデータをそのまま送り返す。大きなデータ（最大 64KB）に対応。
    ///
    /// 注意: wait_for_server_ready() がポートの準備状況を確認する際に一時的な
    /// 接続を作成することがあり、この接続は即座に閉じられます（EOF = 0 バイト）。
    /// そのため、0 バイト読み取りの場合は次の接続を待ちます。
    fn accept_and_echo(&self, timeout: Duration) -> std::io::Result<String> {
        self.listener
            .set_nonblocking(false)
            .expect("Failed to set blocking mode");

        let start = std::time::Instant::now();

        // 有効なデータを持つ接続が来るまでリトライ
        loop {
            if start.elapsed() > timeout {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Timeout waiting for valid connection",
                ));
            }

            eprintln!("[LocalService] Waiting for connection...");

            // タイムアウト付きで接続を待機
            let (mut stream, peer_addr) = self.listener.accept()?;
            eprintln!("[LocalService] Accepted connection from {}", peer_addr);

            // 残りのタイムアウト時間を設定
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Timeout after accepting connection",
                ));
            }
            stream.set_read_timeout(Some(remaining))?;
            stream.set_write_timeout(Some(remaining))?;

            // 大きなデータに対応（EOF またはタイムアウトまで読み取る）
            let mut data = Vec::new();
            let mut buf = vec![0u8; 8192];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => {
                        // EOF - 読み取り完了
                        break;
                    }
                    Ok(n) => {
                        data.extend_from_slice(&buf[..n]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // タイムアウト - データがあればそれを使用、なければ続行
                        if !data.is_empty() {
                            // データを受信済みならそれを返す
                            break;
                        }
                        // まだデータがなければ待機継続（次のループで再試行）
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(e) => {
                        eprintln!("[LocalService] Read error: {}", e);
                        return Err(e);
                    }
                }
            }

            eprintln!("[LocalService] Read {} bytes", data.len());

            // 0 バイト（EOF のみ）の場合は次の接続を待つ
            // これは wait_for_server_ready() による一時的な接続の場合に発生
            if data.is_empty() {
                eprintln!("[LocalService] Empty connection (probe?), waiting for next...");
                continue;
            }

            let received = String::from_utf8_lossy(&data).to_string();

            // エコーバック
            stream.write_all(&data)?;
            stream.flush()?;
            eprintln!("[LocalService] Echoed {} bytes", data.len());

            // データがクライアントに届くまで少し待機してから接続を閉じる
            // （QUIC トンネル経由の場合、バッファリングにより即座に閉じると
            //   クライアント側で読み取り前に接続がリセットされる可能性がある）
            thread::sleep(Duration::from_millis(200));

            return Ok(received);
        }
    }

    /// 接続を受け入れて固定レスポンスを返す
    #[allow(dead_code)]
    fn accept_and_respond(&self, response: &[u8], timeout: Duration) -> std::io::Result<String> {
        self.listener
            .set_nonblocking(false)
            .expect("Failed to set blocking mode");

        let (mut stream, _) = self.listener.accept()?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf)?;
        let received = String::from_utf8_lossy(&buf[..n]).to_string();

        // 固定レスポンスを返す
        stream.write_all(response)?;
        stream.flush()?;

        Ok(received)
    }
}

/// ローカル UDP サービス（エコーサーバー）をシミュレート
struct LocalUdpService {
    socket: UdpSocket,
}

impl LocalUdpService {
    fn new(port: u16) -> Self {
        let addr = format!("127.0.0.1:{}", port);
        let socket = UdpSocket::bind(&addr).expect("Failed to bind UDP socket");
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("Failed to set read timeout");
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .expect("Failed to set write timeout");
        Self { socket }
    }

    /// パケットを受信してエコーバック
    fn recv_and_echo(&self, timeout: Duration) -> std::io::Result<String> {
        self.socket.set_read_timeout(Some(timeout))?;

        let mut buf = vec![0u8; 65535];
        let (len, src_addr) = self.socket.recv_from(&mut buf)?;

        eprintln!(
            "[LocalUdpService] Received {} bytes from {}",
            len, src_addr
        );

        let received = String::from_utf8_lossy(&buf[..len]).to_string();

        // エコーバック
        self.socket.send_to(&buf[..len], src_addr)?;
        eprintln!("[LocalUdpService] Echoed {} bytes to {}", len, src_addr);

        Ok(received)
    }
}

// ============================================================================
// PSK 認証テスト
// ============================================================================

#[test]
fn test_psk_authentication_and_tunnel() {
    // ポート番号を取得
    let server_port = get_test_port();
    let remote_port = get_test_port();
    let local_port = get_test_port();

    // 1. ローカルサービス（転送先）を起動
    let local_service = LocalService::new(local_port);

    // 2. quicport サーバーを起動
    let _server = TestServer::start_with_psk(server_port, test_keys::TEST_PSK);

    // 3. quicport クライアントを起動
    let _client = TestClient::start_with_psk(
        &format!("127.0.0.1:{}", server_port),
        remote_port,
        local_port,
        test_keys::TEST_PSK,
    );

    // 4. リモートポートが開くまで待機
    let remote_addr = format!("127.0.0.1:{}", remote_port);
    assert!(
        wait_for_server_ready(&remote_addr, Duration::from_secs(5)),
        "Remote port {} did not become available",
        remote_port
    );

    // 5. トンネル経由でデータを送受信
    let test_message = b"Hello through PSK tunnel!";

    // ローカルサービスを別スレッドで待機
    let local_service_handle =
        thread::spawn(move || local_service.accept_and_echo(Duration::from_secs(5)));

    // トンネル経由で接続
    thread::sleep(Duration::from_millis(100));
    let mut tunnel_conn = TcpStream::connect(&remote_addr).expect("Failed to connect to tunnel");
    tunnel_conn
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    tunnel_conn
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // データを送信
    tunnel_conn
        .write_all(test_message)
        .expect("Failed to write to tunnel");
    tunnel_conn.flush().expect("Failed to flush");

    // 書き込み完了をシグナル（EOF を送信）
    tunnel_conn
        .shutdown(std::net::Shutdown::Write)
        .expect("Failed to shutdown write");

    // レスポンスを受信
    let mut response = vec![0u8; 1024];
    let n = tunnel_conn
        .read(&mut response)
        .expect("Failed to read response");
    let response_str = String::from_utf8_lossy(&response[..n]);

    // ローカルサービスが受信したデータを確認
    let received = local_service_handle
        .join()
        .expect("Local service thread panicked");
    assert!(received.is_ok(), "Local service failed: {:?}", received);
    assert_eq!(
        received.unwrap(),
        String::from_utf8_lossy(test_message),
        "Data mismatch at local service"
    );

    // エコーバックされたデータを確認
    assert_eq!(
        response_str,
        String::from_utf8_lossy(test_message),
        "Echo response mismatch"
    );
}

// ============================================================================
// X25519 相互認証テスト
// ============================================================================

#[test]
fn test_x25519_mutual_authentication_and_tunnel() {
    // ポート番号を取得
    let server_port = get_test_port();
    let remote_port = get_test_port();
    let local_port = get_test_port();

    // 1. ローカルサービスを起動
    let local_service = LocalService::new(local_port);

    // 2. quicport サーバーを起動（X25519 相互認証）
    let _server = TestServer::start_with_x25519(
        server_port,
        test_keys::SERVER_PRIVKEY,
        test_keys::CLIENT_PUBKEY,
    );

    // 3. quicport クライアントを起動（X25519 相互認証）
    let _client = TestClient::start_with_x25519(
        &format!("127.0.0.1:{}", server_port),
        remote_port,
        local_port,
        test_keys::CLIENT_PRIVKEY,
        test_keys::SERVER_PUBKEY,
    );

    // 4. リモートポートが開くまで待機
    let remote_addr = format!("127.0.0.1:{}", remote_port);
    assert!(
        wait_for_server_ready(&remote_addr, Duration::from_secs(5)),
        "Remote port {} did not become available",
        remote_port
    );

    // 5. トンネル経由でデータを送受信
    let test_message = b"Hello through X25519 tunnel!";

    let local_service_handle =
        thread::spawn(move || local_service.accept_and_echo(Duration::from_secs(5)));

    thread::sleep(Duration::from_millis(100));
    let mut tunnel_conn = TcpStream::connect(&remote_addr).expect("Failed to connect to tunnel");
    tunnel_conn
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    tunnel_conn
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    tunnel_conn
        .write_all(test_message)
        .expect("Failed to write to tunnel");
    tunnel_conn.flush().expect("Failed to flush");

    // 書き込み完了をシグナル（EOF を送信）
    tunnel_conn
        .shutdown(std::net::Shutdown::Write)
        .expect("Failed to shutdown write");

    let mut response = vec![0u8; 1024];
    let n = tunnel_conn
        .read(&mut response)
        .expect("Failed to read response");
    let response_str = String::from_utf8_lossy(&response[..n]);

    let received = local_service_handle
        .join()
        .expect("Local service thread panicked");
    assert!(received.is_ok(), "Local service failed: {:?}", received);
    assert_eq!(
        received.unwrap(),
        String::from_utf8_lossy(test_message),
        "Data mismatch at local service"
    );
    assert_eq!(
        response_str,
        String::from_utf8_lossy(test_message),
        "Echo response mismatch"
    );
}

// ============================================================================
// ポートフォワーディング（データリレー）テスト
// ============================================================================

#[test]
fn test_port_forwarding_large_data() {
    // ポート番号を取得
    let server_port = get_test_port();
    let remote_port = get_test_port();
    let local_port = get_test_port();

    // 1. ローカルサービスを起動
    let local_service = LocalService::new(local_port);

    // 2. quicport サーバーとクライアントを起動
    let _server = TestServer::start_with_psk(server_port, test_keys::TEST_PSK);
    let _client = TestClient::start_with_psk(
        &format!("127.0.0.1:{}", server_port),
        remote_port,
        local_port,
        test_keys::TEST_PSK,
    );

    // 3. リモートポートが開くまで待機
    let remote_addr = format!("127.0.0.1:{}", remote_port);
    assert!(
        wait_for_server_ready(&remote_addr, Duration::from_secs(5)),
        "Remote port did not become available"
    );

    // 4. 大きなデータを送受信（8KB）
    let test_data: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
    let test_data_clone = test_data.clone();

    let local_service_handle =
        thread::spawn(move || local_service.accept_and_echo(Duration::from_secs(10)));

    thread::sleep(Duration::from_millis(100));
    let mut tunnel_conn = TcpStream::connect(&remote_addr).expect("Failed to connect to tunnel");
    tunnel_conn
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    tunnel_conn
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    tunnel_conn
        .write_all(&test_data)
        .expect("Failed to write large data");
    tunnel_conn.flush().expect("Failed to flush");

    // 書き込み完了をシグナル（EOF を送信）
    // これにより LocalService が全データを読み取れる
    tunnel_conn
        .shutdown(std::net::Shutdown::Write)
        .expect("Failed to shutdown write");

    // レスポンスを受信（大きなデータなので複数回読み取りが必要な場合がある）
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    while response.len() < test_data_clone.len() {
        match tunnel_conn.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                // 接続がリセットされた場合、既に受信したデータを確認
                break;
            }
            Err(e) => panic!("Failed to read: {}", e),
        }
    }

    let _ = local_service_handle.join();

    assert_eq!(
        response.len(),
        test_data_clone.len(),
        "Response size mismatch"
    );
    assert_eq!(response, test_data_clone, "Large data mismatch");
}

// ============================================================================
// グレースフルシャットダウンテスト
// ============================================================================

#[test]
#[cfg(unix)]
fn test_graceful_shutdown() {
    // ポート番号を取得
    let server_port = get_test_port();
    let remote_port = get_test_port();
    let local_port = get_test_port();

    // 1. ローカルサービスを起動
    let _local_service = LocalService::new(local_port);

    // 2. quicport サーバーとクライアントを起動
    let _server = TestServer::start_with_psk(server_port, test_keys::TEST_PSK);
    let client = TestClient::start_with_psk(
        &format!("127.0.0.1:{}", server_port),
        remote_port,
        local_port,
        test_keys::TEST_PSK,
    );

    // 3. リモートポートが開くまで待機
    let remote_addr = format!("127.0.0.1:{}", remote_port);
    assert!(
        wait_for_server_ready(&remote_addr, Duration::from_secs(5)),
        "Remote port did not become available"
    );

    // 4. SIGTERM を送信してグレースフルシャットダウン
    client.send_sigterm();

    // 5. シャットダウン後、ポートが解放されることを確認
    thread::sleep(Duration::from_secs(2));

    // ポートが閉じていることを確認（接続失敗）
    let result =
        TcpStream::connect_timeout(&remote_addr.parse().unwrap(), Duration::from_millis(500));
    assert!(
        result.is_err(),
        "Port should be closed after graceful shutdown"
    );
}

// ============================================================================
// 複数接続テスト（接続確立のみ）
// ============================================================================

#[test]
fn test_tunnel_accepts_connections() {
    // ポート番号を取得
    let server_port = get_test_port();
    let remote_port = get_test_port();
    let local_port = get_test_port();

    // 1. ローカルサービスを起動（ノンブロッキングで複数接続を受け入れ可能に）
    let _local_service = LocalService::new(local_port);

    // 2. quicport サーバーとクライアントを起動
    let _server = TestServer::start_with_psk(server_port, test_keys::TEST_PSK);
    let _client = TestClient::start_with_psk(
        &format!("127.0.0.1:{}", server_port),
        remote_port,
        local_port,
        test_keys::TEST_PSK,
    );

    // 3. リモートポートが開くまで待機
    let remote_addr = format!("127.0.0.1:{}", remote_port);
    assert!(
        wait_for_server_ready(&remote_addr, Duration::from_secs(5)),
        "Remote port did not become available"
    );

    // 4. トンネル経由で接続できることを確認
    let tunnel_result =
        TcpStream::connect_timeout(&remote_addr.parse().unwrap(), Duration::from_secs(2));
    assert!(
        tunnel_result.is_ok(),
        "Failed to connect through tunnel: {:?}",
        tunnel_result.err()
    );
}

// ============================================================================
// 認証失敗テスト
// ============================================================================

#[test]
fn test_wrong_psk_authentication_fails() {
    // ポート番号を取得
    let server_port = get_test_port();
    let remote_port = get_test_port();
    let local_port = get_test_port();

    // 1. quicport サーバーを起動
    let _server = TestServer::start_with_psk(server_port, "correct-psk");

    // 2. 間違った PSK でクライアントを起動
    let _client = TestClient::start_with_psk(
        &format!("127.0.0.1:{}", server_port),
        remote_port,
        local_port,
        "wrong-psk", // 間違った PSK
    );

    // 3. リモートポートは開かないはず
    let remote_addr = format!("127.0.0.1:{}", remote_port);
    let opened = wait_for_server_ready(&remote_addr, Duration::from_secs(3));
    assert!(
        !opened,
        "Remote port should NOT be available with wrong PSK"
    );
}

#[test]
fn test_wrong_x25519_key_authentication_fails() {
    // ポート番号を取得
    let server_port = get_test_port();
    let remote_port = get_test_port();
    let local_port = get_test_port();

    // 別のクライアント鍵ペア（認可されていない）
    let unauthorized_client_privkey = "YBvjXNoAQIEq/bF3iFQVfEuKDvF1J8YJHUiJLVz+jlg=";

    // 1. quicport サーバーを起動（正規のクライアント公開鍵のみ認可）
    let _server = TestServer::start_with_x25519(
        server_port,
        test_keys::SERVER_PRIVKEY,
        test_keys::CLIENT_PUBKEY, // 正規のクライアント公開鍵のみ
    );

    // 2. 認可されていない鍵でクライアントを起動
    let _client = TestClient::start_with_x25519(
        &format!("127.0.0.1:{}", server_port),
        remote_port,
        local_port,
        unauthorized_client_privkey, // 認可されていない秘密鍵
        test_keys::SERVER_PUBKEY,
    );

    // 3. リモートポートは開かないはず
    let remote_addr = format!("127.0.0.1:{}", remote_port);
    let opened = wait_for_server_ready(&remote_addr, Duration::from_secs(3));
    assert!(
        !opened,
        "Remote port should NOT be available with unauthorized key"
    );
}

// ============================================================================
// UDP トンネリングテスト
// ============================================================================

#[test]
fn test_udp_tunnel() {
    // ポート番号を取得
    let server_port = get_test_port();
    let remote_port = get_test_port();
    let local_port = get_test_port();

    // 1. ローカル UDP サービス（転送先）を起動
    let local_service = LocalUdpService::new(local_port);

    // 2. quicport サーバーを起動
    let _server = TestServer::start_with_psk(server_port, test_keys::TEST_PSK);

    // 3. quicport クライアントを起動（UDP モード）
    eprintln!(
        "[TestClient] Starting UDP client: server=127.0.0.1:{}, remote={}/udp, local={}/udp",
        server_port, remote_port, local_port
    );

    let _client_process = Command::new(quicport_binary())
        .args([
            "client",
            "-s",
            &format!("127.0.0.1:{}", server_port),
            "--remote-source",
            &format!("{}/udp", remote_port),
            "--local-destination",
            &format!("{}/udp", local_port),
            "--psk",
            test_keys::TEST_PSK,
            "--insecure",
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to start quicport client");

    // クライアントがサーバーに接続し、トンネルを確立するまで待機
    thread::sleep(Duration::from_secs(2));

    // 4. トンネル経由で UDP パケットを送受信
    let test_message = b"Hello UDP tunnel!";

    // ローカルサービスを別スレッドで待機
    let local_service_handle =
        thread::spawn(move || local_service.recv_and_echo(Duration::from_secs(5)));

    // 少し待機してからパケット送信
    thread::sleep(Duration::from_millis(100));

    // トンネル経由で UDP パケットを送信
    let client_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind client UDP socket");
    client_socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("Failed to set read timeout");

    let remote_addr = format!("127.0.0.1:{}", remote_port);
    client_socket
        .send_to(test_message, &remote_addr)
        .expect("Failed to send UDP packet");
    eprintln!("[Test] Sent UDP packet to {}", remote_addr);

    // レスポンスを受信
    let mut response = vec![0u8; 1024];
    let (n, _) = client_socket
        .recv_from(&mut response)
        .expect("Failed to receive UDP response");
    let response_str = String::from_utf8_lossy(&response[..n]);
    eprintln!("[Test] Received UDP response: {} bytes", n);

    // ローカルサービスが受信したデータを確認
    let received = local_service_handle
        .join()
        .expect("Local service thread panicked");
    assert!(received.is_ok(), "Local service failed: {:?}", received);
    assert_eq!(
        received.unwrap(),
        String::from_utf8_lossy(test_message),
        "Data mismatch at local service"
    );

    // エコーバックされたデータを確認
    assert_eq!(
        response_str,
        String::from_utf8_lossy(test_message),
        "Echo response mismatch"
    );
}
