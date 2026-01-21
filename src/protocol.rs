//! プロトコル定義
//!
//! quicport の制御メッセージとデータ転送のプロトコルを定義します。
//! 詳細は SPEC.md を参照してください。

use bytes::{Buf, BufMut, Bytes, BytesMut};
use quinn::{RecvStream, SendStream};
use thiserror::Error;

/// プロトコルエラー
#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),

    #[error("Invalid protocol: {0}")]
    InvalidProtocol(u8),

    #[error("Invalid status: {0}")]
    InvalidStatus(u8),

    #[error("Invalid close reason: {0}")]
    InvalidCloseReason(u8),

    #[error("Buffer too short")]
    BufferTooShort,

    #[error("Message too large")]
    MessageTooLarge,

    #[error("Stream closed")]
    StreamClosed,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Read error: {0}")]
    ReadError(#[from] quinn::ReadError),

    #[error("Write error: {0}")]
    WriteError(#[from] quinn::WriteError),
}

/// トンネリング対象のプロトコル
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    Tcp = 0x01,
    Udp = 0x02,
}

impl TryFrom<u8> for Protocol {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Protocol::Tcp),
            0x02 => Ok(Protocol::Udp),
            _ => Err(ProtocolError::InvalidProtocol(value)),
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

impl std::str::FromStr for Protocol {
    type Err = ProtocolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            _ => Err(ProtocolError::InvalidProtocol(0)),
        }
    }
}

/// 制御メッセージのタイプ
///
/// 番号体系:
/// - 0x0X: Local Port Forwarding (LPF)
/// - 0x2X: Remote Port Forwarding (RPF)
/// - 0x4X: Session Control
/// - 0x6X: Connection Control
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    // Local Port Forwarding (LPF) 用メッセージ
    LocalForwardRequest = 0x01,
    LocalForwardResponse = 0x02,
    LocalNewConnection = 0x03,
    // Remote Port Forwarding (RPF) 用メッセージ
    RemoteForwardRequest = 0x21,
    RemoteForwardResponse = 0x22,
    RemoteNewConnection = 0x23,
    // セッション制御メッセージ
    SessionClose = 0x41,
    // 接続制御メッセージ
    ConnectionClose = 0x61,
}

impl TryFrom<u8> for MessageType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            // LPF (0x0X)
            0x01 => Ok(MessageType::LocalForwardRequest),
            0x02 => Ok(MessageType::LocalForwardResponse),
            0x03 => Ok(MessageType::LocalNewConnection),
            // RPF (0x2X)
            0x21 => Ok(MessageType::RemoteForwardRequest),
            0x22 => Ok(MessageType::RemoteForwardResponse),
            0x23 => Ok(MessageType::RemoteNewConnection),
            // Session Control (0x4X)
            0x41 => Ok(MessageType::SessionClose),
            // Connection Control (0x6X)
            0x61 => Ok(MessageType::ConnectionClose),
            _ => Err(ProtocolError::InvalidMessageType(value)),
        }
    }
}

/// RemoteForwardResponse のステータス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseStatus {
    Success = 0x00,
    PortInUse = 0x01,
    PermissionDenied = 0x02,
    InternalError = 0x03,
}

impl TryFrom<u8> for ResponseStatus {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(ResponseStatus::Success),
            0x01 => Ok(ResponseStatus::PortInUse),
            0x02 => Ok(ResponseStatus::PermissionDenied),
            0x03 => Ok(ResponseStatus::InternalError),
            _ => Err(ProtocolError::InvalidStatus(value)),
        }
    }
}

/// ConnectionClose の理由
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CloseReason {
    Normal = 0x00,
    ConnectionRefused = 0x01,
    Timeout = 0x02,
    OtherError = 0x03,
}

impl TryFrom<u8> for CloseReason {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0x00 => Ok(CloseReason::Normal),
            0x01 => Ok(CloseReason::ConnectionRefused),
            0x02 => Ok(CloseReason::Timeout),
            0x03 => Ok(CloseReason::OtherError),
            _ => Err(ProtocolError::InvalidCloseReason(value)),
        }
    }
}

/// 制御メッセージ
#[derive(Debug, Clone)]
pub enum ControlMessage {
    // =========================================================================
    // Remote Port Forwarding (RPF) 用メッセージ
    // サーバー側でポートをリッスンし、クライアント側のローカルサービスに転送
    // =========================================================================
    /// ポート開放リクエスト (Client → Server)
    ///
    /// - port: サーバー側でリッスンするポート番号
    /// - protocol: プロトコル (TCP/UDP)
    /// - local_destination: クライアント側の転送先（ログ用メタデータ）
    RemoteForwardRequest {
        port: u16,
        protocol: Protocol,
        local_destination: String,
    },

    /// ポート開放レスポンス (Server → Client)
    RemoteForwardResponse {
        status: ResponseStatus,
        message: String,
    },

    // =========================================================================
    // Local Port Forwarding (LPF) 用メッセージ
    // クライアント側でポートをリッスンし、サーバー側のリモートサービスに転送
    // =========================================================================
    /// ローカルフォワードリクエスト (Client → Server)
    ///
    /// - remote_destination: サーバー側の転送先 (例: "192.168.1.100:22")
    /// - protocol: プロトコル (TCP/UDP)
    /// - local_source: クライアント側のリッスンポート（ログ用メタデータ）
    LocalForwardRequest {
        remote_destination: String,
        protocol: Protocol,
        local_source: String,
    },

    /// ローカルフォワードレスポンス (Server → Client)
    LocalForwardResponse {
        status: ResponseStatus,
        message: String,
    },

    // =========================================================================
    // セッション制御メッセージ
    // =========================================================================
    /// セッション終了 (双方向)
    SessionClose,

    // =========================================================================
    // 接続管理メッセージ
    // =========================================================================
    /// 新しい接続の通知 (Server → Client) - RPF 用
    RemoteNewConnection {
        connection_id: u32,
        protocol: Protocol,
    },

    /// 接続終了 (双方向)
    ConnectionClose {
        connection_id: u32,
        reason: CloseReason,
    },

    /// 新しいローカル接続の通知 (Client → Server) - LPF 用
    ///
    /// クライアントがローカルポートで新しい接続を受け付けた際に送信
    LocalNewConnection {
        connection_id: u32,
        protocol: Protocol,
    },
}

impl ControlMessage {
    /// メッセージをバイト列にエンコード
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();

        match self {
            ControlMessage::RemoteForwardRequest {
                port,
                protocol,
                local_destination,
            } => {
                let dest_bytes = local_destination.as_bytes();
                buf.put_u8(MessageType::RemoteForwardRequest as u8);
                // payload: port(2) + protocol(1) + local_destination(variable)
                buf.put_u16(3 + dest_bytes.len() as u16);
                buf.put_u16(*port);
                buf.put_u8(*protocol as u8);
                buf.put_slice(dest_bytes);
            }
            ControlMessage::RemoteForwardResponse { status, message } => {
                let msg_bytes = message.as_bytes();
                buf.put_u8(MessageType::RemoteForwardResponse as u8);
                buf.put_u16(1 + msg_bytes.len() as u16);
                buf.put_u8(*status as u8);
                buf.put_slice(msg_bytes);
            }
            ControlMessage::SessionClose => {
                buf.put_u8(MessageType::SessionClose as u8);
                buf.put_u16(0);
            }
            ControlMessage::RemoteNewConnection {
                connection_id,
                protocol,
            } => {
                buf.put_u8(MessageType::RemoteNewConnection as u8);
                buf.put_u16(5); // 4 + 1
                buf.put_u32(*connection_id);
                buf.put_u8(*protocol as u8);
            }
            ControlMessage::ConnectionClose {
                connection_id,
                reason,
            } => {
                buf.put_u8(MessageType::ConnectionClose as u8);
                buf.put_u16(5);
                buf.put_u32(*connection_id);
                buf.put_u8(*reason as u8);
            }
            ControlMessage::LocalForwardRequest {
                remote_destination,
                protocol,
                local_source,
            } => {
                // payload: protocol(1) + remote_dest_len(2) + remote_dest + local_source
                let remote_bytes = remote_destination.as_bytes();
                let local_bytes = local_source.as_bytes();
                buf.put_u8(MessageType::LocalForwardRequest as u8);
                buf.put_u16((1 + 2 + remote_bytes.len() + local_bytes.len()) as u16);
                buf.put_u8(*protocol as u8);
                buf.put_u16(remote_bytes.len() as u16);
                buf.put_slice(remote_bytes);
                buf.put_slice(local_bytes);
            }
            ControlMessage::LocalForwardResponse { status, message } => {
                let msg_bytes = message.as_bytes();
                buf.put_u8(MessageType::LocalForwardResponse as u8);
                buf.put_u16(1 + msg_bytes.len() as u16);
                buf.put_u8(*status as u8);
                buf.put_slice(msg_bytes);
            }
            ControlMessage::LocalNewConnection {
                connection_id,
                protocol,
            } => {
                buf.put_u8(MessageType::LocalNewConnection as u8);
                buf.put_u16(5); // 4 + 1
                buf.put_u32(*connection_id);
                buf.put_u8(*protocol as u8);
            }
        }

        buf.freeze()
    }

    /// バイト列からメッセージをデコード
    pub fn decode(mut buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < 3 {
            return Err(ProtocolError::BufferTooShort);
        }

        let msg_type = MessageType::try_from(buf.get_u8())?;
        let payload_len = buf.get_u16() as usize;

        if buf.len() < payload_len {
            return Err(ProtocolError::BufferTooShort);
        }

        match msg_type {
            MessageType::RemoteForwardRequest => {
                if payload_len < 3 {
                    return Err(ProtocolError::BufferTooShort);
                }
                let port = buf.get_u16();
                let protocol = Protocol::try_from(buf.get_u8())?;
                // 残りのバイトは local_destination
                let local_destination =
                    String::from_utf8_lossy(&buf[..payload_len - 3]).to_string();
                Ok(ControlMessage::RemoteForwardRequest {
                    port,
                    protocol,
                    local_destination,
                })
            }
            MessageType::RemoteForwardResponse => {
                if payload_len < 1 {
                    return Err(ProtocolError::BufferTooShort);
                }
                let status = ResponseStatus::try_from(buf.get_u8())?;
                let message = String::from_utf8_lossy(&buf[..payload_len - 1]).to_string();
                Ok(ControlMessage::RemoteForwardResponse { status, message })
            }
            MessageType::SessionClose => Ok(ControlMessage::SessionClose),
            MessageType::RemoteNewConnection => {
                if payload_len < 5 {
                    return Err(ProtocolError::BufferTooShort);
                }
                let connection_id = buf.get_u32();
                let protocol = Protocol::try_from(buf.get_u8())?;
                Ok(ControlMessage::RemoteNewConnection {
                    connection_id,
                    protocol,
                })
            }
            MessageType::ConnectionClose => {
                if payload_len < 5 {
                    return Err(ProtocolError::BufferTooShort);
                }
                let connection_id = buf.get_u32();
                let reason = CloseReason::try_from(buf.get_u8())?;
                Ok(ControlMessage::ConnectionClose {
                    connection_id,
                    reason,
                })
            }
            MessageType::LocalForwardRequest => {
                // payload: protocol(1) + remote_dest_len(2) + remote_dest + local_source
                if payload_len < 3 {
                    return Err(ProtocolError::BufferTooShort);
                }
                let protocol = Protocol::try_from(buf.get_u8())?;
                let remote_dest_len = buf.get_u16() as usize;
                if payload_len < 3 + remote_dest_len {
                    return Err(ProtocolError::BufferTooShort);
                }
                let remote_destination =
                    String::from_utf8_lossy(&buf[..remote_dest_len]).to_string();
                buf.advance(remote_dest_len);
                let local_source_len = payload_len - 3 - remote_dest_len;
                let local_source = String::from_utf8_lossy(&buf[..local_source_len]).to_string();
                Ok(ControlMessage::LocalForwardRequest {
                    remote_destination,
                    protocol,
                    local_source,
                })
            }
            MessageType::LocalForwardResponse => {
                if payload_len < 1 {
                    return Err(ProtocolError::BufferTooShort);
                }
                let status = ResponseStatus::try_from(buf.get_u8())?;
                let message = String::from_utf8_lossy(&buf[..payload_len - 1]).to_string();
                Ok(ControlMessage::LocalForwardResponse { status, message })
            }
            MessageType::LocalNewConnection => {
                if payload_len < 5 {
                    return Err(ProtocolError::BufferTooShort);
                }
                let connection_id = buf.get_u32();
                let protocol = Protocol::try_from(buf.get_u8())?;
                Ok(ControlMessage::LocalNewConnection {
                    connection_id,
                    protocol,
                })
            }
        }
    }
}

/// ポート指定をパース
///
/// サポートする形式:
/// - "port" (e.g., "9022") -> (9022, Protocol::Tcp)
/// - "port/protocol" (e.g., "9022/tcp") -> (9022, Protocol::Tcp)
///
/// プロトコル省略時は TCP がデフォルト
pub fn parse_port_spec(spec: &str) -> Result<(u16, Protocol), ProtocolError> {
    let (port_str, protocol) = if let Some(slash_pos) = spec.find('/') {
        let (p, proto_str) = spec.split_at(slash_pos);
        let protocol: Protocol = proto_str[1..].parse()?;
        (p, protocol)
    } else {
        (spec, Protocol::Tcp)
    };

    let port: u16 = port_str
        .parse()
        .map_err(|_| ProtocolError::InvalidProtocol(0))?;

    Ok((port, protocol))
}

/// 転送先指定をパース
///
/// サポートする形式:
/// - "port" (e.g., "22") -> ("127.0.0.1", 22, Protocol::Tcp)
/// - "port/protocol" (e.g., "22/tcp") -> ("127.0.0.1", 22, Protocol::Tcp)
/// - "addr:port" (e.g., "192.168.1.100:22") -> ("192.168.1.100", 22, Protocol::Tcp)
/// - "addr:port/protocol" (e.g., "192.168.1.100:22/tcp") -> ("192.168.1.100", 22, Protocol::Tcp)
/// - "[ipv6]:port" (e.g., "[::1]:22") -> ("::1", 22, Protocol::Tcp)
/// - "[ipv6]:port/protocol" (e.g., "[::1]:22/tcp") -> ("::1", 22, Protocol::Tcp)
///
/// プロトコル省略時は TCP がデフォルト
pub fn parse_destination_spec(spec: &str) -> Result<(String, u16, Protocol), ProtocolError> {
    // '/' があればプロトコル部分を分離、なければ TCP をデフォルト
    let (addr_port, protocol) = if let Some(slash_pos) = spec.rfind('/') {
        let (ap, proto_str) = spec.split_at(slash_pos);
        let protocol: Protocol = proto_str[1..].parse()?;
        (ap, protocol)
    } else {
        (spec, Protocol::Tcp)
    };

    // addr:port または port のみかを判定
    // IPv6 アドレスの場合は [addr]:port 形式
    if addr_port.starts_with('[') {
        // IPv6: [addr]:port
        let bracket_end = addr_port
            .find(']')
            .ok_or(ProtocolError::InvalidProtocol(0))?;
        let addr = &addr_port[1..bracket_end];
        let port_part = &addr_port[bracket_end + 1..];
        if !port_part.starts_with(':') {
            return Err(ProtocolError::InvalidProtocol(0));
        }
        let port: u16 = port_part[1..]
            .parse()
            .map_err(|_| ProtocolError::InvalidProtocol(0))?;
        Ok((addr.to_string(), port, protocol))
    } else if let Some(colon_pos) = addr_port.rfind(':') {
        // addr:port 形式（IPv4 またはホスト名）
        let addr = &addr_port[..colon_pos];
        let port: u16 = addr_port[colon_pos + 1..]
            .parse()
            .map_err(|_| ProtocolError::InvalidProtocol(0))?;
        Ok((addr.to_string(), port, protocol))
    } else {
        // port のみ -> 127.0.0.1 をデフォルトとして使用
        let port: u16 = addr_port
            .parse()
            .map_err(|_| ProtocolError::InvalidProtocol(0))?;
        Ok(("127.0.0.1".to_string(), port, protocol))
    }
}

/// 制御ストリームのラッパー
///
/// QUIC ストリームは バイトストリームであり、`read()` が 1 メッセージ分を
/// 返す保証がないため、メッセージフレーミングを正しく処理する必要がある。
///
/// このラッパーは以下を保証する:
/// - 部分読み取り (partial read) の正しいバッファリング
/// - メッセージ境界の維持
/// - 複数メッセージの正しい分離
pub struct ControlStream {
    send: SendStream,
    recv: RecvStream,
    /// 読み取りバッファ（部分読み取りデータを保持）
    read_buf: BytesMut,
}

/// メッセージヘッダーサイズ (1 byte type + 2 bytes length)
const HEADER_SIZE: usize = 3;

/// 最大ペイロードサイズ (64KB)
const MAX_PAYLOAD_SIZE: usize = 65535;

impl ControlStream {
    /// 新しい ControlStream を作成
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            read_buf: BytesMut::with_capacity(1024),
        }
    }

    /// SendStream への参照を取得（認証処理用）
    #[allow(dead_code)]
    pub fn send_stream(&mut self) -> &mut SendStream {
        &mut self.send
    }

    /// RecvStream への参照を取得（認証処理用）
    #[allow(dead_code)]
    pub fn recv_stream(&mut self) -> &mut RecvStream {
        &mut self.recv
    }

    /// ControlStream を分解して内部のストリームを取得
    #[allow(dead_code)]
    pub fn into_inner(self) -> (SendStream, RecvStream) {
        (self.send, self.recv)
    }

    /// メッセージを送信
    pub async fn send_message(&mut self, msg: &ControlMessage) -> Result<(), ProtocolError> {
        let encoded = msg.encode();
        self.send.write_all(&encoded).await?;
        Ok(())
    }

    /// 完全なメッセージを 1 つ読み取る
    ///
    /// この関数は以下を保証する:
    /// - ヘッダー (3 bytes) を完全に読み取るまでバッファリング
    /// - ペイロード全体を完全に読み取るまでバッファリング
    /// - 余分なデータはバッファに保持し、次回の読み取りで使用
    pub async fn recv_message(&mut self) -> Result<ControlMessage, ProtocolError> {
        // 1. ヘッダー (3 bytes) を読み取る
        self.fill_buffer(HEADER_SIZE).await?;

        // 2. ペイロード長を取得（バッファを消費せずに peek）
        let payload_len = u16::from_be_bytes([self.read_buf[1], self.read_buf[2]]) as usize;

        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::MessageTooLarge);
        }

        // 3. メッセージ全体 (header + payload) を読み取る
        let total_len = HEADER_SIZE + payload_len;
        self.fill_buffer(total_len).await?;

        // 4. バッファからメッセージ部分を取り出してデコード
        let msg_bytes = self.read_buf.split_to(total_len);
        ControlMessage::decode(&msg_bytes)
    }

    /// バッファに指定サイズ以上のデータを確保
    ///
    /// 既にバッファに十分なデータがある場合は即座に戻る。
    /// 不足分はストリームから読み取る。
    async fn fill_buffer(&mut self, required: usize) -> Result<(), ProtocolError> {
        while self.read_buf.len() < required {
            // 一時バッファに読み取り
            let mut tmp = vec![0u8; 4096];
            match self.recv.read(&mut tmp).await? {
                Some(0) | None => {
                    return Err(ProtocolError::StreamClosed);
                }
                Some(n) => {
                    self.read_buf.extend_from_slice(&tmp[..n]);
                }
            }
        }
        Ok(())
    }

    /// SendStream を finish する
    pub fn finish(&mut self) -> Result<(), ProtocolError> {
        self.send.finish().map_err(|e| {
            ProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // Protocol enum テスト
    // ============================================================================

    #[test]
    fn test_protocol_try_from() {
        assert_eq!(Protocol::try_from(0x01).unwrap(), Protocol::Tcp);
        assert_eq!(Protocol::try_from(0x02).unwrap(), Protocol::Udp);
        assert!(Protocol::try_from(0x00).is_err());
        assert!(Protocol::try_from(0x03).is_err());
    }

    #[test]
    fn test_protocol_from_str() {
        assert_eq!("tcp".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert_eq!("TCP".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert_eq!("udp".parse::<Protocol>().unwrap(), Protocol::Udp);
        assert_eq!("UDP".parse::<Protocol>().unwrap(), Protocol::Udp);
        assert!("invalid".parse::<Protocol>().is_err());
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(format!("{}", Protocol::Tcp), "tcp");
        assert_eq!(format!("{}", Protocol::Udp), "udp");
    }

    // ============================================================================
    // ResponseStatus enum テスト
    // ============================================================================

    #[test]
    fn test_response_status_try_from() {
        assert_eq!(
            ResponseStatus::try_from(0x00).unwrap(),
            ResponseStatus::Success
        );
        assert_eq!(
            ResponseStatus::try_from(0x01).unwrap(),
            ResponseStatus::PortInUse
        );
        assert_eq!(
            ResponseStatus::try_from(0x02).unwrap(),
            ResponseStatus::PermissionDenied
        );
        assert_eq!(
            ResponseStatus::try_from(0x03).unwrap(),
            ResponseStatus::InternalError
        );
        assert!(ResponseStatus::try_from(0x04).is_err());
    }

    // ============================================================================
    // CloseReason enum テスト
    // ============================================================================

    #[test]
    fn test_close_reason_try_from() {
        assert_eq!(CloseReason::try_from(0x00).unwrap(), CloseReason::Normal);
        assert_eq!(
            CloseReason::try_from(0x01).unwrap(),
            CloseReason::ConnectionRefused
        );
        assert_eq!(CloseReason::try_from(0x02).unwrap(), CloseReason::Timeout);
        assert_eq!(
            CloseReason::try_from(0x03).unwrap(),
            CloseReason::OtherError
        );
        assert!(CloseReason::try_from(0x04).is_err());
    }

    // ============================================================================
    // MessageType enum テスト
    // ============================================================================

    #[test]
    fn test_message_type_try_from() {
        // LPF メッセージ (0x0X)
        assert_eq!(
            MessageType::try_from(0x01).unwrap(),
            MessageType::LocalForwardRequest
        );
        assert_eq!(
            MessageType::try_from(0x02).unwrap(),
            MessageType::LocalForwardResponse
        );
        assert_eq!(
            MessageType::try_from(0x03).unwrap(),
            MessageType::LocalNewConnection
        );
        // RPF メッセージ (0x2X)
        assert_eq!(
            MessageType::try_from(0x21).unwrap(),
            MessageType::RemoteForwardRequest
        );
        assert_eq!(
            MessageType::try_from(0x22).unwrap(),
            MessageType::RemoteForwardResponse
        );
        assert_eq!(
            MessageType::try_from(0x23).unwrap(),
            MessageType::RemoteNewConnection
        );
        // セッション制御メッセージ (0x4X)
        assert_eq!(
            MessageType::try_from(0x41).unwrap(),
            MessageType::SessionClose
        );
        // 接続制御メッセージ (0x6X)
        assert_eq!(
            MessageType::try_from(0x61).unwrap(),
            MessageType::ConnectionClose
        );
        // 無効な値
        assert!(MessageType::try_from(0x00).is_err());
        assert!(MessageType::try_from(0x10).is_err());
        assert!(MessageType::try_from(0xFF).is_err());
    }

    // ============================================================================
    // ControlMessage エンコード/デコード テスト
    // ============================================================================

    #[test]
    fn test_port_request_encode_decode() {
        let msg = ControlMessage::RemoteForwardRequest {
            port: 9022,
            protocol: Protocol::Tcp,
            local_destination: "192.168.1.100:22".to_string(),
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();

        match decoded {
            ControlMessage::RemoteForwardRequest {
                port,
                protocol,
                local_destination,
            } => {
                assert_eq!(port, 9022);
                assert_eq!(protocol, Protocol::Tcp);
                assert_eq!(local_destination, "192.168.1.100:22");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_port_response_encode_decode() {
        let msg = ControlMessage::RemoteForwardResponse {
            status: ResponseStatus::Success,
            message: "Listening on port 9022".to_string(),
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();

        match decoded {
            ControlMessage::RemoteForwardResponse { status, message } => {
                assert_eq!(status, ResponseStatus::Success);
                assert_eq!(message, "Listening on port 9022");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_port_response_error_encode_decode() {
        let msg = ControlMessage::RemoteForwardResponse {
            status: ResponseStatus::PortInUse,
            message: "Port already in use".to_string(),
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();

        match decoded {
            ControlMessage::RemoteForwardResponse { status, message } => {
                assert_eq!(status, ResponseStatus::PortInUse);
                assert_eq!(message, "Port already in use");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_session_close_encode_decode() {
        let msg = ControlMessage::SessionClose;
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();

        assert!(matches!(decoded, ControlMessage::SessionClose));
    }

    #[test]
    fn test_new_connection_encode_decode() {
        let msg = ControlMessage::RemoteNewConnection {
            connection_id: 12345,
            protocol: Protocol::Tcp,
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();

        match decoded {
            ControlMessage::RemoteNewConnection {
                connection_id,
                protocol,
            } => {
                assert_eq!(connection_id, 12345);
                assert_eq!(protocol, Protocol::Tcp);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_connection_close_encode_decode() {
        let msg = ControlMessage::ConnectionClose {
            connection_id: 99,
            reason: CloseReason::ConnectionRefused,
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();

        match decoded {
            ControlMessage::ConnectionClose {
                connection_id,
                reason,
            } => {
                assert_eq!(connection_id, 99);
                assert_eq!(reason, CloseReason::ConnectionRefused);
            }
            _ => panic!("Wrong message type"),
        }
    }

    // ============================================================================
    // デコードエラー テスト
    // ============================================================================

    #[test]
    fn test_decode_buffer_too_short() {
        // ヘッダーより短い
        assert!(matches!(
            ControlMessage::decode(&[0x21, 0x00]),
            Err(ProtocolError::BufferTooShort)
        ));

        // ペイロードが不足
        assert!(matches!(
            ControlMessage::decode(&[0x21, 0x00, 0x03, 0x00]), // RemoteForwardRequest だが 3 バイト必要で 1 バイトしかない
            Err(ProtocolError::BufferTooShort)
        ));
    }

    #[test]
    fn test_decode_invalid_message_type() {
        assert!(matches!(
            ControlMessage::decode(&[0xFF, 0x00, 0x00]),
            Err(ProtocolError::InvalidMessageType(0xFF))
        ));
    }

    #[test]
    fn test_decode_invalid_protocol() {
        // RemoteForwardRequest with invalid protocol
        let mut buf = vec![0x21, 0x00, 0x03]; // RemoteForwardRequest header
        buf.extend_from_slice(&9022u16.to_be_bytes()); // port
        buf.push(0xFF); // invalid protocol

        assert!(matches!(
            ControlMessage::decode(&buf),
            Err(ProtocolError::InvalidProtocol(0xFF))
        ));
    }

    // ============================================================================
    // parse_port_spec テスト
    // ============================================================================

    #[test]
    fn test_parse_port_spec() {
        let (port, protocol) = parse_port_spec("9022/tcp").unwrap();
        assert_eq!(port, 9022);
        assert_eq!(protocol, Protocol::Tcp);

        let (port, protocol) = parse_port_spec("53/udp").unwrap();
        assert_eq!(port, 53);
        assert_eq!(protocol, Protocol::Udp);
    }

    #[test]
    fn test_parse_port_spec_case_insensitive() {
        let (port, protocol) = parse_port_spec("8080/TCP").unwrap();
        assert_eq!(port, 8080);
        assert_eq!(protocol, Protocol::Tcp);

        let (port, protocol) = parse_port_spec("53/UDP").unwrap();
        assert_eq!(port, 53);
        assert_eq!(protocol, Protocol::Udp);
    }

    #[test]
    fn test_parse_port_spec_default_protocol() {
        // プロトコル省略時は TCP がデフォルト
        let (port, protocol) = parse_port_spec("9022").unwrap();
        assert_eq!(port, 9022);
        assert_eq!(protocol, Protocol::Tcp);
    }

    #[test]
    fn test_parse_port_spec_invalid() {
        // 無効なポート番号
        assert!(parse_port_spec("notaport/tcp").is_err());
        assert!(parse_port_spec("notaport").is_err());

        // 無効なプロトコル
        assert!(parse_port_spec("9022/invalid").is_err());

        // 空文字列
        assert!(parse_port_spec("").is_err());
    }

    // ============================================================================
    // parse_destination_spec テスト
    // ============================================================================

    #[test]
    fn test_parse_destination_spec_port_only() {
        // ポートのみ -> 127.0.0.1 がデフォルト、TCP がデフォルト
        let (addr, port, protocol) = parse_destination_spec("22").unwrap();
        assert_eq!(addr, "127.0.0.1");
        assert_eq!(port, 22);
        assert_eq!(protocol, Protocol::Tcp);
    }

    #[test]
    fn test_parse_destination_spec_port_protocol() {
        // port/protocol
        let (addr, port, protocol) = parse_destination_spec("22/tcp").unwrap();
        assert_eq!(addr, "127.0.0.1");
        assert_eq!(port, 22);
        assert_eq!(protocol, Protocol::Tcp);

        let (addr, port, protocol) = parse_destination_spec("53/udp").unwrap();
        assert_eq!(addr, "127.0.0.1");
        assert_eq!(port, 53);
        assert_eq!(protocol, Protocol::Udp);
    }

    #[test]
    fn test_parse_destination_spec_addr_port() {
        // addr:port -> TCP がデフォルト
        let (addr, port, protocol) = parse_destination_spec("192.168.1.100:22").unwrap();
        assert_eq!(addr, "192.168.1.100");
        assert_eq!(port, 22);
        assert_eq!(protocol, Protocol::Tcp);
    }

    #[test]
    fn test_parse_destination_spec_addr_port_protocol() {
        // addr:port/protocol
        let (addr, port, protocol) = parse_destination_spec("192.168.1.100:22/tcp").unwrap();
        assert_eq!(addr, "192.168.1.100");
        assert_eq!(port, 22);
        assert_eq!(protocol, Protocol::Tcp);

        let (addr, port, protocol) = parse_destination_spec("example.com:80/tcp").unwrap();
        assert_eq!(addr, "example.com");
        assert_eq!(port, 80);
        assert_eq!(protocol, Protocol::Tcp);
    }

    #[test]
    fn test_parse_destination_spec_ipv6() {
        // IPv6: [addr]:port
        let (addr, port, protocol) = parse_destination_spec("[::1]:22").unwrap();
        assert_eq!(addr, "::1");
        assert_eq!(port, 22);
        assert_eq!(protocol, Protocol::Tcp);

        // IPv6: [addr]:port/protocol
        let (addr, port, protocol) = parse_destination_spec("[::1]:22/tcp").unwrap();
        assert_eq!(addr, "::1");
        assert_eq!(port, 22);
        assert_eq!(protocol, Protocol::Tcp);

        let (addr, port, protocol) = parse_destination_spec("[2001:db8::1]:8080/tcp").unwrap();
        assert_eq!(addr, "2001:db8::1");
        assert_eq!(port, 8080);
        assert_eq!(protocol, Protocol::Tcp);
    }

    #[test]
    fn test_parse_destination_spec_invalid() {
        // 無効なポート番号
        assert!(parse_destination_spec("notaport").is_err());
        assert!(parse_destination_spec("192.168.1.100:notaport").is_err());

        // 無効なプロトコル
        assert!(parse_destination_spec("22/invalid").is_err());

        // 空文字列
        assert!(parse_destination_spec("").is_err());

        // IPv6 でブラケットが閉じていない
        assert!(parse_destination_spec("[::1:22").is_err());
    }

    // ============================================================================
    // エッジケース テスト
    // ============================================================================

    #[test]
    fn test_port_response_empty_message() {
        let msg = ControlMessage::RemoteForwardResponse {
            status: ResponseStatus::Success,
            message: String::new(),
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();

        match decoded {
            ControlMessage::RemoteForwardResponse { status, message } => {
                assert_eq!(status, ResponseStatus::Success);
                assert_eq!(message, "");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_port_request_boundary_values() {
        // 最小ポート番号
        let msg = ControlMessage::RemoteForwardRequest {
            port: 1,
            protocol: Protocol::Tcp,
            local_destination: "22".to_string(),
        };
        let decoded = ControlMessage::decode(&msg.encode()).unwrap();
        match decoded {
            ControlMessage::RemoteForwardRequest { port, .. } => assert_eq!(port, 1),
            _ => panic!("Wrong message type"),
        }

        // 最大ポート番号
        let msg = ControlMessage::RemoteForwardRequest {
            port: 65535,
            protocol: Protocol::Udp,
            local_destination: "".to_string(),
        };
        let decoded = ControlMessage::decode(&msg.encode()).unwrap();
        match decoded {
            ControlMessage::RemoteForwardRequest { port, .. } => assert_eq!(port, 65535),
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_connection_id_boundary_values() {
        // 最小値
        let msg = ControlMessage::ConnectionClose {
            connection_id: 0,
            reason: CloseReason::Normal,
        };
        let decoded = ControlMessage::decode(&msg.encode()).unwrap();
        match decoded {
            ControlMessage::ConnectionClose { connection_id, .. } => assert_eq!(connection_id, 0),
            _ => panic!("Wrong message type"),
        }

        // 最大値
        let msg = ControlMessage::ConnectionClose {
            connection_id: u32::MAX,
            reason: CloseReason::Normal,
        };
        let decoded = ControlMessage::decode(&msg.encode()).unwrap();
        match decoded {
            ControlMessage::ConnectionClose { connection_id, .. } => {
                assert_eq!(connection_id, u32::MAX)
            }
            _ => panic!("Wrong message type"),
        }
    }

    // ============================================================================
    // Local Port Forwarding (LPF) メッセージ テスト
    // ============================================================================

    #[test]
    fn test_local_forward_request_encode_decode() {
        let msg = ControlMessage::LocalForwardRequest {
            remote_destination: "192.168.1.100:22".to_string(),
            protocol: Protocol::Tcp,
            local_source: "9022".to_string(),
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();

        match decoded {
            ControlMessage::LocalForwardRequest {
                remote_destination,
                protocol,
                local_source,
            } => {
                assert_eq!(remote_destination, "192.168.1.100:22");
                assert_eq!(protocol, Protocol::Tcp);
                assert_eq!(local_source, "9022");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_local_forward_request_udp_encode_decode() {
        let msg = ControlMessage::LocalForwardRequest {
            remote_destination: "8.8.8.8:53".to_string(),
            protocol: Protocol::Udp,
            local_source: "5353".to_string(),
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();

        match decoded {
            ControlMessage::LocalForwardRequest {
                remote_destination,
                protocol,
                local_source,
            } => {
                assert_eq!(remote_destination, "8.8.8.8:53");
                assert_eq!(protocol, Protocol::Udp);
                assert_eq!(local_source, "5353");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_local_forward_response_encode_decode() {
        let msg = ControlMessage::LocalForwardResponse {
            status: ResponseStatus::Success,
            message: "Ready to forward".to_string(),
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();

        match decoded {
            ControlMessage::LocalForwardResponse { status, message } => {
                assert_eq!(status, ResponseStatus::Success);
                assert_eq!(message, "Ready to forward");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_local_forward_response_error_encode_decode() {
        let msg = ControlMessage::LocalForwardResponse {
            status: ResponseStatus::PermissionDenied,
            message: "Cannot connect to remote".to_string(),
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();

        match decoded {
            ControlMessage::LocalForwardResponse { status, message } => {
                assert_eq!(status, ResponseStatus::PermissionDenied);
                assert_eq!(message, "Cannot connect to remote");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_local_new_connection_encode_decode() {
        let msg = ControlMessage::LocalNewConnection {
            connection_id: 42,
            protocol: Protocol::Tcp,
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();

        match decoded {
            ControlMessage::LocalNewConnection {
                connection_id,
                protocol,
            } => {
                assert_eq!(connection_id, 42);
                assert_eq!(protocol, Protocol::Tcp);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_local_new_connection_udp_encode_decode() {
        let msg = ControlMessage::LocalNewConnection {
            connection_id: 12345,
            protocol: Protocol::Udp,
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();

        match decoded {
            ControlMessage::LocalNewConnection {
                connection_id,
                protocol,
            } => {
                assert_eq!(connection_id, 12345);
                assert_eq!(protocol, Protocol::Udp);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_local_forward_request_empty_local_source() {
        let msg = ControlMessage::LocalForwardRequest {
            remote_destination: "localhost:22".to_string(),
            protocol: Protocol::Tcp,
            local_source: String::new(),
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();

        match decoded {
            ControlMessage::LocalForwardRequest {
                remote_destination,
                protocol,
                local_source,
            } => {
                assert_eq!(remote_destination, "localhost:22");
                assert_eq!(protocol, Protocol::Tcp);
                assert_eq!(local_source, "");
            }
            _ => panic!("Wrong message type"),
        }
    }
}
