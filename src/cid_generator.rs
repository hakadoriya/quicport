//! eBPF ルーティング対応の Connection ID Generator
//!
//! このモジュールは、QUIC Connection ID に server_id を埋め込むことで、
//! eBPF プログラムが BPF_SK_REUSEPORT を使用してパケットを正しいソケットに
//! ルーティングできるようにします。
//!
//! # CID フォーマット (8 bytes 固定長)
//!
//! ```text
//! +------------------+------------------+
//! | server_id (4B)   | counter (4B)     |
//! | Big Endian       | Big Endian       |
//! +------------------+------------------+
//!  0                4                  8
//! ```
//!
//! - `server_id`: Data Plane プロセスを一意に識別する 32-bit 値
//! - `counter`: 接続ごとにインクリメントされる 32-bit カウンター
//!
//! # eBPF ルーティングの仕組み
//!
//! 1. eBPF プログラムが QUIC パケットを受信
//! 2. CID の先頭 4 バイト (server_id) を抽出
//! 3. BPF_MAP_TYPE_REUSEPORT_SOCKARRAY で server_id -> socket index を検索
//! 4. `bpf_sk_select_reuseport()` で対応するソケットにパケットを転送

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use quinn_proto::{ConnectionId, ConnectionIdGenerator};

/// CID の固定長 (8 bytes)
pub const CID_LENGTH: usize = 8;

/// server_id のオフセット (0 bytes)
pub const SERVER_ID_OFFSET: usize = 0;

/// server_id の長さ (4 bytes)
pub const SERVER_ID_LENGTH: usize = 4;

/// counter のオフセット (4 bytes)
pub const COUNTER_OFFSET: usize = 4;

/// counter の長さ (4 bytes)
pub const COUNTER_LENGTH: usize = 4;

/// eBPF ルーティング対応の Connection ID Generator
///
/// 8 バイト固定長の CID を生成し、先頭 4 バイトに server_id を埋め込むことで、
/// eBPF プログラムがパケットを正しい Data Plane プロセスにルーティングできます。
#[derive(Debug)]
pub struct RoutableCidGenerator {
    /// このジェネレーターが生成する CID に埋め込む server_id
    server_id: u32,
    /// 接続ごとにインクリメントされるカウンター
    counter: AtomicU32,
}

impl RoutableCidGenerator {
    /// 新しい `RoutableCidGenerator` を作成
    ///
    /// # Arguments
    ///
    /// * `server_id` - この Data Plane プロセスを一意に識別する値
    ///
    /// # Example
    ///
    /// ```
    /// use quicport::cid_generator::RoutableCidGenerator;
    ///
    /// let generator = RoutableCidGenerator::new(1);
    /// ```
    pub fn new(server_id: u32) -> Self {
        Self {
            server_id,
            counter: AtomicU32::new(1),
        }
    }

    /// この Generator が使用する server_id を取得
    pub fn server_id(&self) -> u32 {
        self.server_id
    }

    /// CID から server_id を抽出
    ///
    /// # Arguments
    ///
    /// * `cid` - Connection ID (8 bytes 以上)
    ///
    /// # Returns
    ///
    /// * `Some(server_id)` - CID が有効な場合
    /// * `None` - CID が 8 bytes 未満の場合
    pub fn extract_server_id(cid: &ConnectionId) -> Option<u32> {
        let bytes = cid.as_ref();
        if bytes.len() < CID_LENGTH {
            return None;
        }
        let server_id_bytes: [u8; SERVER_ID_LENGTH] = bytes[SERVER_ID_OFFSET..COUNTER_OFFSET]
            .try_into()
            .ok()?;
        Some(u32::from_be_bytes(server_id_bytes))
    }

    /// CID から counter を抽出
    ///
    /// # Arguments
    ///
    /// * `cid` - Connection ID (8 bytes 以上)
    ///
    /// # Returns
    ///
    /// * `Some(counter)` - CID が有効な場合
    /// * `None` - CID が 8 bytes 未満の場合
    pub fn extract_counter(cid: &ConnectionId) -> Option<u32> {
        let bytes = cid.as_ref();
        if bytes.len() < CID_LENGTH {
            return None;
        }
        let counter_bytes: [u8; COUNTER_LENGTH] = bytes[COUNTER_OFFSET..CID_LENGTH]
            .try_into()
            .ok()?;
        Some(u32::from_be_bytes(counter_bytes))
    }
}

impl ConnectionIdGenerator for RoutableCidGenerator {
    /// 新しい Connection ID を生成
    ///
    /// # CID フォーマット
    ///
    /// ```text
    /// [server_id: 4 bytes (BE)] + [counter: 4 bytes (BE)]
    /// ```
    fn generate_cid(&mut self) -> ConnectionId {
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut cid = [0u8; CID_LENGTH];
        cid[SERVER_ID_OFFSET..COUNTER_OFFSET].copy_from_slice(&self.server_id.to_be_bytes());
        cid[COUNTER_OFFSET..CID_LENGTH].copy_from_slice(&counter.to_be_bytes());
        ConnectionId::new(&cid)
    }

    /// Connection ID の長さを返す (常に 8)
    fn cid_len(&self) -> usize {
        CID_LENGTH
    }

    /// Connection ID の有効期限を返す
    ///
    /// Graceful restart 中も古い CID が有効である必要があるため、
    /// 長めの有効期限を設定しています。
    fn cid_lifetime(&self) -> Option<Duration> {
        // Graceful restart を考慮して 24 時間
        Some(Duration::from_secs(24 * 60 * 60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cid_generation() {
        let mut generator = RoutableCidGenerator::new(0x12345678);

        let cid1 = generator.generate_cid();
        let cid2 = generator.generate_cid();
        let cid3 = generator.generate_cid();

        // CID の長さが 8 バイトであることを確認
        assert_eq!(cid1.len(), CID_LENGTH);
        assert_eq!(cid2.len(), CID_LENGTH);
        assert_eq!(cid3.len(), CID_LENGTH);

        // server_id が正しく埋め込まれていることを確認
        assert_eq!(RoutableCidGenerator::extract_server_id(&cid1), Some(0x12345678));
        assert_eq!(RoutableCidGenerator::extract_server_id(&cid2), Some(0x12345678));
        assert_eq!(RoutableCidGenerator::extract_server_id(&cid3), Some(0x12345678));

        // counter がインクリメントされていることを確認
        assert_eq!(RoutableCidGenerator::extract_counter(&cid1), Some(1));
        assert_eq!(RoutableCidGenerator::extract_counter(&cid2), Some(2));
        assert_eq!(RoutableCidGenerator::extract_counter(&cid3), Some(3));
    }

    #[test]
    fn test_cid_len() {
        let generator = RoutableCidGenerator::new(1);
        assert_eq!(generator.cid_len(), CID_LENGTH);
    }

    #[test]
    fn test_cid_lifetime() {
        let generator = RoutableCidGenerator::new(1);
        let lifetime = generator.cid_lifetime();
        assert!(lifetime.is_some());
        assert_eq!(lifetime.unwrap(), Duration::from_secs(24 * 60 * 60));
    }

    #[test]
    fn test_server_id_getter() {
        let generator = RoutableCidGenerator::new(42);
        assert_eq!(generator.server_id(), 42);
    }

    #[test]
    fn test_extract_from_short_cid() {
        // 8 バイト未満の CID からは抽出できない
        let short_cid = ConnectionId::new(&[0, 1, 2, 3]);
        assert_eq!(RoutableCidGenerator::extract_server_id(&short_cid), None);
        assert_eq!(RoutableCidGenerator::extract_counter(&short_cid), None);
    }

    #[test]
    fn test_big_endian_encoding() {
        let mut generator = RoutableCidGenerator::new(0x01020304);
        let cid = generator.generate_cid();
        let bytes = cid.as_ref();

        // Big Endian でエンコードされていることを確認
        assert_eq!(&bytes[0..4], &[0x01, 0x02, 0x03, 0x04]);
        // counter = 1 (Big Endian)
        assert_eq!(&bytes[4..8], &[0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn test_multiple_generators_same_server_id() {
        // 同じ server_id で複数のジェネレーターを作成
        // (通常は起こらないが、テストのため)
        let mut gen1 = RoutableCidGenerator::new(100);
        let mut gen2 = RoutableCidGenerator::new(100);

        let cid1 = gen1.generate_cid();
        let cid2 = gen2.generate_cid();

        // server_id は同じ
        assert_eq!(
            RoutableCidGenerator::extract_server_id(&cid1),
            RoutableCidGenerator::extract_server_id(&cid2)
        );

        // counter は両方とも 1 から始まる (独立したカウンター)
        assert_eq!(RoutableCidGenerator::extract_counter(&cid1), Some(1));
        assert_eq!(RoutableCidGenerator::extract_counter(&cid2), Some(1));
    }

    #[test]
    fn test_different_server_ids() {
        let mut gen1 = RoutableCidGenerator::new(1);
        let mut gen2 = RoutableCidGenerator::new(2);

        let cid1 = gen1.generate_cid();
        let cid2 = gen2.generate_cid();

        // server_id が異なることを確認
        assert_ne!(
            RoutableCidGenerator::extract_server_id(&cid1),
            RoutableCidGenerator::extract_server_id(&cid2)
        );
    }
}
