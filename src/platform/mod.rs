//! プラットフォーム固有の機能
//!
//! このモジュールは OS 固有の機能を抽象化します。
//!
//! # eBPF ルーティング (Linux only)
//!
//! Linux では eBPF を使用した QUIC Connection ID ベースのパケットルーティングを
//! サポートしています。`ebpf` feature が有効な場合、`EbpfRouter` が利用可能になります。

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub use linux::*;
