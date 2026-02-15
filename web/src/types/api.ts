// Rust IPC 型 (src/ipc/mod.rs) に対応する TypeScript 型定義
//
// DataPlaneState は serde(rename_all = "SCREAMING_SNAKE_CASE") で
// シリアライズされるため、大文字のスネークケースで定義する。
// TunnelInfoWithDpId は serde(flatten) で tunnel フィールドが展開されるため、
// フラットな構造として定義する。

export type DataPlaneState = "STARTING" | "ACTIVE" | "DRAINING" | "TERMINATED";

export interface DataPlaneSummary {
  dp_id: string;
  pid: number;
  state: DataPlaneState;
  active_tunnels: number;
  bytes_sent: number;
  bytes_received: number;
}

// TunnelInfoWithDpId は Rust 側で #[serde(flatten)] を使用しているため、
// tunnel フィールドのプロパティが dp_id と同じレベルに展開される
export interface TunnelInfoWithDpId {
  dp_id: string;
  tunnel_id: number;
  remote_addr: string;
  forwarding_mode: string; // "RPF" | "LPF"
  started_at: number;
  active_connections: number;
  bytes_sent: number;
  bytes_received: number;
}

export interface ListDataPlanesResponse {
  data_planes: DataPlaneSummary[];
}

export interface ListTunnelsResponse {
  tunnels: TunnelInfoWithDpId[];
}

// ConnectionInfoWithDpId は Rust 側で #[serde(flatten)] を使用しているため、
// connection フィールドのプロパティが dp_id と同じレベルに展開される
export interface ConnectionInfoWithDpId {
  dp_id: string;
  connection_id: number;
  remote_addr: string;
  protocol: string; // "TCP" | "UDP"
  bytes_sent: number;
  bytes_received: number;
}

export interface ListConnectionsResponse {
  connections: ConnectionInfoWithDpId[];
}
