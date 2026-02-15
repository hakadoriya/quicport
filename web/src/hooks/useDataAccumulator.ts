// ポーリング + データ蓄積フック
//
// - 5 秒間隔で listDataPlanes() をポーリングし、集計した DataPoint を蓄積
// - 15 秒間隔で listTunnels() をポーリング
// - 最大 1440 ポイント保持（2 時間）
// - 転送速度は前回ポイントとの差分から算出

import { useCallback, useEffect, useRef, useState } from "react";
import { loadDataPoints, loadPrevPoint, saveDataPoints, savePrevPoint } from "../lib/storage";
import { listConnections, listDataPlanes, listTunnels } from "../api/client";
import type { ConnectionInfoWithDpId, DataPlaneSummary, TunnelInfoWithDpId } from "../types/api";

export interface DataPoint {
  timestamp: number;
  dataPlaneCount: number;
  activeTunnels: number;
  bytesSent: number;
  bytesReceived: number;
  activeConnections: number;
  // 前回ポイントとの差分から算出した転送速度 (bytes/sec)
  sendRate: number;
  recvRate: number;
}

const MAX_POINTS = 1440;
const DP_POLL_INTERVAL = 5_000; // 5 秒
const TUNNEL_POLL_INTERVAL = 15_000; // 15 秒

export interface AccumulatorState {
  dataPoints: DataPoint[];
  latestDataPlanes: DataPlaneSummary[];
  latestTunnels: TunnelInfoWithDpId[];
  latestConnections: ConnectionInfoWithDpId[];
  isConnected: boolean;
}

export function useDataAccumulator(): AccumulatorState {
  const [dataPoints, setDataPoints] = useState<DataPoint[]>(() => loadDataPoints());
  const [latestDataPlanes, setLatestDataPlanes] = useState<DataPlaneSummary[]>([]);
  const [latestTunnels, setLatestTunnels] = useState<TunnelInfoWithDpId[]>([]);
  const [latestConnections, setLatestConnections] = useState<ConnectionInfoWithDpId[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const latestConnectionCountRef = useRef<number>(0);
  const prevPointRef = useRef<{ bytesSent: number; bytesReceived: number; timestamp: number } | null>(loadPrevPoint());

  // Data Planes ポーリング (5 秒間隔)
  const pollDataPlanes = useCallback(async () => {
    try {
      const res = await listDataPlanes();
      setLatestDataPlanes(res.data_planes);
      setIsConnected(true);

      const now = Date.now();
      const totalTunnels = res.data_planes.reduce((sum, dp) => sum + dp.active_tunnels, 0);
      const totalSent = res.data_planes.reduce((sum, dp) => sum + dp.bytes_sent, 0);
      const totalRecv = res.data_planes.reduce((sum, dp) => sum + dp.bytes_received, 0);

      // 転送速度を前回ポイントとの差分から算出
      let sendRate = 0;
      let recvRate = 0;
      const prev = prevPointRef.current;
      if (prev) {
        const elapsed = (now - prev.timestamp) / 1000; // 秒
        if (elapsed > 0) {
          sendRate = Math.max(0, (totalSent - prev.bytesSent) / elapsed);
          recvRate = Math.max(0, (totalRecv - prev.bytesReceived) / elapsed);
        }
      }
      prevPointRef.current = { bytesSent: totalSent, bytesReceived: totalRecv, timestamp: now };
      savePrevPoint(prevPointRef.current);

      const point: DataPoint = {
        timestamp: now,
        dataPlaneCount: res.data_planes.length,
        activeTunnels: totalTunnels,
        activeConnections: latestConnectionCountRef.current,
        bytesSent: totalSent,
        bytesReceived: totalRecv,
        sendRate,
        recvRate,
      };

      setDataPoints((prev) => {
        const next = [...prev, point];
        // 最大 1440 ポイント保持（2 時間）
        const trimmed = next.length > MAX_POINTS ? next.slice(next.length - MAX_POINTS) : next;
        saveDataPoints(trimmed);
        return trimmed;
      });
    } catch {
      setIsConnected(false);
    }
  }, []);

  // Tunnels ポーリング (15 秒間隔)
  const pollTunnels = useCallback(async () => {
    try {
      const res = await listTunnels();
      setLatestTunnels(res.tunnels);
    } catch {
      // Data Planes ポーリングで接続状態を管理するため、ここではエラーを無視
    }
  }, []);

  // Connections ポーリング (15 秒間隔、Tunnels と同じタイミング)
  const pollConnections = useCallback(async () => {
    try {
      const res = await listConnections();
      setLatestConnections(res.connections);
      latestConnectionCountRef.current = res.connections.length;
    } catch {
      // Data Planes ポーリングで接続状態を管理するため、ここではエラーを無視
    }
  }, []);

  useEffect(() => {
    // 初回即座に実行
    pollDataPlanes();
    pollTunnels();
    pollConnections();

    const dpTimer = setInterval(pollDataPlanes, DP_POLL_INTERVAL);
    const tunnelTimer = setInterval(pollTunnels, TUNNEL_POLL_INTERVAL);
    const connTimer = setInterval(pollConnections, TUNNEL_POLL_INTERVAL);

    return () => {
      clearInterval(dpTimer);
      clearInterval(tunnelTimer);
      clearInterval(connTimer);
    };
  }, [pollDataPlanes, pollTunnels, pollConnections]);

  return { dataPoints, latestDataPlanes, latestTunnels, latestConnections, isConnected };
}
