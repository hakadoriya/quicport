// メインダッシュボード
//
// ┌─────────────────────────────────────────────────┐
// │ quicport Dashboard              [Refresh: 5s ●] │
// ├─────────────────────────────────────────────────┤
// │ [DP数] [トンネル数] [送信] [受信]  ← カード     │
// ├─────────────────────────────────────────────────┤
// │ [Active Tunnels 推移]   [Transfer Rate 推移]    │
// ├─────────────────────────────────────────────────┤
// │ Data Planes テーブル                             │
// ├─────────────────────────────────────────────────┤
// │ Tunnels テーブル                                 │
// └─────────────────────────────────────────────────┘

import { useDataAccumulator } from "../hooks/useDataAccumulator";
import OverviewCards from "./OverviewCards";
import MetricsChart from "./MetricsChart";
import DataPlaneTable from "./DataPlaneTable";
import TunnelTable from "./TunnelTable";

export default function Dashboard() {
  const { dataPoints, latestDataPlanes, latestTunnels, isConnected } = useDataAccumulator();

  return (
    <div className="min-h-screen p-6 max-w-7xl mx-auto space-y-6">
      {/* ヘッダー */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold tracking-tight">quicport Dashboard</h1>
        <div className="flex items-center gap-2 text-sm text-gray-400">
          <span>Refresh: 5s</span>
          <span className={`inline-block w-2 h-2 rounded-full ${isConnected ? "bg-emerald-500" : "bg-red-500"}`} />
        </div>
      </div>

      {/* サマリーカード */}
      <OverviewCards dataPlanes={latestDataPlanes} />

      {/* 時系列グラフ */}
      <MetricsChart dataPoints={dataPoints} />

      {/* Data Planes テーブル */}
      <DataPlaneTable dataPlanes={latestDataPlanes} />

      {/* Tunnels テーブル */}
      <TunnelTable tunnels={latestTunnels} />
    </div>
  );
}
