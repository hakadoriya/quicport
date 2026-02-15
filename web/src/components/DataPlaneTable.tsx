// Data Plane 一覧テーブル
//
// カラム: DP ID, State, Active Tunnels, Bytes Sent, Bytes Received
// 状態に応じたバッジ表示 (ACTIVE=緑, DRAINING=黄, etc.)

import type { DataPlaneSummary, DataPlaneState } from "../types/api";

interface Props {
  dataPlanes: DataPlaneSummary[];
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const val = bytes / Math.pow(1024, i);
  return `${val.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

const stateBadge: Record<DataPlaneState, string> = {
  STARTING: "bg-gray-700 text-gray-300",
  ACTIVE: "bg-emerald-900 text-emerald-300",
  DRAINING: "bg-yellow-900 text-yellow-300",
  TERMINATED: "bg-red-900 text-red-300",
};

export default function DataPlaneTable({ dataPlanes }: Props) {
  return (
    <div className="bg-gray-900 rounded overflow-hidden">
      <div className="px-4 py-3 border-b border-gray-800">
        <h3 className="text-sm font-medium text-gray-400">Data Planes</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-gray-500 border-b border-gray-800">
              <th className="px-4 py-2 font-medium">DP ID</th>
              <th className="px-4 py-2 font-medium">PID</th>
              <th className="px-4 py-2 font-medium">State</th>
              <th className="px-4 py-2 font-medium text-right">Active Tunnels</th>
              <th className="px-4 py-2 font-medium text-right">Bytes Sent</th>
              <th className="px-4 py-2 font-medium text-right">Bytes Received</th>
            </tr>
          </thead>
          <tbody>
            {dataPlanes.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-gray-600">
                  No data planes
                </td>
              </tr>
            ) : (
              dataPlanes.map((dp) => (
                <tr key={dp.dp_id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="px-4 py-2 font-mono">{dp.dp_id}</td>
                  <td className="px-4 py-2 font-mono text-gray-400">{dp.pid}</td>
                  <td className="px-4 py-2">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${stateBadge[dp.state]}`}>
                      {dp.state}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-right font-mono">{dp.active_tunnels}</td>
                  <td className="px-4 py-2 text-right font-mono">{formatBytes(dp.bytes_sent)}</td>
                  <td className="px-4 py-2 text-right font-mono">{formatBytes(dp.bytes_received)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
