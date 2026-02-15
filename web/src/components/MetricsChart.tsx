// 時系列グラフ (Recharts) — 2x2 グリッド
//
// - Data Planes 推移 (LineChart, 青)
// - Transfer Rate (AreaChart, 水+紫)
// - Active Tunnels 推移 (LineChart, 緑)
// - Active Connections 推移 (LineChart, 橙)

import {
  AreaChart,
  Area,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import type { DataPoint } from "../hooks/useDataAccumulator";

interface Props {
  dataPoints: DataPoint[];
}

function formatTime(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatRate(value: number): string {
  if (value === 0) return "0 B/s";
  const units = ["B/s", "KB/s", "MB/s", "GB/s"];
  const i = Math.floor(Math.log(value) / Math.log(1024));
  const idx = Math.min(i, units.length - 1);
  const val = value / Math.pow(1024, idx);
  return `${val.toFixed(1)} ${units[idx]}`;
}

const chartMargin = { top: 5, right: 20, left: 10, bottom: 5 };

export default function MetricsChart({ dataPoints }: Props) {
  if (dataPoints.length < 2) {
    return (
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="bg-gray-900 rounded-lg p-4 h-64 flex items-center justify-center text-gray-500">
            Collecting data...
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {/* Data Planes 推移 */}
      <div className="bg-gray-900 rounded-lg p-4">
        <h3 className="text-sm font-medium text-gray-400 mb-2">Data Planes</h3>
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={dataPoints} margin={chartMargin}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis dataKey="timestamp" tickFormatter={formatTime} stroke="#6B7280" fontSize={11} />
            <YAxis stroke="#6B7280" fontSize={11} allowDecimals={false} />
            <Tooltip
              contentStyle={{ backgroundColor: "#1F2937", border: "1px solid #374151", borderRadius: "8px" }}
              labelFormatter={formatTime}
            />
            <Line
              type="monotone"
              dataKey="dataPlaneCount"
              name="Data Planes"
              stroke="#3B82F6"
              strokeWidth={2}
              dot={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Transfer Rate 推移 */}
      <div className="bg-gray-900 rounded-lg p-4">
        <h3 className="text-sm font-medium text-gray-400 mb-2">Transfer Rate</h3>
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={dataPoints} margin={chartMargin}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis dataKey="timestamp" tickFormatter={formatTime} stroke="#6B7280" fontSize={11} />
            <YAxis stroke="#6B7280" fontSize={11} tickFormatter={formatRate} />
            <Tooltip
              contentStyle={{ backgroundColor: "#1F2937", border: "1px solid #374151", borderRadius: "8px" }}
              labelFormatter={formatTime}
              formatter={(value: number) => formatRate(value)}
            />
            <Legend />
            <Area
              type="monotone"
              dataKey="sendRate"
              name="Send"
              stroke="#06B6D4"
              fill="#06B6D4"
              fillOpacity={0.15}
              strokeWidth={2}
            />
            <Area
              type="monotone"
              dataKey="recvRate"
              name="Receive"
              stroke="#A855F7"
              fill="#A855F7"
              fillOpacity={0.15}
              strokeWidth={2}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Active Tunnels 推移 */}
      <div className="bg-gray-900 rounded-lg p-4">
        <h3 className="text-sm font-medium text-gray-400 mb-2">Active Tunnels</h3>
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={dataPoints} margin={chartMargin}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis dataKey="timestamp" tickFormatter={formatTime} stroke="#6B7280" fontSize={11} />
            <YAxis stroke="#6B7280" fontSize={11} allowDecimals={false} />
            <Tooltip
              contentStyle={{ backgroundColor: "#1F2937", border: "1px solid #374151", borderRadius: "8px" }}
              labelFormatter={formatTime}
            />
            <Line
              type="monotone"
              dataKey="activeTunnels"
              name="Active Tunnels"
              stroke="#10B981"
              strokeWidth={2}
              dot={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Active Connections 推移 */}
      <div className="bg-gray-900 rounded-lg p-4">
        <h3 className="text-sm font-medium text-gray-400 mb-2">Active Connections</h3>
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={dataPoints} margin={chartMargin}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis dataKey="timestamp" tickFormatter={formatTime} stroke="#6B7280" fontSize={11} />
            <YAxis stroke="#6B7280" fontSize={11} allowDecimals={false} />
            <Tooltip
              contentStyle={{ backgroundColor: "#1F2937", border: "1px solid #374151", borderRadius: "8px" }}
              labelFormatter={formatTime}
            />
            <Line
              type="monotone"
              dataKey="activeConnections"
              name="Active Connections"
              stroke="#F59E0B"
              strokeWidth={2}
              dot={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
