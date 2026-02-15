// サマリーカード: Data Plane 数（状態別内訳）、アクティブトンネル数、送受信バイト数

import type { DataPlaneSummary } from "../types/api";

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

export default function OverviewCards({ dataPlanes }: Props) {
  const activeCount = dataPlanes.filter((dp) => dp.state === "ACTIVE").length;
  const drainingCount = dataPlanes.filter((dp) => dp.state === "DRAINING").length;
  const otherCount = dataPlanes.length - activeCount - drainingCount;

  const totalTunnels = dataPlanes.reduce((sum, dp) => sum + dp.active_tunnels, 0);
  const totalSent = dataPlanes.reduce((sum, dp) => sum + dp.bytes_sent, 0);
  const totalRecv = dataPlanes.reduce((sum, dp) => sum + dp.bytes_received, 0);

  const cards = [
    {
      label: "Data Planes",
      value: dataPlanes.length.toString(),
      sub: [
        activeCount > 0 && `${activeCount} active`,
        drainingCount > 0 && `${drainingCount} draining`,
        otherCount > 0 && `${otherCount} other`,
      ]
        .filter(Boolean)
        .join(", "),
      color: "border-blue-500",
    },
    {
      label: "Active Tunnels",
      value: totalTunnels.toString(),
      sub: "",
      color: "border-emerald-500",
    },
    {
      label: "Bytes Sent",
      value: formatBytes(totalSent),
      sub: "",
      color: "border-cyan-500",
    },
    {
      label: "Bytes Received",
      value: formatBytes(totalRecv),
      sub: "",
      color: "border-purple-500",
    },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card) => (
        <div
          key={card.label}
          className={`bg-gray-900 rounded p-4 border-l-4 ${card.color}`}
        >
          <div className="text-sm text-gray-400">{card.label}</div>
          <div className="text-2xl font-bold mt-1">{card.value}</div>
          {card.sub && (
            <div className="text-xs text-gray-500 mt-1">{card.sub}</div>
          )}
        </div>
      ))}
    </div>
  );
}
