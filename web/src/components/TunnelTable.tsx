// トンネル一覧テーブル
//
// カラム: DP ID, Tunnel ID, Remote Addr, Mode (RPF/LPF), Connections, Bytes

import type { TunnelInfoWithDpId } from "../types/api";

interface Props {
  tunnels: TunnelInfoWithDpId[];
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const val = bytes / Math.pow(1024, i);
  return `${val.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function formatDuration(startedAt: number): string {
  const elapsed = Math.floor(Date.now() / 1000) - startedAt;
  if (elapsed < 60) return `${elapsed}s`;
  if (elapsed < 3600) return `${Math.floor(elapsed / 60)}m ${elapsed % 60}s`;
  const h = Math.floor(elapsed / 3600);
  const m = Math.floor((elapsed % 3600) / 60);
  return `${h}h ${m}m`;
}

export default function TunnelTable({ tunnels }: Props) {
  return (
    <div className="bg-gray-900 rounded overflow-hidden">
      <div className="px-4 py-3 border-b border-gray-800">
        <h3 className="text-sm font-medium text-gray-400">Tunnels</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-gray-500 border-b border-gray-800">
              <th className="px-4 py-2 font-medium">DP ID</th>
              <th className="px-4 py-2 font-medium">Tunnel ID</th>
              <th className="px-4 py-2 font-medium">Remote Addr</th>
              <th className="px-4 py-2 font-medium">Mode</th>
              <th className="px-4 py-2 font-medium">Uptime</th>
              <th className="px-4 py-2 font-medium text-right">Connections</th>
              <th className="px-4 py-2 font-medium text-right">Sent</th>
              <th className="px-4 py-2 font-medium text-right">Received</th>
            </tr>
          </thead>
          <tbody>
            {tunnels.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-gray-600">
                  No tunnels
                </td>
              </tr>
            ) : (
              tunnels.map((t) => (
                <tr
                  key={`${t.dp_id}-${t.tunnel_id}`}
                  className="border-b border-gray-800/50 hover:bg-gray-800/30"
                >
                  <td className="px-4 py-2 font-mono">{t.dp_id}</td>
                  <td className="px-4 py-2 font-mono">{t.tunnel_id}</td>
                  <td className="px-4 py-2 font-mono text-gray-300">{t.remote_addr}</td>
                  <td className="px-4 py-2">
                    <span className="px-2 py-0.5 rounded text-xs font-medium bg-gray-700 text-gray-300">
                      {t.forwarding_mode}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-gray-400">{formatDuration(t.started_at)}</td>
                  <td className="px-4 py-2 text-right font-mono">{t.active_connections}</td>
                  <td className="px-4 py-2 text-right font-mono">{formatBytes(t.bytes_sent)}</td>
                  <td className="px-4 py-2 text-right font-mono">{formatBytes(t.bytes_received)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
