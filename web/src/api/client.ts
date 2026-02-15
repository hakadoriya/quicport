// API クライアント (fetch wrapper)
//
// 同一オリジンの Admin API (POST /api/v1/admin/*) を呼び出す。
// すべてのエンドポイントは RPC スタイル (POST + JSON body) で統一されている。

import type { ListConnectionsResponse, ListDataPlanesResponse, ListTunnelsResponse } from "../types/api";

async function rpc<T>(path: string, body: object = {}): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export function listDataPlanes(): Promise<ListDataPlanesResponse> {
  return rpc<ListDataPlanesResponse>("/api/v1/admin/ListDataPlanes");
}

export function listTunnels(): Promise<ListTunnelsResponse> {
  return rpc<ListTunnelsResponse>("/api/v1/admin/ListTunnels");
}

export function listConnections(): Promise<ListConnectionsResponse> {
  return rpc<ListConnectionsResponse>("/api/v1/admin/ListConnections");
}
