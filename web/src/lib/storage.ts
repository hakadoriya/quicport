// localStorage ユーティリティ
//
// ダッシュボードの時系列データをブラウザに永続化する。
// - DataPoint 配列: TTL 2 時間
// - prevPoint (転送速度算出用): TTL 60 秒
// - localStorage が利用不可能な環境ではすべての操作を安全にスキップ
// - すべての read/write を try-catch で保護

import type { DataPoint } from "../hooks/useDataAccumulator";

const KEY_DATA_POINTS = "quicport:dashboard:dataPoints";
const KEY_PREV_POINT = "quicport:dashboard:prevPoint";

// DataPoint の TTL: 2 時間 (ミリ秒)
const DATA_POINTS_TTL_MS = 2 * 60 * 60 * 1000;

// prevPoint の TTL: 60 秒 (ミリ秒)
// ポーリング間隔 (5 秒) を大きく超えた古い prevPoint から転送速度を算出すると不正確になるため短めに設定
const PREV_POINT_TTL_MS = 60 * 1000;

type PrevPoint = { bytesSent: number; bytesReceived: number; timestamp: number };

function isLocalStorageAvailable(): boolean {
  try {
    const key = "__ls_test__";
    localStorage.setItem(key, "1");
    localStorage.removeItem(key);
    return true;
  } catch {
    return false;
  }
}

const storageAvailable = isLocalStorageAvailable();

// --- DataPoints ---

export function saveDataPoints(points: DataPoint[]): void {
  if (!storageAvailable) return;
  try {
    localStorage.setItem(KEY_DATA_POINTS, JSON.stringify(points));
  } catch {
    // QuotaExceededError 等 — 保存失敗は無視して動作を継続
  }
}

export function loadDataPoints(): DataPoint[] {
  if (!storageAvailable) return [];
  try {
    const raw = localStorage.getItem(KEY_DATA_POINTS);
    if (!raw) return [];
    const points: DataPoint[] = JSON.parse(raw);
    // TTL: 2 時間以内のポイントのみ復元
    const cutoff = Date.now() - DATA_POINTS_TTL_MS;
    return points.filter((p) => p.timestamp >= cutoff);
  } catch {
    return [];
  }
}

// --- PrevPoint (転送速度算出用) ---

export function savePrevPoint(prev: PrevPoint): void {
  if (!storageAvailable) return;
  try {
    localStorage.setItem(KEY_PREV_POINT, JSON.stringify(prev));
  } catch {
    // 保存失敗は無視
  }
}

export function loadPrevPoint(): PrevPoint | null {
  if (!storageAvailable) return null;
  try {
    const raw = localStorage.getItem(KEY_PREV_POINT);
    if (!raw) return null;
    const prev: PrevPoint = JSON.parse(raw);
    // TTL: 60 秒以内のみ復元（古い値から速度を計算すると不正確になるため）
    if (Date.now() - prev.timestamp > PREV_POINT_TTL_MS) return null;
    return prev;
  } catch {
    return null;
  }
}
