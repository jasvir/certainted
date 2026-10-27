// Browser-local notification receipts. A receipt records the probe we last
// notified about, not the probe we last saw. That keeps newer evidence pending
// until the repeat cooldown expires.
export const REPEAT_COOLDOWN_MS = 30 * 60 * 1000;

export type NoticeCandidate = { key: string; probeId: number };
export type NoticeReceipt = { probeId: number; notifiedAt: number };
export type NoticeState = Record<string, NoticeReceipt>;

function emptyState(): NoticeState {
  return Object.create(null) as NoticeState;
}

function validProbeId(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function validTime(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function latestCandidates(candidates: readonly NoticeCandidate[]): NoticeCandidate[] {
  const latest = new Map<string, NoticeCandidate>();
  for (const candidate of candidates) {
    if (typeof candidate?.key !== "string" || !candidate.key || !validProbeId(candidate.probeId)) continue;
    const previous = latest.get(candidate.key);
    if (!previous || candidate.probeId > previous.probeId) latest.set(candidate.key, candidate);
  }
  return [...latest.values()];
}

export function dueNoticeCandidates(
  candidates: readonly NoticeCandidate[],
  state: NoticeState,
  now: number,
  cooldownMs = REPEAT_COOLDOWN_MS,
): NoticeCandidate[] {
  if (!validTime(now)) return [];
  const cooldown = Number.isFinite(cooldownMs) ? Math.max(0, cooldownMs) : REPEAT_COOLDOWN_MS;
  return latestCandidates(candidates).filter((candidate) => {
    const receipt = Object.prototype.hasOwnProperty.call(state, candidate.key) ? state[candidate.key] : undefined;
    if (!receipt) return true;
    // A limited or pruned result set may briefly expose an older probe.
    if (candidate.probeId <= receipt.probeId) return false;
    return now - receipt.notifiedAt >= cooldown;
  });
}

export function markNotified(
  state: NoticeState,
  candidates: readonly NoticeCandidate[],
  now: number,
): NoticeState {
  const updated = Object.assign(emptyState(), state);
  if (!validTime(now)) return updated;
  for (const candidate of latestCandidates(candidates)) {
    updated[candidate.key] = { probeId: candidate.probeId, notifiedAt: now };
  }
  return updated;
}

export function parseNoticeState(raw: string | null): NoticeState {
  const state = emptyState();
  if (!raw) return state;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return state;
    for (const [key, value] of Object.entries(parsed)) {
      if (!key || typeof value !== "object" || value === null || Array.isArray(value)) continue;
      const receipt = value as Record<string, unknown>;
      if (validProbeId(receipt.probeId) && validTime(receipt.notifiedAt)) {
        state[key] = { probeId: receipt.probeId, notifiedAt: receipt.notifiedAt };
      }
    }
  } catch { /* Browser storage can contain stale or malformed data. */ }
  return state;
}

// Tabs can read the same localStorage snapshot and write independently. Merge
// their receipts before persisting so one tab does not discard another's notice.
export function mergeNoticeStates(a: NoticeState, b: NoticeState): NoticeState {
  const merged = emptyState();
  for (const source of [a, b]) {
    for (const [key, receipt] of Object.entries(source)) {
      if (!key || !receipt || !validProbeId(receipt.probeId) || !validTime(receipt.notifiedAt)) continue;
      const current = merged[key];
      if (!current || receipt.notifiedAt > current.notifiedAt ||
          (receipt.notifiedAt === current.notifiedAt && receipt.probeId > current.probeId)) {
        merged[key] = { probeId: receipt.probeId, notifiedAt: receipt.notifiedAt };
      }
    }
  }
  return merged;
}

export function compactNoticeState(state: NoticeState, maxEntries: number): NoticeState {
  const compacted = emptyState();
  if (!Number.isSafeInteger(maxEntries) || maxEntries <= 0) return compacted;
  const entries = Object.entries(state)
    .filter(([key, receipt]) => key && receipt && validProbeId(receipt.probeId) && validTime(receipt.notifiedAt))
    .sort(([keyA, a], [keyB, b]) => b.notifiedAt - a.notifiedAt || keyA.localeCompare(keyB));
  for (const [key, receipt] of entries.slice(0, maxEntries)) compacted[key] = receipt;
  return compacted;
}
