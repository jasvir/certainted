import assert from "node:assert/strict";
import test from "node:test";
import {
  REPEAT_COOLDOWN_MS,
  compactNoticeState,
  dueNoticeCandidates,
  markNotified,
  mergeNoticeStates,
  parseNoticeState,
} from "./notification_tracker.ts";

const watch = { key: "watch:ca:example.com", probeId: 12 };

test("repeat cooldown is thirty minutes", () => {
  assert.equal(REPEAT_COOLDOWN_MS, 30 * 60 * 1000);
});

test("a new group is due immediately, then the same probe is never repeated", () => {
  const empty = parseNoticeState(null);
  assert.deepEqual(dueNoticeCandidates([watch], empty, 1), [watch]);
  const notified = markNotified(empty, [watch], 1);
  assert.deepEqual(dueNoticeCandidates([watch], notified, 1 + REPEAT_COOLDOWN_MS), []);
  assert.equal(Object.hasOwn(empty, watch.key), false, "markNotified must not mutate existing state");
});

test("a later probe stays pending until the cooldown expires", () => {
  const first = markNotified(parseNoticeState(null), [watch], 1_000);
  const later = { ...watch, probeId: 13 };
  assert.deepEqual(dueNoticeCandidates([later], first, 1_000 + REPEAT_COOLDOWN_MS - 1), []);
  assert.equal(first[watch.key].probeId, 12, "a suppressed probe must not consume the pending notice");
  assert.deepEqual(dueNoticeCandidates([later], first, 1_000 + REPEAT_COOLDOWN_MS), [later]);
  const second = markNotified(first, [later], 1_000 + REPEAT_COOLDOWN_MS);
  assert.equal(second[watch.key].probeId, 13);
  assert.deepEqual(dueNoticeCandidates([later], second, 1_000 + REPEAT_COOLDOWN_MS * 2), []);
});

test("an older probe resurfacing after pruning never triggers another notice", () => {
  const state = markNotified(parseNoticeState(null), [watch], 100);
  const older = { ...watch, probeId: 11 };
  assert.deepEqual(dueNoticeCandidates([older], state, 100 + REPEAT_COOLDOWN_MS * 2), []);
});

test("different groups alert independently and duplicate candidates choose the latest probe", () => {
  const another = { key: "crl:ca:example.com", probeId: 44 };
  const state = markNotified(parseNoticeState(null), [watch], 100);
  assert.deepEqual(dueNoticeCandidates([watch, another, { ...another, probeId: 43 }], state, 101), [another]);
  assert.equal(markNotified(state, [another, { ...another, probeId: 43 }], 101)[another.key].probeId, 44);
});

test("receipts survive reload without causing a duplicate, while pending probes stay pending", () => {
  const state = markNotified(parseNoticeState(null), [watch], 100);
  const restored = parseNoticeState(JSON.stringify(state));
  assert.deepEqual(dueNoticeCandidates([watch], restored, 200), []);
  const later = { ...watch, probeId: 99 };
  assert.deepEqual(dueNoticeCandidates([later], restored, 200), []);
  assert.deepEqual(dueNoticeCandidates([later], restored, 100 + REPEAT_COOLDOWN_MS), [later]);
});

test("malformed browser storage is ignored and special keys cannot change the prototype", () => {
  assert.equal(Object.keys(parseNoticeState("bad json")).length, 0);
  assert.equal(Object.keys(parseNoticeState("[]")).length, 0);
  const state = parseNoticeState(JSON.stringify({
    good: { probeId: 1, notifiedAt: 0 },
    zero: { probeId: 0, notifiedAt: 0 },
    fraction: { probeId: 1.5, notifiedAt: 0 },
    badTime: { probeId: 1, notifiedAt: -1 },
    missing: {},
    __proto__: { probeId: 2, notifiedAt: 0 },
  }));
  assert.deepEqual(Object.keys(state), ["good"]);
  const special = parseNoticeState('{"__proto__":{"probeId":2,"notifiedAt":0}}');
  assert.equal(Object.getPrototypeOf(special), null);
  assert.equal(special.__proto__.probeId, 2);
});

test("compaction retains the newest receipts and honors the entry bound", () => {
  const state = parseNoticeState(JSON.stringify({
    old: { probeId: 1, notifiedAt: 100 },
    recent: { probeId: 2, notifiedAt: 300 },
    middle: { probeId: 3, notifiedAt: 200 },
  }));
  const compacted = compactNoticeState(state, 2);
  assert.deepEqual(Object.keys(compacted), ["recent", "middle"]);
  assert.equal(Object.keys(state).length, 3);
  assert.equal(Object.keys(compactNoticeState(state, 0)).length, 0);
});

test("the dashboard receipt bound retains 10,000 CA and 1,000 CRL groups", () => {
  let state = parseNoticeState(null);
  for (let i = 0; i < 10_000; i++) state[`ca:${i}`] = { probeId: i + 1, notifiedAt: i };
  for (let i = 0; i < 1_000; i++) state[`crl:${i}`] = { probeId: i + 10_001, notifiedAt: i + 10_000 };
  state = compactNoticeState(state, 12_000);
  assert.equal(Object.keys(state).length, 11_000);
  assert.deepEqual(state["ca:0"], { probeId: 1, notifiedAt: 0 });
  assert.deepEqual(state["ca:9999"], { probeId: 10_000, notifiedAt: 9_999 });
  assert.deepEqual(state["crl:0"], { probeId: 10_001, notifiedAt: 10_000 });
  assert.deepEqual(state["crl:999"], { probeId: 11_000, notifiedAt: 10_999 });
});

test("merging tab receipts keeps the most recent notification and all distinct groups", () => {
  const first = parseNoticeState(JSON.stringify({
    shared: { probeId: 8, notifiedAt: 200 },
    firstOnly: { probeId: 1, notifiedAt: 100 },
    tied: { probeId: 4, notifiedAt: 500 },
  }));
  const second = parseNoticeState(JSON.stringify({
    shared: { probeId: 7, notifiedAt: 300 },
    secondOnly: { probeId: 2, notifiedAt: 120 },
    tied: { probeId: 5, notifiedAt: 500 },
  }));
  const merged = mergeNoticeStates(first, second);
  assert.deepEqual(merged.shared, { probeId: 7, notifiedAt: 300 });
  assert.deepEqual(merged.firstOnly, { probeId: 1, notifiedAt: 100 });
  assert.deepEqual(merged.secondOnly, { probeId: 2, notifiedAt: 120 });
  assert.deepEqual(merged.tied, { probeId: 5, notifiedAt: 500 });
  assert.equal(first.shared.notifiedAt, 200, "the merge must not mutate either input");
  assert.equal(Object.getPrototypeOf(merged), null);
});
