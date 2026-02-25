import { MAX_TRACKED_JTI } from "./constants";

const consumedJtiSet = new Set<string>();
const consumedJtiQueue: string[] = [];

export function consumeJti(jti: string): boolean {
  if (consumedJtiSet.has(jti)) {
    return false;
  }

  consumedJtiSet.add(jti);
  consumedJtiQueue.push(jti);

  if (consumedJtiQueue.length > MAX_TRACKED_JTI) {
    const evicted = consumedJtiQueue.shift();
    if (evicted) {
      consumedJtiSet.delete(evicted);
    }
  }

  return true;
}

export function resetJtiReplayCache(): void {
  consumedJtiSet.clear();
  consumedJtiQueue.length = 0;
}
