/** Retain up to 60 measured ticks, oldest first; values are decimal Mbps. */
export function appendBandwidthSample(history: number[], sample: number): number[] {
  return [...history.slice(-59), sample];
}
