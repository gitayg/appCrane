/** The read-only guaranteed-memory note for a max of `maxMb` (docker --memory-reservation, half the max). */
export function guaranteedHint(maxMb: number): string {
  return `Guaranteed: ${Math.floor(Math.max(0, maxMb) / 2)} MB (half the max). The app can use up to the max when the server has memory free.`
}
