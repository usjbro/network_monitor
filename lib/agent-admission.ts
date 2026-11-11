// KAN-129 Task 2 (spec D5): admission for one reply type's relay route. At
// most `maxInFlight` requests relay-wide and one per key (a connectionId),
// each holding `reservationBytes` from admission until its lease is
// released, which the route does on the HTTP response's finish, close or
// error, never when the agent replies: a reply still unread by a slow
// client is still in this process's memory (Follow Stream plan P1).

export interface Lease {
  /** Idempotent. */
  release(): void;
}

export class Admission {
  private held = new Map<string, symbol>();

  constructor(private readonly opts: { maxInFlight: number; reservationBytes: number }) {}

  /** A lease, or `null` when the relay-wide or per-key limit is reached (429). */
  tryAcquire(key: string): Lease | null {
    if (this.held.size >= this.opts.maxInFlight || this.held.has(key)) return null;
    const token = Symbol(key);
    this.held.set(key, token);
    return {
      release: () => {
        if (this.held.get(key) === token) this.held.delete(key);
      },
    };
  }

  inFlight(): number {
    return this.held.size;
  }

  reservedBytes(): number {
    return this.held.size * this.opts.reservationBytes;
  }
}
