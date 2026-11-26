// lib/enrichment/request-queue.ts

export function shuffle<T>(items: T[], random: () => number = Math.random): T[] {
  const result = [...items];
  for (let i = result.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

export interface RequestQueueOptions {
  minDelayMs?: number;
  maxDelayMs?: number;
  random?: () => number;
}

interface QueuedTask {
  run: () => Promise<unknown>;
  cancelled?: () => boolean;
  resolve: (v: unknown) => void;
  reject: (e: unknown) => void;
}

export class RequestQueue {
  private minDelayMs: number;
  private maxDelayMs: number;
  private random: () => number;
  private queue: QueuedTask[] = [];
  private running = false;
  // Set after a task that may have sent; the next task that will send waits
  // the spacing delay first. A cancelled task neither waits nor uses it up.
  private delayOwed = false;

  constructor(opts: RequestQueueOptions = {}) {
    this.minDelayMs = opts.minDelayMs ?? 3000;
    this.maxDelayMs = opts.maxDelayMs ?? 10000;
    this.random = opts.random ?? Math.random;
  }

  get pending(): number {
    return this.queue.length;
  }

  // A task that is `cancelled` when its turn comes is run at once, without a
  // spacing delay: it must send nothing, so it need not wait (KAN-317).
  enqueue<T>(fn: () => Promise<T>, cancelled?: () => boolean): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.queue.push({ run: fn, cancelled, resolve: resolve as (v: unknown) => void, reject });
      // drain routes task failures to each enqueue promise.
      void this.drain();
    });
  }

  private async drain(): Promise<void> {
    if (this.running) return;
    this.running = true;
    while (this.queue.length > 0) {
      if (this.delayOwed && !this.queue[0].cancelled?.()) {
        const delay = this.minDelayMs + this.random() * (this.maxDelayMs - this.minDelayMs);
        await new Promise((r) => setTimeout(r, delay));
        this.delayOwed = false;
      }
      const task = this.queue.shift()!;
      if (!task.cancelled?.()) this.delayOwed = true;
      try {
        task.resolve(await task.run());
      } catch (err) {
        task.reject(err);
      }
    }
    this.running = false;
  }
}
