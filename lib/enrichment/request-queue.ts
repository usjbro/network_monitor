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
  resolve: (v: unknown) => void;
  reject: (e: unknown) => void;
}

export class RequestQueue {
  private minDelayMs: number;
  private maxDelayMs: number;
  private random: () => number;
  private queue: QueuedTask[] = [];
  private running = false;
  private hasDispatchedOnce = false;

  constructor(opts: RequestQueueOptions = {}) {
    this.minDelayMs = opts.minDelayMs ?? 3000;
    this.maxDelayMs = opts.maxDelayMs ?? 10000;
    this.random = opts.random ?? Math.random;
  }

  get pending(): number {
    return this.queue.length;
  }

  enqueue<T>(fn: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.queue.push({ run: fn, resolve: resolve as (v: unknown) => void, reject });
      this.drain();
    });
  }

  private async drain(): Promise<void> {
    if (this.running) return;
    this.running = true;
    while (this.queue.length > 0) {
      if (this.hasDispatchedOnce) {
        const delay = this.minDelayMs + this.random() * (this.maxDelayMs - this.minDelayMs);
        await new Promise((r) => setTimeout(r, delay));
      }
      this.hasDispatchedOnce = true;
      const task = this.queue.shift()!;
      try {
        task.resolve(await task.run());
      } catch (err) {
        task.reject(err);
      }
    }
    this.running = false;
  }
}
