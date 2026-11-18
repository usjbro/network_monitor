// KAN-129 Task 4: polls POST /api/tcp-samples for one flow while the TCP
// graphs are open. One request in flight; once per second from nextIndex;
// a `more: true` (or stale) reply is followed at once, at most 4 times per
// tick, so a reader that fell behind catches up without a request storm.
import { mapTcpSamplesReply } from './agent-mapping';
import { accumulate, emptyState, requestFor, type TcpGraphState, type TcpSamplesQuery } from './tcp-graphs';
import type { TcpSamplesPage } from './types';

export const POLL_INTERVAL_MS = 1000;
export const MAX_FOLLOW_UPS = 4;

/** A mapped page, or the HTTP status of a refusal (0: network failure, 502: malformed reply). */
export type FetchResult = { ok: true; page: TcpSamplesPage } | { ok: false; status: number };
export type TcpSamplesFetch = (query: TcpSamplesQuery, signal: AbortSignal) => Promise<FetchResult>;
type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export async function fetchTcpSamples(query: TcpSamplesQuery, signal: AbortSignal, fetchImpl: FetchLike = fetch): Promise<FetchResult> {
  let res: Response;
  try {
    res = await fetchImpl('/api/tcp-samples', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(query),
      signal,
    });
  } catch {
    return { ok: false, status: 0 };
  }
  if (!res.ok) return { ok: false, status: res.status };
  try {
    return { ok: true, page: mapTcpSamplesReply(await res.json()) };
  } catch {
    return { ok: false, status: 502 };
  }
}

export interface PollHandlers {
  onState: (state: TcpGraphState) => void;
  /** The status of the last failed request, or null once one succeeds. */
  onError: (status: number | null) => void;
}

export class TcpSamplesPoller {
  private state: TcpGraphState;
  private running = false;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private controller: AbortController | null = null;
  private followUps = 0;

  constructor(connectionId: string, private readonly fetchPage: TcpSamplesFetch, private readonly handlers: PollHandlers) {
    this.state = emptyState(connectionId);
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.tick();
  }

  /** Stops polling and abandons the request in flight; the samples are kept for a later start. */
  stop(): void {
    this.running = false;
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    this.controller?.abort();
    this.controller = null;
  }

  private tick(): void {
    this.timer = null;
    this.followUps = 0;
    void this.request();
  }

  private async request(): Promise<void> {
    const controller = new AbortController();
    this.controller = controller;
    const result = await this.fetchPage(requestFor(this.state), controller.signal);
    // Stopped, or superseded by a stop and start, meanwhile.
    if (this.controller !== controller || !this.running) return;
    this.controller = null;
    if (!result.ok) {
      this.handlers.onError(result.status);
      return this.schedule();
    }
    const { page } = result;
    this.state = accumulate(this.state, page);
    this.handlers.onError(null);
    this.handlers.onState(this.state);
    // The agent no longer has the flow: nothing more will arrive.
    if (!page.found) {
      this.running = false;
      return;
    }
    if ((page.stale || page.more) && this.followUps < MAX_FOLLOW_UPS) {
      this.followUps++;
      return void this.request();
    }
    this.schedule();
  }

  private schedule(): void {
    this.timer = setTimeout(() => this.tick(), POLL_INTERVAL_MS);
  }
}
