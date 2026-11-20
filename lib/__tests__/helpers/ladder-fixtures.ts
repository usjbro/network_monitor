// KAN-130: indexed samples and TCP graph states for the flow ladder's model
// and view tests.
import type { IndexedSample, TcpGraphState } from '../../tcp-graphs';
import { TCP_SAMPLE_FLAG as F, TCP_SAMPLE_MARK as M, type TcpSample } from '../../types';

export const LADDER_ID = 'Tcp-192.168.1.10:51000-93.184.216.34:443';
export const BASE = { outbound: 1000, inbound: 5000 };

/** One retained segment at ring index `index`; an ACK unless `over` says otherwise. */
export function s(index: number, tUs: number, outbound: boolean, over: Partial<TcpSample> = {}): IndexedSample {
  const mark = (outbound ? M.OUTBOUND : 0) | (over.mark ?? 0);
  return { index, tUs, seq: 0, ack: 0, win: 1000, len: 0, flags: F.ACK, rttUs: 0, ...over, mark, outbound };
}

/** A found, current state holding `samples`, sequence bases `BASE`, no head or labels unless given. */
export function state(samples: IndexedSample[], over: Partial<TcpGraphState> = {}): TcpGraphState {
  return {
    connectionId: LADDER_ID, generation: 'g:1', samples, nextIndex: (samples.at(-1)?.index ?? -1) + 1,
    meta: { handshakeSeen: true, windowScale: null, seqBase: BASE, relativeTo: 'isn' },
    found: true, head: [], labels: new Map(), ...over,
  };
}
