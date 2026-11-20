// KAN-130 flow ladder (spec docs/superpowers/specs/2026-11-20-flow-sequence-diagram-design.md
// D3 rows and collapse, D4 packet-view match key; plan Task 3). Pure: no
// React, no I/O. Input is the TCP graphs state (lib/tcp-graphs.ts), which
// holds every retained segment of one flow (KAN-129's ring, not the sampled
// packet events), plus the pinned head and labels.
import type { IndexedSample, TcpGraphState } from './tcp-graphs';
import {
  TCP_SAMPLE_FLAG as F,
  TCP_SAMPLE_LABEL_KINDS,
  TCP_SAMPLE_MARK as M,
  type NetworkConnection,
  type PacketFrame,
  type TcpSample,
  type TcpSampleLabel,
} from './types';

/** A run of bulk segments at most this long is drawn arrow by arrow (spec D3.3). */
export const RUN_DRAW_MAX = 4;
/** Rows beyond this keep the first and last half and elide the middle (spec D3.4). */
export const MAX_ROWS = 200;

export interface LadderLabel {
  kind: string;
  text: string;
}

export interface RunSide {
  /** Segments carrying payload. */
  data: number;
  /** Payload bytes, summed over retained segments only. */
  bytes: number;
  /** Segments without payload. */
  acks: number;
}

export type LadderRow =
  | { kind: 'arrow'; index: number; sample: IndexedSample; text: string; label?: LadderLabel; interesting: boolean }
  | { kind: 'run'; firstIndex: number; lastIndex: number; segments: number; spanUs: number; out: RunSide; in: RunSide }
  | { kind: 'gap'; afterIndex: number; missing: number }
  | { kind: 'elided'; rows: number; segments: number };

const KNOWN_KINDS: ReadonlySet<string> = new Set(TCP_SAMPLE_LABEL_KINDS);

const FLAG_NAMES: [number, string][] = [
  [F.SYN, 'SYN'],
  [F.FIN, 'FIN'],
  [F.RST, 'RST'],
  [F.PSH, 'PSH'],
  [F.ACK, 'ACK'],
];

/** `SYN,ACK`, `PSH,ACK len=517 · ClientHello (SNI: example.com)`, `ACK · retransmission`. */
export function arrowText(sample: TcpSample, label?: LadderLabel): string {
  const flags = FLAG_NAMES.filter(([bit]) => (sample.flags & bit) !== 0).map(([, name]) => name);
  let text = flags.length > 0 ? flags.join(',') : '(no flags)';
  if (sample.len > 0) text += ` len=${sample.len}`;
  const notes: string[] = [];
  if (label) notes.push(KNOWN_KINDS.has(label.kind) ? label.text : 'unknown label');
  if ((sample.mark & M.RETRANSMIT) !== 0) notes.push('retransmission');
  if ((sample.mark & M.ZERO_WINDOW) !== 0) notes.push('zero window');
  return [text, ...notes].join(' · ');
}

function toLabel(label: TcpSampleLabel | undefined): LadderLabel | undefined {
  return label && { kind: label.kind, text: label.text };
}

/** Spec D3: rows for the retained segments (head, then rolling samples), in index order. */
export function buildLadder(state: TcpGraphState): LadderRow[] {
  const segments = state.head.length > 0 ? [...state.head, ...state.samples] : state.samples;
  const rows: LadderRow[] = [];
  const seenPayload = { out: false, in: false };
  let run: IndexedSample[] = [];

  const arrow = (sample: IndexedSample, interesting: boolean) => {
    const label = toLabel(state.labels.get(sample.index));
    rows.push({ kind: 'arrow', index: sample.index, sample, text: arrowText(sample, label), label, interesting });
  };
  const flush = () => {
    if (run.length <= RUN_DRAW_MAX) {
      for (const sample of run) arrow(sample, false);
    } else {
      const side = (): RunSide => ({ data: 0, bytes: 0, acks: 0 });
      const sides = { out: side(), in: side() };
      for (const sample of run) {
        const s = sample.outbound ? sides.out : sides.in;
        if (sample.len > 0) {
          s.data += 1;
          s.bytes += sample.len;
        } else {
          s.acks += 1;
        }
      }
      const first = run[0];
      const last = run[run.length - 1];
      rows.push({
        kind: 'run', firstIndex: first.index, lastIndex: last.index, segments: run.length,
        spanUs: last.tUs - first.tUs, out: sides.out, in: sides.in,
      });
    }
    run = [];
  };

  let previous: IndexedSample | undefined;
  for (const sample of segments) {
    if (previous && sample.index > previous.index + 1) {
      flush();
      rows.push({ kind: 'gap', afterIndex: previous.index, missing: sample.index - previous.index - 1 });
    }
    previous = sample;

    const side = sample.outbound ? 'out' : 'in';
    const firstPayload = sample.len > 0 && !seenPayload[side];
    if (sample.len > 0) seenPayload[side] = true;
    const interesting =
      (sample.flags & (F.SYN | F.FIN | F.RST)) !== 0 ||
      (sample.mark & (M.RETRANSMIT | M.ZERO_WINDOW)) !== 0 ||
      state.labels.has(sample.index) ||
      firstPayload;
    if (interesting) {
      flush();
      arrow(sample, true);
    } else {
      run.push(sample);
    }
  }
  flush();

  if (rows.length <= MAX_ROWS) return rows;
  const keep = MAX_ROWS / 2;
  const hidden = rows.slice(keep, rows.length - keep);
  const hiddenSegments = hidden.reduce((n, r) => n + (r.kind === 'arrow' ? 1 : r.kind === 'run' ? r.segments : 0), 0);
  return [...rows.slice(0, keep), { kind: 'elided', rows: hidden.length, segments: hiddenSegments }, ...rows.slice(rows.length - keep)];
}

type SeqBase = { outbound: number; inbound: number };
const KEY_FLAGS = F.SYN | F.ACK | F.FIN | F.RST; // PSH is not in a packet event's fields

function key(outbound: boolean, seq: number, ack: number | null, flags: number, ms: number): string {
  return `${outbound ? 'o' : 'i'}|${seq}|${ack ?? '-'}|${flags & KEY_FLAGS}|${ms}`;
}

/** Spec D4: the key of a sample, with raw (absolute) sequence and ACK numbers. */
export function sampleKey(sample: TcpSample, seqBase: SeqBase): string {
  const own = sample.outbound ? seqBase.outbound : seqBase.inbound;
  const other = sample.outbound ? seqBase.inbound : seqBase.outbound;
  const ack = (sample.flags & F.ACK) !== 0 ? (other + sample.ack) >>> 0 : null;
  return key(sample.outbound, (own + sample.seq) >>> 0, ack, sample.flags, Math.floor(sample.tUs / 1000));
}

/** `addr:port` as packet events write it (no brackets, even for IPv6), canonicalised. */
function endpoint(text: string): string | null {
  const colon = text.lastIndexOf(':');
  if (colon <= 0) return null;
  const port = Number(text.slice(colon + 1));
  if (!Number.isInteger(port)) return null;
  return `${canonicalAddr(text.slice(0, colon))}|${port}`;
}

function canonicalAddr(addr: string): string {
  return addr.replace(/^\[(.*)\]$/, '$1').toLowerCase();
}

function fieldValue(frame: PacketFrame, path: string): boolean | number | string | undefined {
  return frame.fields.find((f) => f.path === path)?.value;
}

/** Spec D4: the same key for a buffered packet event of `conn`, or null when it is not one of this flow's TCP segments. */
export function packetKey(frame: PacketFrame, conn: NetworkConnection): string | null {
  const src = endpoint(frame.src);
  const dst = endpoint(frame.dst);
  const local = `${canonicalAddr(conn.localAddr)}|${conn.localPort}`;
  const remote = `${canonicalAddr(conn.remoteAddr)}|${conn.remotePort}`;
  let outbound: boolean;
  if (src === local && dst === remote) outbound = true;
  else if (src === remote && dst === local) outbound = false;
  else return null;

  const seq = fieldValue(frame, 'tcp.seq');
  const ackNumber = fieldValue(frame, 'tcp.ack_number');
  const bit = (name: string, flag: number) => {
    const v = fieldValue(frame, `tcp.flags.${name}`);
    return typeof v === 'boolean' ? (v ? flag : 0) : undefined;
  };
  const bits = [bit('syn', F.SYN), bit('ack', F.ACK), bit('fin', F.FIN), bit('rst', F.RST)];
  if (typeof seq !== 'number' || typeof ackNumber !== 'number' || bits.some((b) => b === undefined)) return null;
  const flags = bits.reduce<number>((n, b) => n | (b ?? 0), 0);
  const ms = Number(frame.timestamp);
  if (!Number.isSafeInteger(ms)) return null;
  return key(outbound, seq >>> 0, (flags & F.ACK) !== 0 ? ackNumber >>> 0 : null, flags, ms);
}

/**
 * Spec D4: sample index → packet id for every retained sample whose key is
 * unique among the retained samples and matches exactly one buffered frame.
 * Ambiguity on either side links nothing.
 */
export function linkSamples(state: TcpGraphState, frames: PacketFrame[], conn: NetworkConnection): Map<number, string> {
  const links = new Map<number, string>();
  const seqBase = state.meta?.seqBase;
  if (!seqBase) return links;

  const framesByKey = new Map<string, string | null>();
  for (const frame of frames) {
    const k = packetKey(frame, conn);
    if (k !== null) framesByKey.set(k, framesByKey.has(k) ? null : frame.id);
  }
  const samplesByKey = new Map<string, number | null>();
  for (const sample of [...state.head, ...state.samples]) {
    const k = sampleKey(sample, seqBase);
    samplesByKey.set(k, samplesByKey.has(k) ? null : sample.index);
  }
  for (const [k, index] of samplesByKey) {
    const id = framesByKey.get(k);
    if (index !== null && id) links.set(index, id);
  }
  return links;
}
