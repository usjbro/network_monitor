'use client';

import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  BarChart2,
  Globe,
  Layers,
  Network,
  Radio,
  ShieldAlert,
} from 'lucide-react';
import {
  AgentStatus,
  CaptureConfig,
  CaptureFileStatus,
  CaptureStats,
  DecryptedPayloadSegment,
  Finding,
  OSILayerInfo,
  NetworkConnection,
  NetworkInterface,
  PacketFrame,
  SystemStats,
  TerminalTheme,
  ThemeConfig,
  OSILayerNumber,
  TracerouteHop,
} from '@/lib/types';
import { THEMES } from '@/lib/osi-engine';
import {
  mapAgentStatusEvent,
  mapCaptureConfigErrorEvent,
  mapCaptureConfigEvent,
  mapCaptureFileStatusEvent,
  mapCaptureStatsEvent,
  mapConnectionClosedEvent,
  mapConnectionEvent,
  mapFindingEvent,
  mapInterfaceErrorEvent,
  mapInterfaceListEvent,
  mapPacketEvent,
  mapSystemStatsEvent,
  mapTracerouteHopEvent,
  mergeLayerStats,
} from '@/lib/agent-mapping';
import { mapDecryptedPayloadEvent } from '@/lib/decrypted-mapping';
import { applyEnrichmentEvent } from '@/lib/enrichment-mapping';
import { isTraceComplete, mergeGeoHopUpdate, mergeTracerouteHop } from '@/lib/traceroute-state';
import { HeaderBar } from '@/components/HeaderBar';
import { DashboardView } from '@/components/DashboardView';
import { LayerDetailView } from '@/components/LayerDetailView';
import { ConnectionsView } from '@/components/ConnectionsView';
import { PacketStreamView } from '@/components/PacketStreamView';
import { FindingsPanel, type FindingNavigateTarget } from '@/components/FindingsPanel';
import { ProtocolMatrixView } from '@/components/ProtocolMatrixView';
import { InstallModal } from '@/components/InstallModal';
import { CommandLineBar } from '@/components/CommandLineBar';
import { compileDisplayFilter, type CompiledDisplayFilter } from '@/lib/display-filter';

export default function TerminalApp() {
  // Application State
  const [activeTab, setActiveTab] = useState<'dashboard' | 'layer' | 'connections' | 'packets' | 'topology' | 'findings'>('dashboard');
  const [selectedLayerNum, setSelectedLayerNum] = useState<OSILayerNumber>(7);
  const [selectedTheme, setSelectedTheme] = useState<TerminalTheme>('sophisticated');
  const [isPaused, setIsPaused] = useState(false);
  const [crtEnabled, setCrtEnabled] = useState(false);
  const [isInstallOpen, setIsInstallOpen] = useState(false);
  const [agentConnected, setAgentConnected] = useState(false);
  // Live/replay mode (epic #55/JAM-133) — null until the agent's first
  // agent_status tick arrives, same "no placeholder" discipline as
  // stats/captureConfig below. Orthogonal to agentConnected: that answers
  // "is the TCP socket to the agent up at all," this answers "what mode is
  // the agent in" — see the three-state banner derivation below.
  const [agentMode, setAgentMode] = useState<AgentStatus | null>(null);
  // Capture-to-file status (epic #55/JAM-132/GitHub #70, ring rotation
  // JAM-5/GitHub #72) — null until the agent's first capture_file_status
  // tick arrives.
  const [captureFileStatus, setCaptureFileStatus] = useState<CaptureFileStatus | null>(null);
  const [liveLayers, setLiveLayers] = useState<Record<OSILayerNumber, Partial<OSILayerInfo>>>({} as never);
  const layers = useMemo(() => mergeLayerStats(liveLayers), [liveLayers]);
  // Capture health (issue #61) — null until the agent's first capture_stats
  // tick arrives, distinct from "zero drops so far" (a real, healthy state).
  const [captureStats, setCaptureStats] = useState<CaptureStats | null>(null);
  const captureDegraded =
    captureStats !== null &&
    (captureStats.dropped > 0 ||
      captureStats.ifDropped > 0 ||
      captureStats.relayLaggedEvents > 0 ||
      captureStats.unparseableFrames > 0);

  // System Stats State (issue #64) — null until the agent's first
  // system_stats tick arrives; every field is then a real measurement, not
  // a placeholder. HeaderBar/DashboardView render an explicit "—" for
  // anything not yet received.
  const [stats, setStats] = useState<SystemStats | null>(null);

  // Capture-time controls (issue #68) — null until the agent's first
  // capture_config tick arrives, same "no placeholder" discipline as
  // `stats` above. `captureConfigError` is a one-off signal (an invalid
  // filter/snaplen) — dismissed explicitly (see its banner's button), not
  // auto-cleared by the next capture_config tick, since that tick re-sends
  // the same still-unchanged config regardless of whether an error just
  // happened and isn't itself evidence the rejection was resolved.
  const [captureConfig, setCaptureConfig] = useState<CaptureConfig | null>(null);
  const [captureConfigError, setCaptureConfigError] = useState<string | null>(null);
  const [displayFilter, setDisplayFilter] = useState<{ expression: string; predicate: CompiledDisplayFilter } | null>(null);
  const [displayFilterError, setDisplayFilterError] = useState<string | null>(null);

  // Interface selection (issue #69) — `availableInterfaces` starts empty
  // and is populated on-demand by an explicit `iface list` (or opening the
  // header's picker), not fetched automatically on load, matching this
  // app's existing "opt-in trigger" pattern for enrichment/geoip.
  // `interfaceError` is a one-off rejection signal, same dismiss-don't-
  // auto-clear discipline as `captureConfigError` above.
  const [availableInterfaces, setAvailableInterfaces] = useState<NetworkInterface[]>([]);
  const [interfaceError, setInterfaceError] = useState<string | null>(null);

  // Connections & Packets State (populated from the live capture stream)
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [packets, setPackets] = useState<PacketFrame[]>([]);
  // Expert Info (JAM-12) — capped the same way `packets` is, reusing
  // packetBufferLimitRef rather than introducing a second buffer-limit
  // command verb for one more stream.
  const [findings, setFindings] = useState<Finding[]>([]);
  const [historyRx, setHistoryRx] = useState<number[]>([]);
  const [historyTx, setHistoryTx] = useState<number[]>([]);
  // Tier B (opt-in decrypted TLS content) — same 100-entry cap discipline
  // as `packets` above, so one busy decrypt-eligible connection can't grow
  // this buffer without bound for the life of the browser tab.
  const [decryptedSegments, setDecryptedSegments] = useState<DecryptedPayloadSegment[]>([]);

  // How many recent items this browser tab keeps, per view (JAM-6/GitHub
  // #73's `buffer packets|connections|decrypted <n>` command-bar verbs).
  // Purely client-side: changing one re-caps what the SSE handler below
  // retains going forward, and never sends anything to the agent — the
  // agent's own flow-table ceiling is `MAX_FLOWS`, a separate, server-side
  // knob. Defaults are the literals these buffers were hard-capped at
  // before this became adjustable.
  const [packetBufferLimit, setPacketBufferLimit] = useState(100);
  const [connectionBufferLimit, setConnectionBufferLimit] = useState(200);
  const [decryptedBufferLimit, setDecryptedBufferLimit] = useState(100);

  // The SSE effect below has an empty dependency array (deliberately — it
  // must open exactly one EventSource for the life of the component), so
  // its `onmessage` closure captures whatever these values were on the
  // first render and would never see a later `buffer ...` command. Reading
  // them through refs instead is what actually makes the command take
  // effect; the state copies above exist for rendering (the horizon text)
  // and are the single writer of these refs, kept in sync below.
  const packetBufferLimitRef = useRef(packetBufferLimit);
  const connectionBufferLimitRef = useRef(connectionBufferLimit);
  const decryptedBufferLimitRef = useRef(decryptedBufferLimit);
  useEffect(() => {
    packetBufferLimitRef.current = packetBufferLimit;
    connectionBufferLimitRef.current = connectionBufferLimit;
    decryptedBufferLimitRef.current = decryptedBufferLimit;
  }, [packetBufferLimit, connectionBufferLimit, decryptedBufferLimit]);

  // Ownership enrichment state (spec Components §7's five-state Ownership
  // display, and §1's opt-in disclosure). `enrichmentMode` mirrors the
  // server-side EnrichmentClient's mode (kept in sync via the
  // /api/enrichment/control responses below, not read back from the
  // server); `disclosureText` drives a dismissible banner shown on every
  // enable per spec §1 ("re-shown on every enable").
  const [enrichmentMode, setEnrichmentMode] = useState<'off' | 'on-demand' | 'background'>('off');
  const [disclosureText, setDisclosureText] = useState<string | null>(null);
  const [lookingUpIds, setLookingUpIds] = useState<Set<string>>(new Set());
  const [unavailableIds, setUnavailableIds] = useState<Set<string>>(new Set());
  // Per-connectionId lookup timers, keyed outside React state since they're
  // an implementation detail (not rendered) and need synchronous
  // set/clear access from both requestLookup and the SSE handler below.
  const lookupTimers = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  // Traceroute state (on-demand only — see handleTraceRoute below, the sole
  // trigger). Keyed by connectionId, matching ConnectionsView's props.
  const [traceroute, setTraceroute] = useState<Record<string, TracerouteHop[]>>({});
  const [traceInFlight, setTraceInFlight] = useState<Record<string, boolean>>({});
  // The traceroute_hop/geo_hop_update wire events only carry targetIp, not
  // connectionId — this ref remembers which connection asked for a trace
  // against a given target IP so the SSE handler below can route hops back
  // to the right connection. Populated in handleTraceRoute, read-only from
  // the SSE effect. A ref (not state) because it's write-once-per-trace
  // bookkeeping that should never itself trigger a re-render.
  const targetIpToConnectionId = useRef<Map<string, string>>(new Map());

  // Live Capture Stream — replaces the old simulation loop
  useEffect(() => {
    const source = new EventSource('/api/stream');

    source.onmessage = (event) => {
      // A single malformed/unexpected event (e.g. an agent binary built
      // before this UI, sending a payload missing a field the mappers now
      // require) must not take down the whole SSE handler — without this
      // guard, one throw here silently and permanently stops all future
      // events from ever being processed, since EventSource keeps calling
      // the same onmessage handler.
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'connection_status') {
          setAgentConnected(data.connected);
          return;
        }
        if (data.type === 'connection_update') {
          const connection = mapConnectionEvent(data.connection);
          setConnections((prev) => {
            const idx = prev.findIndex((c) => c.id === connection.id);
            if (idx === -1) return [connection, ...prev].slice(0, connectionBufferLimitRef.current);
            const next = [...prev];
            next[idx] = connection;
            return next;
          });
        }
        if (data.type === 'connection_closed') {
          const id = mapConnectionClosedEvent(data);
          setConnections((prev) => prev.filter((c) => c.id !== id));
        }
        if (data.type === 'packet') {
          const packet = mapPacketEvent(data.packet);
          setPackets((prev) => [packet, ...prev.slice(0, packetBufferLimitRef.current - 1)]);
        }
        if (data.type === 'finding') {
          const finding = mapFindingEvent(data);
          setFindings((prev) => [finding, ...prev.slice(0, packetBufferLimitRef.current - 1)]);
        }
        if (data.type === 'decrypted_payload') {
          const segment = mapDecryptedPayloadEvent(data);
          setDecryptedSegments((prev) => [segment, ...prev.slice(0, decryptedBufferLimitRef.current - 1)]);
        }
        if (data.type === 'layer_update') {
          setLiveLayers((prev) => {
            const next = { ...prev };
            for (const layer of data.layers) {
              next[layer.layer as OSILayerNumber] = layer;
            }
            return next;
          });
        }
        if (data.type === 'capture_stats') {
          setCaptureStats(mapCaptureStatsEvent(data));
        }
        if (data.type === 'system_stats') {
          setStats(mapSystemStatsEvent(data));
        }
        if (data.type === 'agent_status') {
          setAgentMode(mapAgentStatusEvent(data));
        }
        if (data.type === 'capture_file_status') {
          setCaptureFileStatus(mapCaptureFileStatusEvent(data));
        }
        if (data.type === 'capture_config') {
          // Sent once per tick regardless of whether anything changed (so a
          // client that just reconnected sees current values immediately —
          // issue #68's "always visible" requirement) — never auto-clears
          // captureConfigError below, since an unrelated periodic re-send
          // of the same still-unchanged config isn't evidence the earlier
          // rejection was resolved. The error banner is dismissed
          // explicitly instead (see its button).
          setCaptureConfig(mapCaptureConfigEvent(data));
        }
        if (data.type === 'capture_config_error') {
          setCaptureConfigError(mapCaptureConfigErrorEvent(data));
        }
        if (data.type === 'interface_list') {
          setAvailableInterfaces(mapInterfaceListEvent(data));
        }
        if (data.type === 'interface_changed') {
          // system_stats (above) is the enduring source of truth for the
          // active interfaceName/ipAddress — this event exists only so a
          // successful switch clears any earlier rejection right away,
          // rather than leaving a stale error banner up for another ~1s
          // until the next system_stats tick would otherwise imply it.
          setInterfaceError(null);
        }
        if (data.type === 'interface_error') {
          setInterfaceError(mapInterfaceErrorEvent(data));
        }
        if (data.type === 'connection_enrichment') {
          setConnections((prev) => applyEnrichmentEvent(prev, data));
          // A result arrived for this connectionId — it's no longer "in
          // flight," and if it had previously timed out into "unavailable"
          // (e.g. a slow background-mode lookup that finished late), a real
          // result should supersede that state rather than leave it stuck.
          const timer = lookupTimers.current.get(data.connectionId);
          if (timer) {
            clearTimeout(timer);
            lookupTimers.current.delete(data.connectionId);
          }
          setLookingUpIds((prev) => {
            if (!prev.has(data.connectionId)) return prev;
            const next = new Set(prev);
            next.delete(data.connectionId);
            return next;
          });
          setUnavailableIds((prev) => {
            if (!prev.has(data.connectionId)) return prev;
            const next = new Set(prev);
            next.delete(data.connectionId);
            return next;
          });
        }
        if (data.type === 'traceroute_hop') {
          const hop = mapTracerouteHopEvent(data);
          const connectionId = targetIpToConnectionId.current.get(hop.targetIp);
          if (connectionId) {
            setTraceroute((prev) => mergeTracerouteHop(prev, connectionId, hop));
            if (isTraceComplete(hop, hop.targetIp)) {
              setTraceInFlight((prev) => ({ ...prev, [connectionId]: false }));
            }
          }
        }
        if (data.type === 'geo_hop_update') {
          const connectionId = targetIpToConnectionId.current.get(data.targetIp);
          if (connectionId) {
            setTraceroute((prev) => mergeGeoHopUpdate(prev, connectionId, data.hopNumber, data.location ?? undefined));
          }
        }
      } catch (err) {
        console.error('capture-agent: failed to process stream event', err, event.data);
      }
    };

    return () => source.close();
  }, []);

  // Sends a pause/resume control message to the capture agent via the relay.
  const sendControl = (type: 'pause' | 'resume') => {
    fetch('/api/control', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type }),
    });
  };

  // Toggles ownership enrichment mode via /api/enrichment/control (Task 9's
  // route, backed by Task 8's EnrichmentClient). Re-shows the disclosure
  // banner on every enable (on-demand or background), per spec §1.
  const enrichmentControl = async (action: string) => {
    const res = await fetch('/api/enrichment/control', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action }),
    });
    const body = await res.json();
    if (body.disclosureText) setDisclosureText(body.disclosureText); // re-shown on every enable, per spec §1
    if (action === 'enable') setEnrichmentMode('on-demand');
    if (action === 'enable_background') setEnrichmentMode('background');
    if (action === 'disable') setEnrichmentMode('off');
    if (action === 'disable_background') setEnrichmentMode('on-demand');
    if (action === 'clear') {
      setEnrichmentMode('off');
      // Wipe any in-flight/unavailable bookkeeping along with the
      // server-side cache+log clear — a stale "Looking up…" or
      // "Unavailable" badge left over from before the clear would be
      // misleading once enrichment is off and the cache is gone.
      for (const timer of lookupTimers.current.values()) clearTimeout(timer);
      lookupTimers.current.clear();
      setLookingUpIds(new Set());
      setUnavailableIds(new Set());
    }
  };

  // How long to wait for a connection_enrichment event before treating a
  // lookup as "Unavailable" rather than leaving it on "Looking up…"
  // forever. Generous on purpose: RequestQueue can hold a lookup for up to
  // ~10s of jittered spacing (lib/enrichment/request-queue.ts) before even
  // dispatching it, on top of RdapClient's own 10s request timeout
  // (lib/enrichment/rdap-client.ts) — 25s covers both with margin.
  const LOOKUP_TIMEOUT_MS = 25_000;

  const requestLookup = (connectionId: string, remoteAddr: string) => {
    setLookingUpIds((prev) => new Set(prev).add(connectionId));
    setUnavailableIds((prev) => {
      if (!prev.has(connectionId)) return prev;
      const next = new Set(prev);
      next.delete(connectionId);
      return next;
    });

    const existing = lookupTimers.current.get(connectionId);
    if (existing) clearTimeout(existing);
    const timer = setTimeout(() => {
      lookupTimers.current.delete(connectionId);
      setLookingUpIds((prev) => {
        if (!prev.has(connectionId)) return prev;
        const next = new Set(prev);
        next.delete(connectionId);
        return next;
      });
      setUnavailableIds((prev) => new Set(prev).add(connectionId));
    }, LOOKUP_TIMEOUT_MS);
    lookupTimers.current.set(connectionId, timer);

    fetch('/api/enrichment/lookup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ connectionId, remoteAddr }),
    });
  };

  // Traceroute is on-demand only — this is the sole trigger for a trace
  // anywhere in the app (see the design spec's Explicitly out of scope
  // section and the implementation plan's Global Constraints).
  const handleTraceRoute = (connectionId: string, remoteAddr: string) => {
    targetIpToConnectionId.current.set(remoteAddr, connectionId);
    setTraceroute((prev) => ({ ...prev, [connectionId]: [] }));
    setTraceInFlight((prev) => ({ ...prev, [connectionId]: true }));
    fetch('/api/traceroute/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ connectionId, remoteAddr }),
    });
  };

  // GeoIP mode is opt-in and runtime-only (never persisted) — see
  // lib/geoip.ts and docs/geoip-protocol.md.
  const sendGeoIpControl = (action: 'enable' | 'disable' | 'clear') => {
    fetch('/api/geoip/control', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action }),
    });
  };

  // Capture-time controls (issue #68) — routed through the same
  // /api/control endpoint as pause/resume, since both are just control
  // messages forwarded to the agent's existing control channel.
  const sendCaptureFilter = (filter: string) => {
    fetch('/api/control', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'set_capture_filter', filter }),
    });
  };
  const sendSnaplen = (bytes: number) => {
    fetch('/api/control', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'set_snaplen', bytes }),
    });
  };

  // Capture-to-file (epic #55/JAM-132/GitHub #70, ring rotation JAM-5/
  // GitHub #72) — the same /api/control POST route as pause/filter/snaplen
  // above; no dedicated route. The agent is the authoritative validator and
  // reports a rejection via `capture_file_error`, so nothing here tries to
  // second-guess whether a path is writable.
  const sendStartCaptureFile = (
    path: string,
    ring?: { mode: string; threshold: number },
    autostop?: { mode: string; threshold: number },
  ) => {
    fetch('/api/control', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'start_capture_file', path, ring, autostop }),
    });
  };
  const sendStopCaptureFile = () => {
    fetch('/api/control', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'stop_capture_file' }),
    });
  };

  // Parses the `ring`/`autostop` option pairs out of a `capture <path> ...`
  // command's token list. Returns `undefined` when the keyword is absent
  // (the common case — a plain, non-rotating capture) and `null` when it's
  // present but malformed, which the caller treats as "don't send anything"
  // rather than silently starting a capture with the option dropped.
  const parseCaptureOption = (
    tokens: string[],
    keyword: string,
    allowedModes: string[],
  ): { mode: string; threshold: number } | undefined | null => {
    const idx = tokens.indexOf(keyword);
    if (idx === -1) return undefined;
    const mode = tokens[idx + 1];
    const threshold = Number(tokens[idx + 2]);
    if (!mode || !allowedModes.includes(mode)) return null;
    if (!Number.isInteger(threshold) || threshold <= 0) return null;
    return { mode, threshold };
  };

  // Interface selection (issue #69). Listing is on-demand only (the header
  // picker requests it when opened; `iface list` does the same from the
  // command bar) — never fetched automatically, matching this app's
  // existing opt-in-trigger pattern for enrichment/geoip.
  const sendListInterfaces = () => {
    fetch('/api/control', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'list_interfaces' }),
    });
  };
  const sendSetInterface = (name: string) => {
    fetch('/api/control', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'set_interface', name }),
    });
  };

  // Command Line Handler
  const handleExecuteCommand = (cmdStr: string) => {
    const parts = cmdStr.toLowerCase().split(' ');
    const mainCmd = parts[0];
    const arg1 = parts[1];

    if (mainCmd === 'dash' || mainCmd === 'dashboard') {
      setActiveTab('dashboard');
    } else if (mainCmd === 'layer' && arg1) {
      const num = parseInt(arg1, 10) as OSILayerNumber;
      if (num >= 1 && num <= 7) {
        setSelectedLayerNum(num);
        setActiveTab('layer');
      }
    } else if (mainCmd === 'conn' || mainCmd === 'sockets' || mainCmd === 'connections') {
      setActiveTab('connections');
    } else if (mainCmd === 'pcap' || mainCmd === 'packets') {
      setActiveTab('packets');
    } else if (mainCmd === 'matrix' || mainCmd === 'topology') {
      setActiveTab('topology');
    } else if (mainCmd === 'theme' && arg1) {
      if (THEMES[arg1 as TerminalTheme]) {
        setSelectedTheme(arg1 as TerminalTheme);
      }
    } else if (mainCmd === 'pause') {
      sendControl('pause');
    } else if (mainCmd === 'resume') {
      sendControl('resume');
    } else if (mainCmd === 'reset') {
      setConnections([]);
      setPackets([]);
      setDecryptedSegments([]);
      setFindings([]);
    } else if (mainCmd === 'geoip' && arg1 === 'enable') {
      sendGeoIpControl('enable');
    } else if (mainCmd === 'geoip' && arg1 === 'disable') {
      sendGeoIpControl('disable');
    } else if (mainCmd === 'geoip' && arg1 === 'clear') {
      sendGeoIpControl('clear');
    } else if (['install', 'macos', 'brew', 'curl', 'sw_vers'].includes(mainCmd)) {
      setIsInstallOpen(true);
    } else if (mainCmd === 'enrich' && arg1 === 'on') {
      enrichmentControl('enable');
    } else if (mainCmd === 'enrich' && arg1 === 'off') {
      enrichmentControl('disable');
    } else if (mainCmd === 'enrich' && arg1 === 'background' && parts[2] === 'on') {
      // `parts` comes from cmdStr.toLowerCase().split(' ') above, so this
      // three-token form is reachable — a two-token-only mainCmd/arg1 check
      // would silently drop the "on"/"off" token here.
      enrichmentControl('enable_background');
    } else if (mainCmd === 'enrich' && arg1 === 'background' && parts[2] === 'off') {
      enrichmentControl('disable_background');
    } else if (mainCmd === 'enrich' && arg1 === 'clear') {
      enrichmentControl('clear');
    } else if (mainCmd === 'display') {
      const expression = cmdStr.includes(' ') ? cmdStr.slice(cmdStr.indexOf(' ') + 1).trim() : '';
      if (expression.toLowerCase() === 'clear') {
        setDisplayFilter(null);
        setDisplayFilterError(null);
      } else {
        const result = compileDisplayFilter(expression);
        if (result.ok) {
          setDisplayFilter({ expression, predicate: result.predicate });
          setDisplayFilterError(null);
        } else {
          setDisplayFilterError(`Display filter error: ${result.error.message} at token "${result.error.token}" (character ${result.error.position + 1}).`);
        }
      }
    } else if (mainCmd === 'filter' && arg1 === 'clear') {
      sendCaptureFilter('');
    } else if (mainCmd === 'filter' && arg1) {
      // The BPF expression's case matters (e.g. a hostname in `host
      // Example.com`), so this is sliced off the ORIGINAL cmdStr, not the
      // lowercased `parts` used for command routing above.
      const filterExpr = cmdStr.slice(cmdStr.indexOf(' ') + 1).trim();
      if (filterExpr) sendCaptureFilter(filterExpr);
    } else if (mainCmd === 'snaplen' && arg1 === 'full') {
      sendSnaplen(65535);
    } else if (mainCmd === 'snaplen' && arg1) {
      const bytes = parseInt(arg1, 10);
      if (Number.isInteger(bytes) && bytes > 0) sendSnaplen(bytes);
    } else if (mainCmd === 'iface' && arg1 === 'list') {
      sendListInterfaces();
    } else if (mainCmd === 'iface' && arg1) {
      // Interface names (en0, lo0, utun8, ...) are conventionally already
      // lowercase, so the pre-lowercased `arg1` is fine here — unlike a
      // free-text filter expression, there's no case-sensitive content to
      // preserve.
      sendSetInterface(arg1);
    } else if (mainCmd === 'capture' && arg1 === 'stop') {
      sendStopCaptureFile();
    } else if (mainCmd === 'capture' && arg1) {
      // `capture /Users/Me/Captures/Run1.pcapng ring size 104857600 autostop duration 3600`
      //
      // A filesystem path is case-sensitive on any volume that isn't
      // case-insensitive, so the path is sliced off the ORIGINAL cmdStr,
      // not the lowercased `parts` used for routing — the same precedent
      // `filter <expr>` sets above, and the single thing most likely to
      // regress here (see lib/__tests__/page-command-bar-capture.test.tsx).
      const rest = cmdStr.slice(cmdStr.indexOf(' ') + 1).trim();
      const tokens = rest.split(/\s+/);
      const path = tokens[0];
      // The option KEYWORDS and mode names are matched case-insensitively
      // (they're command syntax, not data) while the path above keeps its
      // case. Lowercasing only the tokens used for option lookup is what
      // keeps those two requirements from fighting.
      const optionTokens = tokens.map((t) => t.toLowerCase());
      const ring = parseCaptureOption(optionTokens, 'ring', ['size', 'duration', 'count']);
      const autostop = parseCaptureOption(optionTokens, 'autostop', ['duration', 'totalsize']);
      // A malformed option is refused locally rather than sent with the
      // option silently dropped — starting an un-rotated, un-autostopped
      // capture when the operator asked for both is the worse failure.
      if (path && ring !== null && autostop !== null) {
        sendStartCaptureFile(
          path,
          ring,
          // The wire contract spells this mode "totalSize" (camelCase);
          // the command bar accepts it in any case, so it's normalized
          // back here rather than at the parse site.
          autostop && autostop.mode === 'totalsize' ? { ...autostop, mode: 'totalSize' } : autostop,
        );
      }
    } else if (mainCmd === 'buffer' && arg1 && parts[2]) {
      // Purely client-side: re-caps what this tab keeps, no agent
      // round-trip. A non-positive or unparseable count is ignored rather
      // than clamped, matching `snaplen <n>`'s own validation posture.
      const n = parseInt(parts[2], 10);
      if (Number.isInteger(n) && n > 0) {
        // Each branch also truncates what's already held. Without this, a
        // LOWERED limit would only take effect on the next event of that
        // kind — so `buffer packets 10` on an idle capture would leave 100
        // packets on screen indefinitely, which reads as the command
        // having been ignored. Raising a limit needs no equivalent (the
        // dropped items are gone), it just lets the buffer grow again.
        if (arg1 === 'packets') {
          setPacketBufferLimit(n);
          setPackets((prev) => prev.slice(0, n));
        } else if (arg1 === 'connections') {
          setConnectionBufferLimit(n);
          setConnections((prev) => prev.slice(0, n));
        } else if (arg1 === 'decrypted') {
          setDecryptedBufferLimit(n);
          setDecryptedSegments((prev) => prev.slice(0, n));
        }
      }
    }
  };

  const themeConfig = THEMES[selectedTheme];
  const activeLayer = layers.find((l) => l.layer === selectedLayerNum) || layers[0];

  // Persistent, always-visible indicator that Tier B (opt-in decrypted TLS
  // content) is active for at least one connection — never ambient/silent,
  // per the spec's "decrypting must always be visible" requirement. Derived
  // straight from having seen any decrypted_payload events for a still-open
  // connection, rather than a dedicated wire signal (see docs/wire-protocol.md
  // and the plan's Self-Review Notes for why: threading the wrapped
  // command string through to the browser is flagged there as a follow-up,
  // not built in this pass — this connection-count banner is the interim
  // stand-in that still satisfies "never silent").
  const decryptingConnectionIds = new Set(decryptedSegments.map((s) => s.connectionId));
  const isDecrypting = decryptingConnectionIds.size > 0;

  // Three-state mode banner (epic #55/JAM-133's UI honesty requirement: "the
  // UI must say 'replaying <file>' rather than implying live capture").
  // Order matters: disconnected (no TCP socket at all) always wins over
  // whatever mode was last known, since a disconnected agent's last-known
  // mode is stale information. 'live' renders no banner, matching the
  // pre-existing "no banner when connected" behavior exactly.
  const bannerState: 'disconnected' | 'live' | 'replaying' = !agentConnected
    ? 'disconnected'
    : agentMode?.mode === 'replay'
      ? 'replaying'
      : 'live';

  return (
    <div className={`min-h-screen ${themeConfig.bg} ${themeConfig.text} font-mono flex flex-col justify-between overflow-x-hidden relative select-none transition-colors duration-300`}>
      {bannerState === 'disconnected' && (
        <div className="w-full bg-red-900/40 border-b border-red-700 text-red-200 text-sm px-4 py-2">
          capture agent not connected — run <code>./capture-agent</code> in <code>capture-agent/</code> (see capture-agent/README.md)
        </div>
      )}

      {bannerState === 'replaying' && (
        <div className="w-full bg-sky-900/40 border-b border-sky-700 text-sky-200 text-sm px-4 py-2">
          replaying <code>{agentMode?.replaySource ?? 'unknown file'}</code> — not a live capture
          {agentMode?.directionAttributionUnavailable &&
            ' — direction (rx/tx) could not be determined for this file and is shown positionally, not authoritatively'}
        </div>
      )}

      {/* Capture-side loss (issue #61): kernel/driver drops or a lagging
          relay both mean data never reached this UI at all — distinct from,
          and a precondition for trusting, any connection's own loss %
          below. Shown whenever any of the three counters is nonzero;
          persistent (not dismissible) since it stays true until the
          underlying cause does. */}
      {captureDegraded && captureStats && (
        <div className="w-full bg-red-900/40 border-b border-red-700 text-red-200 text-sm px-4 py-2">
          capture degraded — {captureStats.dropped + captureStats.ifDropped} frame(s) dropped by the kernel/driver
          {captureStats.relayLaggedEvents > 0 && `, ${captureStats.relayLaggedEvents} event(s) dropped for a lagging client`}
          {captureStats.unparseableFrames > 0 && `, ${captureStats.unparseableFrames} frame(s) could not be parsed`}
          {' '}— per-connection loss figures below may under-report
        </div>
      )}

      {isDecrypting && (
        <div className="w-full bg-amber-900/40 border-b border-amber-700 text-amber-200 text-sm px-4 py-2">
          Decrypting traffic for: {decryptingConnectionIds.size} connection(s) — Tier B opt-in content visible in LIVE PCAP
        </div>
      )}

      {/* A rejected `filter`/`snaplen` command bar action (issue #68) —
          dismissible rather than auto-cleared, since the next periodic
          capture_config tick re-sends the same (unchanged, still rejected)
          config and isn't itself evidence the operator has fixed it. */}
      {captureConfigError && (
        <div className="w-full bg-red-900/40 border-b border-red-700 text-red-200 text-sm px-4 py-2 flex items-start justify-between gap-3">
          <span>capture config rejected — {captureConfigError}</span>
          <button
            onClick={() => setCaptureConfigError(null)}
            className="shrink-0 text-red-200 hover:text-white font-bold"
            aria-label="Dismiss capture config error"
          >
            [CLOSE]
          </button>
        </div>
      )}

      {/* A rejected `iface <name>` switch (issue #69) — dismissible, same
          reasoning as the capture-config error above. Cleared automatically
          on a successful switch (interface_changed), unlike that one,
          since interface_changed only ever fires on success — real
          evidence the rejection was resolved. */}
      {interfaceError && (
        <div className="w-full bg-red-900/40 border-b border-red-700 text-red-200 text-sm px-4 py-2 flex items-start justify-between gap-3">
          <span>interface switch rejected — {interfaceError}</span>
          <button
            onClick={() => setInterfaceError(null)}
            className="shrink-0 text-red-200 hover:text-white font-bold"
            aria-label="Dismiss interface error"
          >
            [CLOSE]
          </button>
        </div>
      )}

      {/* Ownership enrichment disclosure — re-shown on every "enrich on" /
          "enrich background on", per spec §1. Simple dismissible banner,
          consistent with the "agent not connected" banner's styling above,
          not a full modal. */}
      {disclosureText && (
        <div className="w-full bg-amber-900/40 border-b border-amber-700 text-amber-100 text-sm px-4 py-2 flex items-start justify-between gap-3">
          <span>{disclosureText}</span>
          <button
            onClick={() => setDisclosureText(null)}
            className="shrink-0 text-amber-200 hover:text-white font-bold"
            aria-label="Dismiss disclosure"
          >
            [CLOSE]
          </button>
        </div>
      )}

      {/* CRT Scanline Overlay Effect */}
      {crtEnabled && <div className="pointer-events-none fixed inset-0 z-50 crt-scanlines opacity-40"></div>}

      <div className="flex-1 flex flex-col">
        {/* Header Navigation Bar */}
        <HeaderBar
          stats={stats}
          captureConfig={captureConfig}
          captureFileStatus={captureFileStatus}
          availableInterfaces={availableInterfaces}
          onListInterfaces={sendListInterfaces}
          onSelectInterface={sendSetInterface}
          theme={themeConfig}
          onSelectTheme={setSelectedTheme}
          isPaused={isPaused}
          onTogglePause={() => {
            const next = !isPaused;
            setIsPaused(next);
            sendControl(next ? 'pause' : 'resume');
          }}
          onReset={() => {
            setConnections([]);
            setPackets([]);
            setDecryptedSegments([]);
            setFindings([]);
          }}
          crtEnabled={crtEnabled}
          onToggleCrt={() => setCrtEnabled(!crtEnabled)}
          onOpenInstall={() => setIsInstallOpen(true)}
        />

        {/* View Navigation Tabs Bar (F1-F6) */}
        <nav className={`bg-slate-950 border-b ${themeConfig.border} px-3 py-1.5 flex items-center space-x-1 overflow-x-auto text-xs`}>
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded transition font-bold ${
              activeTab === 'dashboard'
                ? themeConfig.highlight
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <BarChart2 className="h-3.5 w-3.5" />
            <span>F1: DASHBOARD</span>
          </button>

          <button
            onClick={() => setActiveTab('layer')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded transition font-bold ${
              activeTab === 'layer'
                ? themeConfig.highlight
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Layers className="h-3.5 w-3.5" />
            <span>F2: LAYER {selectedLayerNum} INSPECTOR</span>
          </button>

          <button
            onClick={() => setActiveTab('connections')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded transition font-bold ${
              activeTab === 'connections'
                ? themeConfig.highlight
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Network className="h-3.5 w-3.5" />
            <span>F3: SOCKETS ({connections.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('packets')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded transition font-bold ${
              activeTab === 'packets'
                ? themeConfig.highlight
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Radio className="h-3.5 w-3.5" />
            <span>F4: LIVE PCAP ({packets.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('topology')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded transition font-bold ${
              activeTab === 'topology'
                ? themeConfig.highlight
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Globe className="h-3.5 w-3.5" />
            <span>F5: TOPOLOGY</span>
          </button>

          <button
            onClick={() => setActiveTab('findings')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded transition font-bold ${
              activeTab === 'findings'
                ? themeConfig.highlight
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <ShieldAlert className="h-3.5 w-3.5" />
            <span>F6: FINDINGS ({findings.length})</span>
          </button>

        </nav>

        {/* Active View Container */}
        <main className="flex-1 max-w-7xl w-full mx-auto">
          {activeTab === 'dashboard' && (
            <DashboardView
              layers={layers}
              stats={stats}
              theme={themeConfig}
              onSelectLayer={(num) => {
                setSelectedLayerNum(num);
                setActiveTab('layer');
              }}
              historyRx={historyRx}
              historyTx={historyTx}
            />
          )}

          {activeTab === 'layer' && (
            <LayerDetailView
              layer={activeLayer}
              theme={themeConfig}
              onBack={() => setActiveTab('dashboard')}
              onSelectLayer={(num) => setSelectedLayerNum(num)}
            />
          )}

          {activeTab === 'connections' && (
            <ConnectionsView
              connections={connections}
              theme={themeConfig}
              enrichmentMode={enrichmentMode}
              onRequestLookup={requestLookup}
              lookingUpIds={lookingUpIds}
              unavailableIds={unavailableIds}
              traceroute={traceroute}
              traceInFlight={traceInFlight}
              onTraceRoute={handleTraceRoute}
              captureDegraded={captureDegraded}
              totalObserved={captureStats?.totalConnectionsObserved}
              capacityEvictions={captureStats?.capacityEvictions}
              bufferLimit={connectionBufferLimit}
              displayFilter={displayFilter?.predicate}
              displayFilterExpression={displayFilter?.expression}
              findings={findings}
            />
          )}

          {activeTab === 'packets' && (
            <PacketStreamView
              packets={packets}
              theme={themeConfig}
              onClearPackets={() => setPackets([])}
              decryptedSegments={decryptedSegments}
              totalObserved={captureStats?.received}
              bufferLimit={packetBufferLimit}
              displayFilter={displayFilter?.predicate}
              displayFilterExpression={displayFilter?.expression}
              findings={findings}
            />
          )}

          {activeTab === 'topology' && (
            <ProtocolMatrixView
              layers={layers}
              theme={themeConfig}
              onSelectLayer={(num) => {
                setSelectedLayerNum(num);
                setActiveTab('layer');
              }}
            />
          )}

          {activeTab === 'findings' && (
            <FindingsPanel
              findings={findings}
              theme={themeConfig}
              onNavigate={(target: FindingNavigateTarget) => {
                setActiveTab(target.kind === 'frame' ? 'packets' : 'connections');
              }}
            />
          )}
        </main>
      </div>

      {/* macOS Terminal & App Installer Modal */}
      <InstallModal
        isOpen={isInstallOpen}
        onClose={() => setIsInstallOpen(false)}
        theme={themeConfig}
      />

      {/* Interactive Bottom CLI Command Bar */}
      <CommandLineBar theme={themeConfig} onExecuteCommand={handleExecuteCommand} displayFilterError={displayFilterError} />
    </div>
  );
}
