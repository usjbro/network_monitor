// JAM-185: the source of `osi-mon`, the terminal client /api/install writes
// to ~/.local/bin. It used to print hardcoded per-layer "Gbps" figures,
// Math.random() throughput and a constant uptime. Now it reads the same
// /api/stream SSE feed the web UI does and prints only what the agent
// reported:
//
// - `system_stats`: host identity, total Mbps/pps, packets captured.
// - `layer_update`: rates for layers 3, 4 and 7, the only ones the agent
//   measures. Layers 1, 2, 5 and 6 are listed as not measured separately.
//
// Until a report arrives, or while the server or agent is unreachable, it
// says so and shows no figures.
//
// The program is plain Node with no dependencies, and is embedded in a
// quoted (non-expanding) heredoc, so it must never contain a line that is
// exactly `EOF`. `String.raw` keeps its escape sequences (`\x1b`, `\n`) as
// source text for Node to interpret, not for this file to.

export function osiMonClientSource(origin: string): string {
  return String.raw`#!/usr/bin/env node
// osi-mon: a terminal view of Network Monitor's live counters.
// Every figure comes from the server's /api/stream. Nothing is estimated.
'use strict';

const http = require('http');
const https = require('https');

const SERVER_URL = ${JSON.stringify(origin)};
const RECONNECT_MS = 2000;
// Bound on a partial SSE event held between chunks.
const MAX_BUFFERED = 1048576;

const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[90m',
  green: '\x1b[32m',
  cyan: '\x1b[36m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
};

const LAYERS = [
  { num: 7, name: 'L7: APPLICATION' },
  { num: 6, name: 'L6: PRESENTATION' },
  { num: 5, name: 'L5: SESSION' },
  { num: 4, name: 'L4: TRANSPORT' },
  { num: 3, name: 'L3: NETWORK' },
  { num: 2, name: 'L2: DATA LINK' },
  { num: 1, name: 'L1: PHYSICAL' },
];
// The agent counts IP, transport and application bytes only.
const UNMEASURED = [1, 2, 5, 6];

const state = {
  problem: 'Connecting to ' + SERVER_URL + ' ...',
  agentConnected: null,
  system: null,
  layers: {},
};
let retryPending = false;

// Agent-reported text goes to a terminal, so control characters, escape
// sequences and bidirectional overrides are shown as escapes, never sent.
function safe(text) {
  return String(text).replace(/[\x00-\x1f\x7f-\x9f‎‏‪-‮⁦-⁩]/g, function (c) {
    const code = c.charCodeAt(0);
    return code < 256 ? '\\x' + ('0' + code.toString(16)).slice(-2) : '\\u' + ('000' + code.toString(16)).slice(-4);
  });
}

function isNumber(value) {
  return typeof value === 'number' && isFinite(value);
}

function rate(bytesPerSec) {
  if (!isNumber(bytesPerSec)) return 'n/a';
  if (bytesPerSec < 1024) return bytesPerSec.toFixed(0) + ' B/s';
  if (bytesPerSec < 1024 * 1024) return (bytesPerSec / 1024).toFixed(1) + ' KB/s';
  if (bytesPerSec < 1024 * 1024 * 1024) return (bytesPerSec / (1024 * 1024)).toFixed(2) + ' MB/s';
  return (bytesPerSec / (1024 * 1024 * 1024)).toFixed(2) + ' GB/s';
}

function fixed(value, digits, unit) {
  return isNumber(value) ? value.toFixed(digits) + unit : 'n/a';
}

function clearFigures() {
  state.system = null;
  state.layers = {};
}

function render() {
  const lines = [];
  lines.push(C.green + C.bold + 'osi-mon' + C.reset + C.dim + '  ' + safe(SERVER_URL) + '  ' + new Date().toLocaleTimeString() + C.reset);
  lines.push('');
  const hasFigures = state.system !== null || Object.keys(state.layers).length > 0;
  if (state.problem) {
    lines.push(C.yellow + state.problem + C.reset);
  } else if (state.agentConnected === false) {
    lines.push(C.red + 'Agent disconnected: the server is up but is not receiving data from the capture agent.' + C.reset);
  } else if (!hasFigures) {
    lines.push(C.dim + 'Connected. Waiting for the agent to report...' + C.reset);
  } else {
    const s = state.system;
    if (s) {
      lines.push(C.bold + 'Host ' + C.reset + safe(s.hostname || '(unknown)') +
        C.dim + '  interface ' + C.reset + safe(s.interfaceName || '(unknown)') +
        C.dim + '  address ' + C.reset + safe(s.ipAddress || '(none)'));
      lines.push(C.bold + 'Total ' + C.reset +
        C.green + 'RX ' + fixed(s.rxTotalMbps, 2, ' Mbps') + C.reset + '  ' +
        C.cyan + 'TX ' + fixed(s.txTotalMbps, 2, ' Mbps') + C.reset + '  ' +
        C.green + 'RX ' + fixed(s.rxPpsTotal, 0, ' pps') + C.reset + '  ' +
        C.cyan + 'TX ' + fixed(s.txPpsTotal, 0, ' pps') + C.reset);
      lines.push(C.dim + (isNumber(s.totalPacketsCaptured) ? s.totalPacketsCaptured : 'n/a') + ' packets captured' + C.reset);
      lines.push('');
    }
    LAYERS.forEach(function (layer) {
      const label = C.bold + (layer.name + '                  ').slice(0, 18) + C.reset;
      const stats = state.layers[layer.num];
      if (stats) {
        lines.push(label + C.green + 'RX ' + rate(stats.rxSpeed) + C.reset + '  ' + C.cyan + 'TX ' + rate(stats.txSpeed) + C.reset);
      } else if (UNMEASURED.indexOf(layer.num) !== -1) {
        lines.push(label + C.dim + 'not measured separately' + C.reset);
      } else {
        lines.push(label + C.dim + 'no report yet' + C.reset);
      }
    });
  }
  lines.push('');
  lines.push(C.dim + 'Ctrl+C to stop. Full view: ' + safe(SERVER_URL) + C.reset);
  process.stdout.write('\x1b[H\x1b[2J' + lines.join('\n') + '\n');
}

function handle(json) {
  let event;
  try {
    event = JSON.parse(json);
  } catch (err) {
    return;
  }
  if (!event || typeof event !== 'object') return;
  if (event.type === 'connection_status') {
    state.agentConnected = event.connected === true;
    if (!state.agentConnected) clearFigures();
  } else if (event.type === 'system_stats' && event.stats && typeof event.stats === 'object') {
    state.system = event.stats;
  } else if (event.type === 'layer_update' && Array.isArray(event.layers)) {
    event.layers.forEach(function (layer) {
      if (layer && isNumber(layer.layer)) state.layers[layer.layer] = layer;
    });
  }
}

function retry() {
  if (retryPending) return;
  retryPending = true;
  setTimeout(function () {
    retryPending = false;
    connect();
  }, RECONNECT_MS);
}

function connect() {
  let url;
  try {
    url = new URL('/api/stream', SERVER_URL);
  } catch (err) {
    state.problem = 'Not a usable server address: ' + safe(SERVER_URL);
    render();
    return;
  }
  const client = url.protocol === 'https:' ? https : http;
  const req = client.get(url, { headers: { Accept: 'text/event-stream' } }, function (res) {
    if (res.statusCode !== 200) {
      state.problem = 'The server answered HTTP ' + res.statusCode + ' for ' + safe(url) + '. Retrying...';
      clearFigures();
      render();
      res.resume();
      retry();
      return;
    }
    state.problem = null;
    render();
    res.setEncoding('utf8');
    let buffered = '';
    res.on('data', function (chunk) {
      buffered += chunk;
      let end;
      while ((end = buffered.indexOf('\n\n')) !== -1) {
        const frame = buffered.slice(0, end);
        buffered = buffered.slice(end + 2);
        frame.split('\n').forEach(function (line) {
          if (line.indexOf('data: ') === 0) handle(line.slice(6));
        });
      }
      if (buffered.length > MAX_BUFFERED) buffered = '';
      render();
    });
    res.on('end', function () {
      state.problem = 'The stream from ' + safe(SERVER_URL) + ' ended. Reconnecting...';
      clearFigures();
      render();
      retry();
    });
  });
  req.on('error', function (err) {
    state.problem = 'Cannot reach ' + safe(url) + ': ' + safe(err && err.message) + '. Retrying...';
    clearFigures();
    render();
    retry();
  });
}

setInterval(render, 1000);
render();
connect();
`;
}
