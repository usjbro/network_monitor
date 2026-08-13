'use client';

import React, { useState } from 'react';
import {
  ArrowDown,
  ArrowUp,
  Layers,
} from 'lucide-react';
import { OSILayerInfo, ThemeConfig, OSILayerNumber } from '@/lib/types';
import { formatSpeed } from '@/lib/osi-engine';

interface ProtocolMatrixViewProps {
  layers: OSILayerInfo[];
  theme: ThemeConfig;
  onSelectLayer: (num: OSILayerNumber) => void;
}

export const ProtocolMatrixView: React.FC<ProtocolMatrixViewProps> = ({
  layers,
  theme,
  onSelectLayer,
}) => {
  const [direction, setDirection] = useState<'ENCAPSULATION' | 'DECAPSULATION'>('ENCAPSULATION');

  const orderedLayers = direction === 'ENCAPSULATION' ? [...layers].reverse() : [...layers];

  return (
    <div className="space-y-4 font-mono text-xs p-3">
      {/* Top Banner Control */}
      <div className="flex flex-wrap items-center justify-between gap-2 bg-slate-950 p-3 rounded border border-slate-800">
        <div>
          <h2 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
            <Layers className={`h-4 w-4 ${theme.accent}`} />
            <span>OSI 7-LAYER ENCAPSULATION & DATA FLOW TOPOLOGY</span>
          </h2>
          <p className="text-[11px] text-slate-400">
            Visualizing packet overhead construction from Application Data down to Physical Bits.
          </p>
        </div>

        {/* Direction Toggle */}
        <div className="flex items-center space-x-2 bg-slate-900 p-1 rounded border border-slate-800">
          <button
            onClick={() => setDirection('ENCAPSULATION')}
            className={`flex items-center space-x-1 px-2.5 py-1 rounded text-[11px] font-bold transition ${
              direction === 'ENCAPSULATION'
                ? 'bg-emerald-950 text-emerald-300 border border-emerald-600'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ArrowDown className="h-3.5 w-3.5" />
            <span>ENCAPSULATION (TX)</span>
          </button>

          <button
            onClick={() => setDirection('DECAPSULATION')}
            className={`flex items-center space-x-1 px-2.5 py-1 rounded text-[11px] font-bold transition ${
              direction === 'DECAPSULATION'
                ? 'bg-sky-950 text-sky-300 border border-sky-600'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ArrowUp className="h-3.5 w-3.5" />
            <span>DECAPSULATION (RX)</span>
          </button>
        </div>
      </div>

      {/* 7 Layers Interactive Architecture Flow Chart */}
      <div className="space-y-3">
        {orderedLayers.map((layer, index) => {
          return (
            <div
              key={layer.layer}
              onClick={() => onSelectLayer(layer.layer)}
              className={`p-3 rounded border ${theme.border} bg-slate-950/80 hover:bg-slate-900 transition cursor-pointer relative group space-y-2`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center space-x-3">
                  {/* Layer Number Pill */}
                  <span className={`px-2.5 py-1 rounded text-xs font-bold ${layer.badgeBg} ${layer.badgeText}`}>
                    Layer {layer.layer}: {layer.name}
                  </span>

                  {/* PDU Type */}
                  <span className="bg-slate-900 border border-slate-700 px-2 py-0.5 rounded text-[10px] text-slate-300 font-bold">
                    PDU: {layer.pdu}
                  </span>
                </div>

                {/* Protocol Badges */}
                <div className="flex items-center space-x-1.5">
                  {layer.protocols.map((p) => (
                    <span key={p} className="bg-slate-900 text-slate-300 border border-slate-800 px-2 py-0.5 rounded text-[10px]">
                      {p}
                    </span>
                  ))}
                </div>
              </div>

              {/* Data Flow Indicator / Payload Envelope Box */}
              <div className="p-2 bg-black/60 rounded border border-slate-800/80 flex items-center justify-between text-[11px] text-slate-300">
                <div className="flex items-center space-x-2">
                  <span className="text-slate-500 font-bold">Header Overhead:</span>
                  <span className="text-emerald-400 font-bold">
                    {layer.layer === 7 ? '0 Bytes (Raw Data)' : layer.layer === 4 ? '+20 Bytes (TCP Header)' : layer.layer === 3 ? '+20 Bytes (IPv4 Header)' : layer.layer === 2 ? '+14 Bytes (Ethernet II Frame)' : '+4 Bytes (Preamble & PHY)'}
                  </span>
                </div>

                <div className="text-right">
                  <span className="text-slate-400">Current Speed: </span>
                  <span className="font-bold text-slate-200">{formatSpeed(layer.rxSpeed + layer.txSpeed)}</span>
                </div>
              </div>

              {/* Connector Arrow between steps */}
              {index < orderedLayers.length - 1 && (
                <div className="flex justify-center -mb-2 pt-1 opacity-60">
                  {direction === 'ENCAPSULATION' ? (
                    <ArrowDown className="h-4 w-4 text-emerald-400 animate-bounce" />
                  ) : (
                    <ArrowUp className="h-4 w-4 text-sky-400 animate-bounce" />
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
