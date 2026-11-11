// KAN-129: POST /api/tcp-samples. Behaviour and its rationale live in
// lib/tcp-samples-route.ts; a Pages API module may export only the handler
// and `config`.
import type { NextApiRequest, NextApiResponse } from 'next';
import { handleTcpSamples } from '@/lib/tcp-samples-route';

// The route reads and bounds the raw body itself (512 bytes).
export const config = { api: { bodyParser: false } };

export default function handler(req: NextApiRequest, res: NextApiResponse): Promise<void> {
  return handleTcpSamples(req, res);
}
