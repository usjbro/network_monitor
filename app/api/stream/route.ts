import { buildStreamResponse } from '@/lib/stream-response';

export async function GET() {
  return buildStreamResponse();
}
