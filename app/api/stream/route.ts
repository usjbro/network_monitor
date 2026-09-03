import { buildStreamResponse } from '@/lib/stream-response';

export async function GET(request: Request) {
  return buildStreamResponse({ request });
}
