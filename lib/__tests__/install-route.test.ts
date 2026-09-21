// Coverage for /api/install — the generated bash installer script's
// response shape and its host-derived origin substitution.
import { describe, expect, it } from 'vitest';
import type { NextRequest } from 'next/server';
import { GET } from '@/app/api/install/route';

function req(headers: Record<string, string> = {}): NextRequest {
  return { headers: new Headers(headers) } as unknown as NextRequest;
}

describe('GET /api/install', () => {
  it('serves the script as inline text/plain', async () => {
    const res = await GET(req({ host: 'localhost:3000' }));

    expect(res.headers.get('Content-Type')).toBe('text/plain; charset=utf-8');
    expect(res.headers.get('Content-Disposition')).toBe('inline; filename="install.sh"');
  });

  it('embeds an http origin for a localhost host header', async () => {
    const res = await GET(req({ host: 'localhost:3000' }));
    const body = await res.text();

    expect(body).toContain('SERVER_URL = "http://localhost:3000"');
  });

  it('embeds an https origin for a non-localhost host header', async () => {
    const res = await GET(req({ host: 'example.com' }));
    const body = await res.text();

    expect(body).toContain('SERVER_URL = "https://example.com"');
  });

  it('falls back to localhost:3000 over http when no host header is present', async () => {
    const res = await GET(req());
    const body = await res.text();

    expect(body).toContain('SERVER_URL = "http://localhost:3000"');
  });

  it('produces a well-formed bash script', async () => {
    const res = await GET(req({ host: 'localhost:3000' }));
    const body = await res.text();

    expect(body.startsWith('#!/bin/bash')).toBe(true);
    expect(body).toContain('set -e');
  });
});
