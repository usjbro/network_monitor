// The one AgentClient per relay process (one authenticated agent
// connection), shared by the App Router SSE stream and the Pages Router
// /api/tcp-samples route (KAN-129 plan P5). Those are separate bundles, so
// the instance lives on globalThis rather than in a module variable.
import { AgentClient } from './agent-client';

declare global {
  var __agentClient: AgentClient | undefined;
}

export function getAgentClient(): AgentClient {
  if (!global.__agentClient) {
    global.__agentClient = new AgentClient('127.0.0.1', 9990);
    global.__agentClient.start();
  }
  return global.__agentClient;
}
