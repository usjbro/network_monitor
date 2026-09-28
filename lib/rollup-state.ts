import { Conversation, Endpoint, NetworkConnection } from './types';

export interface RollupEnrichmentEvent {
  remoteAddr: string;
  remoteHostname?: string;
  enrichment: NetworkConnection['enrichment'];
}

export function mergeEndpointSnapshot(previous: Endpoint[], incoming: Endpoint[]): Endpoint[] {
  const previousByHost = new Map(previous.map((endpoint) => [endpoint.host, endpoint]));
  return incoming.map((endpoint) => {
    const old = previousByHost.get(endpoint.host);
    return {
      ...endpoint,
      remoteHostname: endpoint.remoteHostname ?? old?.remoteHostname,
      enrichment: endpoint.enrichment ?? old?.enrichment,
    };
  });
}

export function mergeConversationSnapshot(previous: Conversation[], incoming: Conversation[]): Conversation[] {
  const previousByPair = new Map(
    previous.map((conversation) => [`${conversation.localAddr}|${conversation.remoteAddr}`, conversation]),
  );
  return incoming.map((conversation) => {
    const old = previousByPair.get(`${conversation.localAddr}|${conversation.remoteAddr}`);
    return {
      ...conversation,
      remoteHostname: conversation.remoteHostname ?? old?.remoteHostname,
      enrichment: conversation.enrichment ?? old?.enrichment,
    };
  });
}

export function applyEndpointEnrichment(
  endpoints: Endpoint[],
  event: RollupEnrichmentEvent,
): Endpoint[] {
  let changed = false;
  const next = endpoints.map((endpoint) => {
    if (endpoint.host !== event.remoteAddr) return endpoint;
    changed = true;
    return {
      ...endpoint,
      enrichment: event.enrichment,
      ...(event.remoteHostname ? { remoteHostname: event.remoteHostname } : {}),
    };
  });
  return changed ? next : endpoints;
}

export function applyConversationEnrichment(
  conversations: Conversation[],
  event: RollupEnrichmentEvent,
): Conversation[] {
  let changed = false;
  const next = conversations.map((conversation) => {
    if (conversation.remoteAddr !== event.remoteAddr) return conversation;
    changed = true;
    return {
      ...conversation,
      enrichment: event.enrichment,
      ...(event.remoteHostname ? { remoteHostname: event.remoteHostname } : {}),
    };
  });
  return changed ? next : conversations;
}
