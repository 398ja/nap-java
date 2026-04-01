package xyz.tcheeric.nap.server;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Guards against replaying the same NIP-98 event across multiple completion attempts.
 */
@FunctionalInterface
public interface EventReplayGuard {

    boolean tryAcquire(String eventId);

    /**
     * Returns a no-op guard that accepts all events (no replay protection).
     */
    static EventReplayGuard noop() {
        return eventId -> true;
    }

    /**
     * Returns an in-memory guard that rejects replayed event IDs.
     * Suitable for single-instance deployments.
     */
    static EventReplayGuard inMemory() {
        ConcurrentHashMap<String, Boolean> seen = new ConcurrentHashMap<>();
        return eventId -> seen.putIfAbsent(eventId, Boolean.TRUE) == null;
    }
}
