package xyz.tcheeric.nap.server.store;

import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.server.SessionStore;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory SessionStore for testing and single-instance deployments.
 */
public final class InMemorySessionStore implements SessionStore {

    private final ConcurrentHashMap<String, SessionRecord> bySessionId = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, SessionRecord> byAccessToken = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, SessionRecord> byChallengeId = new ConcurrentHashMap<>();

    @Override
    public SessionRecord createForChallenge(SessionRecord record) {
        var existing = byChallengeId.putIfAbsent(record.challengeId(), record);
        if (existing != null) {
            return existing;
        }
        bySessionId.put(record.sessionId(), record);
        byAccessToken.put(record.accessToken(), record);
        return record;
    }

    @Override
    public Optional<SessionRecord> getBySessionId(String sessionId) {
        return Optional.ofNullable(bySessionId.get(sessionId))
                .filter(s -> s.revokedAt() == null);
    }

    @Override
    public Optional<SessionRecord> getByAccessToken(String accessToken) {
        return Optional.ofNullable(byAccessToken.get(accessToken))
                .filter(s -> s.revokedAt() == null);
    }

    @Override
    public void revokeBySessionId(String sessionId, long nowUnix) {
        bySessionId.computeIfPresent(sessionId, (key, existing) -> {
            if (existing.revokedAt() != null) return existing;
            var revoked = new SessionRecord(
                    existing.sessionId(), existing.challengeId(), existing.accessToken(),
                    existing.principalNpub(), existing.principalPubkey(),
                    existing.roles(), existing.permissions(),
                    existing.issuedAt(), existing.expiresAt(), nowUnix,
                    existing.stepUpToken(), existing.stepUpExpiresAt()
            );
            byAccessToken.put(existing.accessToken(), revoked);
            return revoked;
        });
    }

    @Override
    public int revokeByPrincipal(String pubkey, long nowUnix) {
        int count = 0;
        for (var entry : bySessionId.entrySet()) {
            if (pubkey.equals(entry.getValue().principalPubkey()) && entry.getValue().revokedAt() == null) {
                revokeBySessionId(entry.getKey(), nowUnix);
                count++;
            }
        }
        return count;
    }

    public void clear() {
        bySessionId.clear();
        byAccessToken.clear();
        byChallengeId.clear();
    }
}
