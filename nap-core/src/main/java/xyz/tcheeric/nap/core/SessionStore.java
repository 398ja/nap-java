package xyz.tcheeric.nap.core;

import java.util.Optional;

public interface SessionStore {

    SessionRecord createForChallenge(SessionRecord record);

    Optional<SessionRecord> getBySessionId(String sessionId);

    Optional<SessionRecord> getByAccessToken(String accessToken);

    void revokeBySessionId(String sessionId, long nowUnix);

    int revokeByPrincipal(String pubkey, long nowUnix);

    /**
     * Advance the sliding window on an active session (spec 006). Updates
     * {@code lastActivityAt} and {@code expiresAt} atomically; leaves
     * {@code absoluteExpiryAt} untouched. No-op when the session is absent,
     * revoked, or past its absolute expiry.
     *
     * <p>The caller is responsible for clamping {@code newExpiresAt} to
     * {@code absoluteExpiryAt} — the store enforces no policy, only storage.
     *
     * @param sessionId            opaque session identifier (same value read from the cookie)
     * @param newLastActivityAt    unix-seconds; typically {@code now}
     * @param newExpiresAt         unix-seconds; typically {@code min(now + idleTtl, absoluteExpiryAt)}
     */
    void touch(String sessionId, long newLastActivityAt, long newExpiresAt);
}
