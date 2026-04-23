package xyz.tcheeric.nap.core;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import java.util.List;

/**
 * NAP session record.
 *
 * <p><b>Sliding-window fields (spec 006):</b>
 * <ul>
 *   <li>{@code issuedAt} — immutable creation time.</li>
 *   <li>{@code lastActivityAt} — timestamp of the most recent {@link SessionStore#touch touch}.
 *       Starts equal to {@code issuedAt}; advanced on every authenticated request.</li>
 *   <li>{@code expiresAt} — the effective (sliding) expiry: capped at {@code absoluteExpiryAt}
 *       and advanced by {@code touch} up to that cap. A filter may treat {@code expiresAt <= now}
 *       as "session ended".</li>
 *   <li>{@code absoluteExpiryAt} — immutable hard cap on the session's total lifetime.</li>
 * </ul>
 * For pre-006 call sites that only know {@code issuedAt}/{@code expiresAt}, the
 * {@link #create(String, String, String, String, String, List, List, long, long)} factory
 * defaults {@code lastActivityAt = issuedAt} and {@code absoluteExpiryAt = expiresAt},
 * giving a non-sliding session.
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record SessionRecord(
        String sessionId,
        String challengeId,
        String accessToken,
        String principalNpub,
        String principalPubkey,
        List<String> roles,
        List<String> permissions,
        long issuedAt,
        long lastActivityAt,
        long expiresAt,
        long absoluteExpiryAt,
        Long revokedAt,
        String stepUpToken,
        Long stepUpExpiresAt
) {

    /**
     * Create a session with explicit sliding-window fields (spec 006).
     */
    public static SessionRecord create(
            String sessionId,
            String challengeId,
            String accessToken,
            String principalNpub,
            String principalPubkey,
            List<String> roles,
            List<String> permissions,
            long issuedAt,
            long lastActivityAt,
            long expiresAt,
            long absoluteExpiryAt
    ) {
        return new SessionRecord(
                sessionId, challengeId, accessToken, principalNpub, principalPubkey,
                roles, permissions, issuedAt, lastActivityAt, expiresAt, absoluteExpiryAt,
                null, null, null
        );
    }

    /**
     * Back-compat factory for callers that only know {@code issuedAt}/{@code expiresAt}.
     * Defaults {@code lastActivityAt = issuedAt} and {@code absoluteExpiryAt = expiresAt},
     * producing a non-sliding session equivalent to the pre-006 shape.
     */
    public static SessionRecord create(
            String sessionId,
            String challengeId,
            String accessToken,
            String principalNpub,
            String principalPubkey,
            List<String> roles,
            List<String> permissions,
            long issuedAt,
            long expiresAt
    ) {
        return create(
                sessionId, challengeId, accessToken, principalNpub, principalPubkey,
                roles, permissions, issuedAt, issuedAt, expiresAt, expiresAt
        );
    }

    /**
     * Whether the session is still usable at {@code now} under sliding semantics:
     * not revoked, and both the effective (sliding) expiry and the absolute cap
     * are in the future.
     */
    public boolean isActive(long now) {
        return revokedAt == null && expiresAt > now && absoluteExpiryAt > now;
    }
}
