package xyz.tcheeric.nap.core;

import java.util.List;

public record SessionRecord(
        String sessionId,
        String challengeId,
        String accessToken,
        String principalNpub,
        String principalPubkey,
        List<String> roles,
        List<String> permissions,
        long issuedAt,
        long expiresAt,
        Long revokedAt,
        String stepUpToken,
        Long stepUpExpiresAt
) {

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
        return new SessionRecord(
                sessionId, challengeId, accessToken, principalNpub, principalPubkey,
                roles, permissions, issuedAt, expiresAt, null, null, null
        );
    }
}
