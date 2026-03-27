package xyz.tcheeric.nap.core;

public record AuthInitResponse(
        String challengeId,
        String challenge,
        String authUrl,
        String authMethod,
        long issuedAt,
        long expiresAt
) {
}
