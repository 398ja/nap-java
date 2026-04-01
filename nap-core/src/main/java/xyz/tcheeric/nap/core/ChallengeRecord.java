package xyz.tcheeric.nap.core;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record ChallengeRecord(
        String challengeId,
        String challenge,
        String npub,
        String pubkey,
        String authUrl,
        String authMethod,
        long issuedAt,
        long expiresAt,
        ChallengeState state,
        String redeemedEventId,
        String redeemedSessionId,
        Long resultCacheUntil
) {

    public static ChallengeRecord issued(
            String challengeId,
            String challenge,
            String npub,
            String pubkey,
            String authUrl,
            String authMethod,
            long issuedAt,
            long expiresAt
    ) {
        return new ChallengeRecord(
                challengeId, challenge, npub, pubkey, authUrl, authMethod,
                issuedAt, expiresAt, ChallengeState.ISSUED, null, null, null
        );
    }
}
