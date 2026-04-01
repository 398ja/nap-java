package xyz.tcheeric.nap.core;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AuthInitResponse(
        String challengeId,
        String challenge,
        String authUrl,
        String authMethod,
        long issuedAt,
        long expiresAt
) {
}
