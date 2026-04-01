package xyz.tcheeric.nap.core;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import java.util.List;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AuthSuccessResponse(
        String status,
        String accessToken,
        String tokenType,
        long expiresAt,
        Principal principal,
        List<String> roles,
        List<String> permissions
) {

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Principal(String npub, String pubkey) {
    }
}
