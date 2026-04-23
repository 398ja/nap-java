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
        long absoluteExpiryAt,
        Principal principal,
        List<String> roles,
        List<String> permissions
) {

    /**
     * Back-compat constructor — pre-006 callers didn't supply {@code absoluteExpiryAt};
     * default it to {@code expiresAt} (no sliding).
     */
    public AuthSuccessResponse(String status, String accessToken, String tokenType, long expiresAt,
                               Principal principal, List<String> roles, List<String> permissions) {
        this(status, accessToken, tokenType, expiresAt, expiresAt, principal, roles, permissions);
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Principal(String npub, String pubkey) {
    }
}
