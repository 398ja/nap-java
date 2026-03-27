package xyz.tcheeric.nap.core;

import java.util.List;

public record AuthSuccessResponse(
        String accessToken,
        String tokenType,
        long expiresAt,
        Principal principal,
        List<String> roles,
        List<String> permissions
) {

    public record Principal(String npub, String pubkey) {
    }
}
