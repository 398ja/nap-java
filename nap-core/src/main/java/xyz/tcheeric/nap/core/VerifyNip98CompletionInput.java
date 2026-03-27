package xyz.tcheeric.nap.core;

public record VerifyNip98CompletionInput(
        String authorization,
        String method,
        String url,
        AuthCompleteRequest body,
        byte[] rawBody,
        long now,
        int maxClockSkewSeconds
) {

    public static final int DEFAULT_MAX_CLOCK_SKEW_SECONDS = 60;
}
