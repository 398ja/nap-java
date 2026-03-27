package xyz.tcheeric.nap.server;

public record VerifyCompletionInput(
        String authorization,
        String method,
        String url,
        byte[] rawBody
) {
}
