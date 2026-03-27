package xyz.tcheeric.nap.server;

public record RedeemParams(String eventId, String sessionId, long now, long resultCacheUntil) {
}
