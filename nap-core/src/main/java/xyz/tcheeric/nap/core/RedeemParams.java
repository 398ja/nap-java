package xyz.tcheeric.nap.core;

public record RedeemParams(String eventId, String sessionId, long now, long resultCacheUntil) {
}
