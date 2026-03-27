package xyz.tcheeric.nap.core;

public enum ChallengeState {
    ISSUED,
    REDEEMED,
    EXPIRED,
    FAILED_TERMINAL;

    public String toWireValue() {
        return name().toLowerCase();
    }

    public static ChallengeState fromWireValue(String value) {
        return valueOf(value.toUpperCase());
    }
}
