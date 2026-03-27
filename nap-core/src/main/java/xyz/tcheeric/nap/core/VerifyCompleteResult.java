package xyz.tcheeric.nap.core;

/**
 * Sealed result type for NAP completion verification.
 */
public sealed interface VerifyCompleteResult {

    record Success(SessionRecord session) implements VerifyCompleteResult {
    }

    record Failure(NapErrorCode code, boolean retryable) implements VerifyCompleteResult {
    }

    static VerifyCompleteResult success(SessionRecord session) {
        return new Success(session);
    }

    static VerifyCompleteResult failure(NapErrorCode code) {
        return new Failure(code, code.isRetryable());
    }
}
