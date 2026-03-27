package xyz.tcheeric.nap.server;

import xyz.tcheeric.nap.core.NapErrorCode;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.core.VerifyCompleteResult;

public sealed interface VerifyCompletionOutcome {

    record Success(SessionRecord session) implements VerifyCompletionOutcome {
    }

    record Failure(NapErrorCode code, boolean retryable) implements VerifyCompletionOutcome {
    }

    record MalformedRequest() implements VerifyCompletionOutcome {
    }

    static VerifyCompletionOutcome success(SessionRecord session) {
        return new Success(session);
    }

    static VerifyCompletionOutcome failure(NapErrorCode code) {
        return new Failure(code, code.isRetryable());
    }

    static VerifyCompletionOutcome malformed() {
        return new MalformedRequest();
    }

    static VerifyCompletionOutcome fromResult(VerifyCompleteResult result) {
        return switch (result) {
            case VerifyCompleteResult.Success s -> success(s.session());
            case VerifyCompleteResult.Failure f -> failure(f.code());
        };
    }

    default boolean isSuccess() {
        return this instanceof Success;
    }
}
