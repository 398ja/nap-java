package xyz.tcheeric.nap.server;

import xyz.tcheeric.nap.core.AuthInitResponse;
import xyz.tcheeric.nap.core.NapErrorCode;

public sealed interface IssueChallengeResult {

    record Success(AuthInitResponse value) implements IssueChallengeResult {
    }

    record Failure(NapErrorCode code, boolean retryable) implements IssueChallengeResult {
    }

    default boolean isSuccess() {
        return this instanceof Success;
    }
}
