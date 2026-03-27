package xyz.tcheeric.nap.server;

import xyz.tcheeric.nap.core.AuthFailureResponse;
import xyz.tcheeric.nap.core.AuthSuccessResponse;
import xyz.tcheeric.nap.core.SessionRecord;

public interface NapServer {

    IssueChallengeResult issueChallenge(IssueChallengeInput input);

    VerifyCompletionOutcome verifyCompletion(VerifyCompletionInput input);

    AuthSuccessResponse toPublicAuthSuccess(SessionRecord session);

    PublicFailureResponse toPublicAuthFailure();

    record PublicFailureResponse(int status, AuthFailureResponse body) {
    }

    static NapServer create(NapServerOptions options) {
        return new DefaultNapServer(options);
    }
}
