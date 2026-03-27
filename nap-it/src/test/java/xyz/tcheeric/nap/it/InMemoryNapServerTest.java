package xyz.tcheeric.nap.it;

import nostr.crypto.bech32.Bech32;
import nostr.crypto.bech32.Bech32Prefix;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import xyz.tcheeric.nap.core.NapErrorCode;
import xyz.tcheeric.nap.server.*;
import xyz.tcheeric.nap.server.store.InMemoryChallengeStore;
import xyz.tcheeric.nap.server.store.InMemorySessionStore;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the NapServer with in-memory stores handles the challenge-response flow correctly.
 */
class InMemoryNapServerTest {

    private static final String TEST_PUBKEY_HEX = "a".repeat(64);
    private NapServer server;

    @BeforeEach
    void setUp() {
        server = NapServer.create(NapServerOptions.builder()
                .challengeStore(new InMemoryChallengeStore())
                .sessionStore(new InMemorySessionStore())
                .aclResolver(new AllowAllAclResolver())
                .challengeTtlSeconds(60)
                .sessionTtlSeconds(3600)
                .build());
    }

    // Issues a challenge for a valid npub and returns success
    @Test
    void issueChallenge_validNpub_returnsSuccess() {
        String npub = Bech32.toBech32(Bech32Prefix.NPUB, TEST_PUBKEY_HEX);

        var result = server.issueChallenge(new IssueChallengeInput(npub, "https://example.com/auth/complete"));

        assertThat(result).isInstanceOf(IssueChallengeResult.Success.class);
        var success = (IssueChallengeResult.Success) result;
        assertThat(success.value().challengeId()).isNotBlank();
        assertThat(success.value().challenge()).isNotBlank();
        assertThat(success.value().authUrl()).isEqualTo("https://example.com/auth/complete");
        assertThat(success.value().authMethod()).isEqualTo("POST");
    }

    // Returns failure for invalid npub format
    @Test
    void issueChallenge_invalidNpub_returnsFailure() {
        var result = server.issueChallenge(new IssueChallengeInput("invalid", "https://example.com/auth/complete"));

        assertThat(result).isInstanceOf(IssueChallengeResult.Failure.class);
        var failure = (IssueChallengeResult.Failure) result;
        assertThat(failure.code()).isEqualTo(NapErrorCode.NAP_INIT_INVALID_NPUB);
    }

    // Returns malformed request when raw body is not valid JSON
    @Test
    void verifyCompletion_malformedBody_returnsMalformed() {
        var result = server.verifyCompletion(new VerifyCompletionInput(
                "Nostr dGVzdA==", "POST", "https://example.com/auth/complete",
                "not json".getBytes()));

        assertThat(result).isInstanceOf(VerifyCompletionOutcome.MalformedRequest.class);
    }

    // Returns failure when no authorization header is provided
    @Test
    void verifyCompletion_noAuthHeader_returnsFailure() {
        String body = "{\"challenge_id\":\"test123\"}";
        var result = server.verifyCompletion(new VerifyCompletionInput(
                null, "POST", "https://example.com/auth/complete",
                body.getBytes()));

        assertThat(result).isInstanceOf(VerifyCompletionOutcome.Failure.class);
        var failure = (VerifyCompletionOutcome.Failure) result;
        assertThat(failure.code()).isEqualTo(NapErrorCode.NAP_COMPLETE_MISSING_AUTH_HEADER);
    }
}
