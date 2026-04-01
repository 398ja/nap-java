package xyz.tcheeric.nap.it;

import nostr.crypto.bech32.Bech32;
import nostr.crypto.bech32.Bech32Prefix;
import nostr.crypto.schnorr.Schnorr;
import org.junit.jupiter.api.Test;
import xyz.tcheeric.nap.client.NapProofBuilder;
import xyz.tcheeric.nap.core.AuthSuccessResponse;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.server.*;
import xyz.tcheeric.nap.server.store.InMemoryChallengeStore;
import xyz.tcheeric.nap.server.store.InMemorySessionStore;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end round-trip test: init -> proof -> verify using only Java components.
 */
class JavaNativeRoundTripTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final String AUTH_URL = "https://example.com/auth/complete";

    @Test
    void fullRoundTrip_issueChallenge_buildProof_verifyCompletion() throws Exception {
        // Arrange - fixed clock for deterministic timestamps
        long now = Instant.now().getEpochSecond();
        Clock fixedClock = Clock.fixed(Instant.ofEpochSecond(now), ZoneOffset.UTC);

        NapServer server = NapServer.create(NapServerOptions.builder()
                .challengeStore(new InMemoryChallengeStore())
                .sessionStore(new InMemorySessionStore())
                .aclResolver(new AllowAllAclResolver())
                .clock(fixedClock)
                .challengeTtlSeconds(60)
                .sessionTtlSeconds(3600)
                .build());

        // Arrange - generate ephemeral key pair
        byte[] privKey = new byte[32];
        new SecureRandom().nextBytes(privKey);
        String privKeyHex = HEX.formatHex(privKey);
        byte[] pubKey = Schnorr.genPubKey(privKey);
        String pubKeyHex = HEX.formatHex(pubKey);
        String npub = Bech32.toBech32(Bech32Prefix.NPUB, pubKeyHex);

        // Act - Issue challenge
        IssueChallengeResult challengeResult = server.issueChallenge(new IssueChallengeInput(npub, AUTH_URL));

        // Assert - challenge issued successfully
        assertThat(challengeResult).isInstanceOf(IssueChallengeResult.Success.class);
        var success = (IssueChallengeResult.Success) challengeResult;
        assertThat(success.value().challengeId()).isNotBlank();
        assertThat(success.value().challenge()).isNotBlank();
        assertThat(success.value().authUrl()).isEqualTo(AUTH_URL);
        assertThat(success.value().authMethod()).isEqualTo("POST");

        String challengeId = success.value().challengeId();
        String challenge = success.value().challenge();

        // Act - Build proof
        String bodyJson = "{\"challenge_id\":\"" + challengeId + "\"}";
        byte[] rawBody = bodyJson.getBytes(StandardCharsets.UTF_8);

        String authorization = new NapProofBuilder()
                .privateKey(privKeyHex)
                .pubkey(pubKeyHex)
                .url(AUTH_URL)
                .method("POST")
                .challenge(challenge)
                .challengeId(challengeId)
                .body(rawBody)
                .createdAt(now)
                .buildAuthorizationHeader();

        assertThat(authorization).startsWith("Nostr ");

        // Act - Verify completion
        VerifyCompletionOutcome outcome = server.verifyCompletion(
                new VerifyCompletionInput(authorization, "POST", AUTH_URL, rawBody));

        // Assert - verification succeeded
        assertThat(outcome).isInstanceOf(VerifyCompletionOutcome.Success.class);
        var verifySuccess = (VerifyCompletionOutcome.Success) outcome;
        SessionRecord session = verifySuccess.session();

        assertThat(session.principalPubkey()).isEqualTo(pubKeyHex);
        assertThat(session.principalNpub()).isEqualTo(npub);
        assertThat(session.sessionId()).isNotBlank();
        assertThat(session.accessToken()).isNotBlank();
        assertThat(session.challengeId()).isEqualTo(challengeId);

        // Act - Verify public response
        AuthSuccessResponse publicResponse = server.toPublicAuthSuccess(session);

        // Assert - public response fields
        assertThat(publicResponse.status()).isEqualTo("ok");
        assertThat(publicResponse.accessToken()).isEqualTo(session.accessToken());
        assertThat(publicResponse.tokenType()).isEqualTo("Bearer");
        assertThat(publicResponse.expiresAt()).isEqualTo(session.expiresAt());
        assertThat(publicResponse.principal().pubkey()).isEqualTo(pubKeyHex);
        assertThat(publicResponse.principal().npub()).isEqualTo(npub);
        assertThat(publicResponse.roles()).isNotNull();
        assertThat(publicResponse.permissions()).isNotNull();
    }
}
