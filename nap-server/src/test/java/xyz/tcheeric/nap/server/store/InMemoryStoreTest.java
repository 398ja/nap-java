package xyz.tcheeric.nap.server.store;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import xyz.tcheeric.nap.core.AclRecord;
import xyz.tcheeric.nap.core.ChallengeRecord;
import xyz.tcheeric.nap.core.ChallengeState;
import xyz.tcheeric.nap.core.RedeemParams;
import xyz.tcheeric.nap.core.RedeemResult;
import xyz.tcheeric.nap.core.SessionRecord;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryStoreTest {

    // ------------------------------------------------------------------ shared helpers

    private static final long NOW = 1_700_000_000L;
    private static final long FUTURE = NOW + 3600;
    private static final long PAST = NOW - 3600;

    private static ChallengeRecord issuedChallenge(String id, long expiresAt) {
        return ChallengeRecord.issued(
                id, "challenge-" + id, "npub1test", "pubkey-abc",
                "https://auth.example.com", "nip98", NOW, expiresAt
        );
    }

    private static SessionRecord session(String sessionId, String challengeId, String pubkey) {
        return SessionRecord.create(
                sessionId, challengeId, "token-" + sessionId,
                "npub1test", pubkey,
                List.of("user"), List.of("read"),
                NOW, FUTURE
        );
    }

    private static RedeemParams redeemParams(long now) {
        return new RedeemParams("event-1", "session-1", now, now + 60);
    }

    // ================================================================== ChallengeStore

    @Nested
    class ChallengeStoreTests {

        private InMemoryChallengeStore store;

        @BeforeEach
        void setUp() {
            store = new InMemoryChallengeStore();
        }

        @Test
        void createAndGet_returnsStoredRecord() {
            // Arrange
            var record = issuedChallenge("c1", FUTURE);

            // Act
            store.create(record);
            var result = store.get("c1");

            // Assert
            assertThat(result).isPresent().contains(record);
        }

        @Test
        void get_returnsEmptyForUnknownId() {
            // Arrange — empty store

            // Act
            var result = store.get("nonexistent");

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        void redeem_returnsRedeemedAndTransitionsState() {
            // Arrange
            store.create(issuedChallenge("c1", FUTURE));

            // Act
            var result = store.redeem("c1", redeemParams(NOW));

            // Assert
            assertThat(result).isEqualTo(RedeemResult.REDEEMED);
            assertThat(store.get("c1")).isPresent()
                    .hasValueSatisfying(r -> assertThat(r.state()).isEqualTo(ChallengeState.REDEEMED));
        }

        @Test
        void redeem_returnsNotFoundForUnknownId() {
            // Arrange — empty store

            // Act
            var result = store.redeem("nonexistent", redeemParams(NOW));

            // Assert
            assertThat(result).isEqualTo(RedeemResult.NOT_FOUND);
        }

        @Test
        void redeem_returnsExpiredWhenChallengeExpired() {
            // Arrange
            store.create(issuedChallenge("c1", PAST));

            // Act
            var result = store.redeem("c1", redeemParams(NOW));

            // Assert
            assertThat(result).isEqualTo(RedeemResult.EXPIRED);
        }

        @Test
        void redeem_returnsAlreadyRedeemedOnSecondCall() {
            // Arrange
            store.create(issuedChallenge("c1", FUTURE));
            store.redeem("c1", redeemParams(NOW));

            // Act
            var result = store.redeem("c1", redeemParams(NOW));

            // Assert
            assertThat(result).isEqualTo(RedeemResult.ALREADY_REDEEMED);
        }

        @Test
        void markExpired_transitionsIssuedToExpired() {
            // Arrange
            store.create(issuedChallenge("c1", PAST));
            store.create(issuedChallenge("c2", FUTURE));

            // Act
            int count = store.markExpired(NOW);

            // Assert
            assertThat(count).isEqualTo(1);
            assertThat(store.get("c1")).isPresent()
                    .hasValueSatisfying(r -> assertThat(r.state()).isEqualTo(ChallengeState.EXPIRED));
            assertThat(store.get("c2")).isPresent()
                    .hasValueSatisfying(r -> assertThat(r.state()).isEqualTo(ChallengeState.ISSUED));
        }
    }

    // ================================================================== SessionStore

    @Nested
    class SessionStoreTests {

        private InMemorySessionStore store;

        @BeforeEach
        void setUp() {
            store = new InMemorySessionStore();
        }

        @Test
        void createForChallenge_returnsSameRecord() {
            // Arrange
            var record = session("s1", "c1", "pubkey-abc");

            // Act
            var result = store.createForChallenge(record);

            // Assert
            assertThat(result).isSameAs(record);
        }

        @Test
        void createForChallenge_idempotentReturnExistingOnDuplicateChallengeId() {
            // Arrange
            var first = session("s1", "c1", "pubkey-abc");
            var duplicate = session("s2", "c1", "pubkey-abc");
            store.createForChallenge(first);

            // Act
            var result = store.createForChallenge(duplicate);

            // Assert
            assertThat(result).isSameAs(first);
            assertThat(store.getBySessionId("s2")).isEmpty();
        }

        @Test
        void getBySessionId_returnsEmptyForRevoked() {
            // Arrange
            var record = session("s1", "c1", "pubkey-abc");
            store.createForChallenge(record);
            store.revokeBySessionId("s1", NOW);

            // Act
            var result = store.getBySessionId("s1");

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        void getByAccessToken_returnsActiveSession() {
            // Arrange
            var record = session("s1", "c1", "pubkey-abc");
            store.createForChallenge(record);

            // Act
            var result = store.getByAccessToken("token-s1");

            // Assert
            assertThat(result).isPresent().contains(record);
        }

        @Test
        void revokeBySessionId_setsRevokedAt() {
            // Arrange
            var record = session("s1", "c1", "pubkey-abc");
            store.createForChallenge(record);

            // Act
            store.revokeBySessionId("s1", NOW);

            // Assert — session is filtered out by getBySessionId and getByAccessToken
            assertThat(store.getBySessionId("s1")).isEmpty();
            assertThat(store.getByAccessToken("token-s1")).isEmpty();
        }

        @Test
        void revokeByPrincipal_revokesAllSessionsForPubkey() {
            // Arrange
            store.createForChallenge(session("s1", "c1", "pubkey-abc"));
            store.createForChallenge(session("s2", "c2", "pubkey-abc"));
            store.createForChallenge(session("s3", "c3", "pubkey-other"));

            // Act
            int count = store.revokeByPrincipal("pubkey-abc", NOW);

            // Assert
            assertThat(count).isEqualTo(2);
            assertThat(store.getBySessionId("s1")).isEmpty();
            assertThat(store.getBySessionId("s2")).isEmpty();
            assertThat(store.getBySessionId("s3")).isPresent();
        }
    }

    // ================================================================== AclStore

    @Nested
    class AclStoreTests {

        private InMemoryAclStore store;

        @BeforeEach
        void setUp() {
            store = new InMemoryAclStore();
        }

        @Test
        void createAndFind_returnsStoredRecord() {
            // Arrange
            var record = new AclRecord("app1", "pubkey-abc", "admin", false);

            // Act
            store.create(record);
            var result = store.findByPubkey("app1", "pubkey-abc");

            // Assert
            assertThat(result).isPresent().contains(record);
        }

        @Test
        void findByPubkey_returnsEmptyForUnknown() {
            // Arrange — empty store

            // Act
            var result = store.findByPubkey("app1", "unknown");

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        void create_duplicateIsNoOp() {
            // Arrange
            var first = new AclRecord("app1", "pubkey-abc", "admin", false);
            var duplicate = new AclRecord("app1", "pubkey-abc", "viewer", true);
            store.create(first);

            // Act
            store.create(duplicate);
            var result = store.findByPubkey("app1", "pubkey-abc");

            // Assert
            assertThat(result).isPresent().contains(first);
        }
    }
}
