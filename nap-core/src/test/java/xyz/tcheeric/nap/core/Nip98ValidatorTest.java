package xyz.tcheeric.nap.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import nostr.crypto.schnorr.Schnorr;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class Nip98ValidatorTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String TEST_URL = "https://example.com/api/auth/complete";
    private static final String TEST_METHOD = "POST";
    private static final String TEST_CHALLENGE = "random-challenge-string";
    private static final String TEST_CHALLENGE_ID = "challenge-id-123";
    private static final byte[] TEST_BODY = "{\"challenge_id\":\"challenge-id-123\"}".getBytes(StandardCharsets.UTF_8);

    // ── Helper to build a fully valid NIP-98 event ──────────────────────────

    /**
     * Builds a valid NIP-98 Authorization header value using real Schnorr signatures.
     * Individual tests override specific fields to trigger validation failures.
     */
    private static TestEvent buildValidEvent() throws Exception {
        byte[] privKey = new byte[32];
        RANDOM.nextBytes(privKey);
        byte[] pubKeyBytes = Schnorr.genPubKey(privKey);
        String pubkeyHex = HEX.formatHex(pubKeyBytes);

        long createdAt = Instant.now().getEpochSecond();
        String payloadHash = sha256Hex(TEST_BODY);

        ArrayNode tags = MAPPER.createArrayNode();
        tags.add(MAPPER.createArrayNode().add("u").add(TEST_URL));
        tags.add(MAPPER.createArrayNode().add("method").add(TEST_METHOD));
        tags.add(MAPPER.createArrayNode().add("payload").add(payloadHash));
        tags.add(MAPPER.createArrayNode().add("challenge").add(TEST_CHALLENGE));
        tags.add(MAPPER.createArrayNode().add("challenge_id").add(TEST_CHALLENGE_ID));

        ArrayNode serialized = MAPPER.createArrayNode();
        serialized.add(0);
        serialized.add(pubkeyHex);
        serialized.add(createdAt);
        serialized.add(27235);
        serialized.add(tags);
        serialized.add("");

        byte[] eventIdBytes = sha256(MAPPER.writeValueAsString(serialized).getBytes(StandardCharsets.UTF_8));
        String eventId = HEX.formatHex(eventIdBytes);

        byte[] auxRand = new byte[32];
        RANDOM.nextBytes(auxRand);
        byte[] signature = Schnorr.sign(eventIdBytes, privKey, auxRand);
        String sig = HEX.formatHex(signature);

        ObjectNode event = MAPPER.createObjectNode();
        event.put("id", eventId);
        event.put("pubkey", pubkeyHex);
        event.put("created_at", createdAt);
        event.put("kind", 27235);
        event.set("tags", tags);
        event.put("content", "");
        event.put("sig", sig);

        String eventJson = MAPPER.writeValueAsString(event);
        String authHeader = "Nostr " + Base64.getEncoder().encodeToString(eventJson.getBytes(StandardCharsets.UTF_8));

        return new TestEvent(authHeader, createdAt, privKey, pubkeyHex, eventJson, event);
    }

    /**
     * Encodes an ObjectNode as a Nostr Authorization header.
     */
    private static String toAuthHeader(ObjectNode event) throws Exception {
        String json = MAPPER.writeValueAsString(event);
        return "Nostr " + Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static VerifyNip98CompletionInput defaultInput(String authHeader, long now) {
        return new VerifyNip98CompletionInput(
                authHeader, TEST_METHOD, TEST_URL,
                new AuthCompleteRequest(TEST_CHALLENGE_ID),
                TEST_BODY, now, 60
        );
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    private static String sha256Hex(byte[] data) throws Exception {
        return HEX.formatHex(sha256(data));
    }

    record TestEvent(String authHeader, long createdAt, byte[] privKey,
                     String pubkeyHex, String eventJson, ObjectNode eventNode) {}

    // ── verifyNip98Completion tests ─────────────────────────────────────────

    @Nested
    @DisplayName("verifyNip98Completion")
    class VerifyNip98CompletionTests {

        @Test
        @DisplayName("null authorization returns MISSING_AUTH_HEADER")
        void nullAuthorization() {
            // Arrange
            var input = new VerifyNip98CompletionInput(
                    null, TEST_METHOD, TEST_URL,
                    new AuthCompleteRequest(TEST_CHALLENGE_ID), TEST_BODY,
                    Instant.now().getEpochSecond(), 60
            );

            // Act
            var result = Nip98Validator.verifyNip98Completion(input);

            // Assert
            assertThat(result).isInstanceOf(Nip98Validator.Nip98ValidationResult.Failure.class);
            var failure = (Nip98Validator.Nip98ValidationResult.Failure) result;
            assertThat(failure.code()).isEqualTo(NapErrorCode.NAP_COMPLETE_MISSING_AUTH_HEADER);
        }

        @Test
        @DisplayName("blank authorization returns MISSING_AUTH_HEADER")
        void blankAuthorization() {
            // Arrange
            var input = new VerifyNip98CompletionInput(
                    "   ", TEST_METHOD, TEST_URL,
                    new AuthCompleteRequest(TEST_CHALLENGE_ID), TEST_BODY,
                    Instant.now().getEpochSecond(), 60
            );

            // Act
            var result = Nip98Validator.verifyNip98Completion(input);

            // Assert
            assertThat(result).isInstanceOf(Nip98Validator.Nip98ValidationResult.Failure.class);
            var failure = (Nip98Validator.Nip98ValidationResult.Failure) result;
            assertThat(failure.code()).isEqualTo(NapErrorCode.NAP_COMPLETE_MISSING_AUTH_HEADER);
        }

        @Test
        @DisplayName("wrong prefix returns INVALID_AUTH_SCHEME")
        void wrongPrefix() {
            // Arrange
            var input = new VerifyNip98CompletionInput(
                    "Bearer abc123", TEST_METHOD, TEST_URL,
                    new AuthCompleteRequest(TEST_CHALLENGE_ID), TEST_BODY,
                    Instant.now().getEpochSecond(), 60
            );

            // Act
            var result = Nip98Validator.verifyNip98Completion(input);

            // Assert
            assertThat(result).isInstanceOf(Nip98Validator.Nip98ValidationResult.Failure.class);
            var failure = (Nip98Validator.Nip98ValidationResult.Failure) result;
            assertThat(failure.code()).isEqualTo(NapErrorCode.NAP_COMPLETE_INVALID_AUTH_SCHEME);
        }

        @Test
        @DisplayName("invalid base64 returns INVALID_EVENT_JSON")
        void invalidBase64() {
            // Arrange
            var input = new VerifyNip98CompletionInput(
                    "Nostr !!!not-base64!!!", TEST_METHOD, TEST_URL,
                    new AuthCompleteRequest(TEST_CHALLENGE_ID), TEST_BODY,
                    Instant.now().getEpochSecond(), 60
            );

            // Act
            var result = Nip98Validator.verifyNip98Completion(input);

            // Assert
            assertThat(result).isInstanceOf(Nip98Validator.Nip98ValidationResult.Failure.class);
            var failure = (Nip98Validator.Nip98ValidationResult.Failure) result;
            assertThat(failure.code()).isEqualTo(NapErrorCode.NAP_COMPLETE_INVALID_EVENT_JSON);
        }

        @Test
        @DisplayName("invalid JSON returns INVALID_EVENT_JSON")
        void invalidJson() {
            // Arrange
            String invalidJson = Base64.getEncoder().encodeToString("not json".getBytes(StandardCharsets.UTF_8));
            var input = new VerifyNip98CompletionInput(
                    "Nostr " + invalidJson, TEST_METHOD, TEST_URL,
                    new AuthCompleteRequest(TEST_CHALLENGE_ID), TEST_BODY,
                    Instant.now().getEpochSecond(), 60
            );

            // Act
            var result = Nip98Validator.verifyNip98Completion(input);

            // Assert
            assertThat(result).isInstanceOf(Nip98Validator.Nip98ValidationResult.Failure.class);
            var failure = (Nip98Validator.Nip98ValidationResult.Failure) result;
            assertThat(failure.code()).isEqualTo(NapErrorCode.NAP_COMPLETE_INVALID_EVENT_JSON);
        }

        @Test
        @DisplayName("wrong kind returns INVALID_KIND")
        void wrongKind() throws Exception {
            // Arrange
            TestEvent valid = buildValidEvent();
            ObjectNode tampered = valid.eventNode().deepCopy();
            tampered.put("kind", 1);
            var input = defaultInput(toAuthHeader(tampered), valid.createdAt());

            // Act
            var result = Nip98Validator.verifyNip98Completion(input);

            // Assert
            assertThat(result).isInstanceOf(Nip98Validator.Nip98ValidationResult.Failure.class);
            var failure = (Nip98Validator.Nip98ValidationResult.Failure) result;
            assertThat(failure.code()).isEqualTo(NapErrorCode.NAP_COMPLETE_INVALID_KIND);
        }

        @Test
        @DisplayName("non-empty content returns INVALID_EVENT_JSON")
        void nonEmptyContent() throws Exception {
            // Arrange
            TestEvent valid = buildValidEvent();
            ObjectNode tampered = valid.eventNode().deepCopy();
            tampered.put("content", "hello");
            var input = defaultInput(toAuthHeader(tampered), valid.createdAt());

            // Act
            var result = Nip98Validator.verifyNip98Completion(input);

            // Assert
            assertThat(result).isInstanceOf(Nip98Validator.Nip98ValidationResult.Failure.class);
            var failure = (Nip98Validator.Nip98ValidationResult.Failure) result;
            assertThat(failure.code()).isEqualTo(NapErrorCode.NAP_COMPLETE_INVALID_EVENT_JSON);
        }

        @Test
        @DisplayName("invalid signature returns INVALID_SIGNATURE")
        void invalidSignature() throws Exception {
            // Arrange
            TestEvent valid = buildValidEvent();
            ObjectNode tampered = valid.eventNode().deepCopy();
            // Replace sig with all zeros (invalid)
            tampered.put("sig", "00".repeat(64));
            var input = defaultInput(toAuthHeader(tampered), valid.createdAt());

            // Act
            var result = Nip98Validator.verifyNip98Completion(input);

            // Assert
            assertThat(result).isInstanceOf(Nip98Validator.Nip98ValidationResult.Failure.class);
            var failure = (Nip98Validator.Nip98ValidationResult.Failure) result;
            assertThat(failure.code()).isEqualTo(NapErrorCode.NAP_COMPLETE_INVALID_SIGNATURE);
        }

        @Test
        @DisplayName("created_at too far in the past returns CREATED_AT_OUT_OF_RANGE")
        void createdAtOutOfRange() throws Exception {
            // Arrange
            TestEvent valid = buildValidEvent();
            // now is 200 seconds after the event was created, exceeding the 60-second skew
            long futureNow = valid.createdAt() + 200;
            var input = defaultInput(valid.authHeader(), futureNow);

            // Act
            var result = Nip98Validator.verifyNip98Completion(input);

            // Assert
            assertThat(result).isInstanceOf(Nip98Validator.Nip98ValidationResult.Failure.class);
            var failure = (Nip98Validator.Nip98ValidationResult.Failure) result;
            assertThat(failure.code()).isEqualTo(NapErrorCode.NAP_COMPLETE_CREATED_AT_OUT_OF_RANGE);
            assertThat(failure.retryable()).isTrue();
        }

        @Test
        @DisplayName("URL mismatch returns URL_MISMATCH")
        void urlMismatch() throws Exception {
            // Arrange
            TestEvent valid = buildValidEvent();
            var input = new VerifyNip98CompletionInput(
                    valid.authHeader(), TEST_METHOD, "https://other.com/different/path",
                    new AuthCompleteRequest(TEST_CHALLENGE_ID), TEST_BODY,
                    valid.createdAt(), 60
            );

            // Act
            var result = Nip98Validator.verifyNip98Completion(input);

            // Assert
            assertThat(result).isInstanceOf(Nip98Validator.Nip98ValidationResult.Failure.class);
            var failure = (Nip98Validator.Nip98ValidationResult.Failure) result;
            assertThat(failure.code()).isEqualTo(NapErrorCode.NAP_COMPLETE_URL_MISMATCH);
        }

        @Test
        @DisplayName("method mismatch returns METHOD_MISMATCH")
        void methodMismatch() throws Exception {
            // Arrange
            TestEvent valid = buildValidEvent();
            var input = new VerifyNip98CompletionInput(
                    valid.authHeader(), "GET", TEST_URL,
                    new AuthCompleteRequest(TEST_CHALLENGE_ID), TEST_BODY,
                    valid.createdAt(), 60
            );

            // Act
            var result = Nip98Validator.verifyNip98Completion(input);

            // Assert
            assertThat(result).isInstanceOf(Nip98Validator.Nip98ValidationResult.Failure.class);
            var failure = (Nip98Validator.Nip98ValidationResult.Failure) result;
            assertThat(failure.code()).isEqualTo(NapErrorCode.NAP_COMPLETE_METHOD_MISMATCH);
        }

        @Test
        @DisplayName("payload hash mismatch returns PAYLOAD_MISMATCH")
        void payloadMismatch() throws Exception {
            // Arrange
            TestEvent valid = buildValidEvent();
            byte[] differentBody = "{\"different\":\"body\"}".getBytes(StandardCharsets.UTF_8);
            var input = new VerifyNip98CompletionInput(
                    valid.authHeader(), TEST_METHOD, TEST_URL,
                    new AuthCompleteRequest(TEST_CHALLENGE_ID), differentBody,
                    valid.createdAt(), 60
            );

            // Act
            var result = Nip98Validator.verifyNip98Completion(input);

            // Assert
            assertThat(result).isInstanceOf(Nip98Validator.Nip98ValidationResult.Failure.class);
            var failure = (Nip98Validator.Nip98ValidationResult.Failure) result;
            assertThat(failure.code()).isEqualTo(NapErrorCode.NAP_COMPLETE_PAYLOAD_MISMATCH);
        }

        @Test
        @DisplayName("missing challenge_id tag returns MISSING_CHALLENGE_ID")
        void missingChallengeIdTag() throws Exception {
            // Arrange: build event without challenge_id tag
            byte[] privKey = new byte[32];
            RANDOM.nextBytes(privKey);
            byte[] pubKeyBytes = Schnorr.genPubKey(privKey);
            String pubkeyHex = HEX.formatHex(pubKeyBytes);
            long createdAt = Instant.now().getEpochSecond();
            String payloadHash = sha256Hex(TEST_BODY);

            ArrayNode tags = MAPPER.createArrayNode();
            tags.add(MAPPER.createArrayNode().add("u").add(TEST_URL));
            tags.add(MAPPER.createArrayNode().add("method").add(TEST_METHOD));
            tags.add(MAPPER.createArrayNode().add("payload").add(payloadHash));
            tags.add(MAPPER.createArrayNode().add("challenge").add(TEST_CHALLENGE));
            // Deliberately omitting challenge_id tag

            ArrayNode serialized = MAPPER.createArrayNode();
            serialized.add(0);
            serialized.add(pubkeyHex);
            serialized.add(createdAt);
            serialized.add(27235);
            serialized.add(tags);
            serialized.add("");

            byte[] eventIdBytes = sha256(MAPPER.writeValueAsString(serialized).getBytes(StandardCharsets.UTF_8));
            String eventId = HEX.formatHex(eventIdBytes);

            byte[] auxRand = new byte[32];
            RANDOM.nextBytes(auxRand);
            byte[] signature = Schnorr.sign(eventIdBytes, privKey, auxRand);
            String sig = HEX.formatHex(signature);

            ObjectNode event = MAPPER.createObjectNode();
            event.put("id", eventId);
            event.put("pubkey", pubkeyHex);
            event.put("created_at", createdAt);
            event.put("kind", 27235);
            event.set("tags", tags);
            event.put("content", "");
            event.put("sig", sig);

            String authHeader = toAuthHeader(event);
            var input = defaultInput(authHeader, createdAt);

            // Act
            var result = Nip98Validator.verifyNip98Completion(input);

            // Assert
            assertThat(result).isInstanceOf(Nip98Validator.Nip98ValidationResult.Failure.class);
            var failure = (Nip98Validator.Nip98ValidationResult.Failure) result;
            assertThat(failure.code()).isEqualTo(NapErrorCode.NAP_COMPLETE_MISSING_CHALLENGE_ID);
        }

        @Test
        @DisplayName("valid event returns Success with extracted fields")
        void validEventReturnsSuccess() throws Exception {
            // Arrange
            TestEvent valid = buildValidEvent();
            var input = defaultInput(valid.authHeader(), valid.createdAt());

            // Act
            var result = Nip98Validator.verifyNip98Completion(input);

            // Assert
            assertThat(result).isInstanceOf(Nip98Validator.Nip98ValidationResult.Success.class);
            assertThat(result.isSuccess()).isTrue();
            var success = (Nip98Validator.Nip98ValidationResult.Success) result;
            assertThat(success.value().challenge()).isEqualTo(TEST_CHALLENGE);
            assertThat(success.value().challengeId()).isEqualTo(TEST_CHALLENGE_ID);
            assertThat(success.value().payload()).isEqualTo(sha256Hex(TEST_BODY));
            assertThat(success.value().event()).isNotNull();
            assertThat(success.value().event().pubkey()).isEqualTo(valid.pubkeyHex());
        }
    }

    // ── validateChallengeBoundCreatedAt tests ───────────────────────────────

    @Nested
    @DisplayName("validateChallengeBoundCreatedAt")
    class ValidateChallengeBoundCreatedAtTests {

        @Test
        @DisplayName("created_at within window returns true")
        void withinWindow() {
            // Arrange
            long issuedAt = 1000;
            long expiresAt = 2000;
            long createdAt = 1500;

            // Act
            boolean result = Nip98Validator.validateChallengeBoundCreatedAt(createdAt, issuedAt, expiresAt, 10, 10);

            // Assert
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("created_at before lower bound returns false")
        void beforeLowerBound() {
            // Arrange
            long issuedAt = 1000;
            long expiresAt = 2000;
            long createdAt = 980; // issuedAt - 10 grace = 990, so 980 is before

            // Act
            boolean result = Nip98Validator.validateChallengeBoundCreatedAt(createdAt, issuedAt, expiresAt, 10, 10);

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("created_at after upper bound returns false")
        void afterUpperBound() {
            // Arrange
            long issuedAt = 1000;
            long expiresAt = 2000;
            long createdAt = 2020; // expiresAt + 10 grace = 2010, so 2020 is after

            // Act
            boolean result = Nip98Validator.validateChallengeBoundCreatedAt(createdAt, issuedAt, expiresAt, 10, 10);

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("created_at at exact lower boundary returns true")
        void atExactLowerBoundary() {
            // Arrange
            long issuedAt = 1000;
            long expiresAt = 2000;
            long createdAt = 990; // exactly issuedAt - grace

            // Act
            boolean result = Nip98Validator.validateChallengeBoundCreatedAt(createdAt, issuedAt, expiresAt, 10, 10);

            // Assert
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("created_at at exact upper boundary returns true")
        void atExactUpperBoundary() {
            // Arrange
            long issuedAt = 1000;
            long expiresAt = 2000;
            long createdAt = 2010; // exactly expiresAt + grace

            // Act
            boolean result = Nip98Validator.validateChallengeBoundCreatedAt(createdAt, issuedAt, expiresAt, 10, 10);

            // Assert
            assertThat(result).isTrue();
        }
    }

    // ── parseNostrAuthorizationHeader tests ─────────────────────────────────

    @Nested
    @DisplayName("parseNostrAuthorizationHeader")
    class ParseNostrAuthorizationHeaderTests {

        @Test
        @DisplayName("valid header returns parsed event")
        void validHeader() throws Exception {
            // Arrange
            TestEvent valid = buildValidEvent();

            // Act
            Nip98Event event = Nip98Validator.parseNostrAuthorizationHeader(valid.authHeader());

            // Assert
            assertThat(event).isNotNull();
            assertThat(event.kind()).isEqualTo(27235);
            assertThat(event.content()).isEmpty();
            assertThat(event.pubkey()).isEqualTo(valid.pubkeyHex());
            assertThat(event.tags()).hasSize(5);
        }

        @Test
        @DisplayName("garbage base64 returns null")
        void garbageBase64() {
            // Arrange / Act
            Nip98Event event = Nip98Validator.parseNostrAuthorizationHeader("Nostr !!!invalid!!!");

            // Assert
            assertThat(event).isNull();
        }

        @Test
        @DisplayName("JSON missing required fields returns null")
        void missingFields() {
            // Arrange
            String json = "{\"kind\": 27235}";
            String header = "Nostr " + Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));

            // Act
            Nip98Event event = Nip98Validator.parseNostrAuthorizationHeader(header);

            // Assert
            assertThat(event).isNull();
        }
    }

    // ── getSingleTag tests ──────────────────────────────────────────────────

    @Nested
    @DisplayName("getSingleTag")
    class GetSingleTagTests {

        @Test
        @DisplayName("returns value for tag present exactly once")
        void singleMatch() {
            // Arrange
            Nip98Event event = new Nip98Event("id", "pk", 0, 27235,
                    List.of(List.of("u", "https://example.com"), List.of("method", "POST")),
                    "", "sig");

            // Act
            String value = Nip98Validator.getSingleTag(event, "u");

            // Assert
            assertThat(value).isEqualTo("https://example.com");
        }

        @Test
        @DisplayName("returns null when tag is missing")
        void missingTag() {
            // Arrange
            Nip98Event event = new Nip98Event("id", "pk", 0, 27235,
                    List.of(List.of("u", "https://example.com")),
                    "", "sig");

            // Act
            String value = Nip98Validator.getSingleTag(event, "method");

            // Assert
            assertThat(value).isNull();
        }

        @Test
        @DisplayName("returns null when tag appears more than once")
        void duplicateTag() {
            // Arrange
            Nip98Event event = new Nip98Event("id", "pk", 0, 27235,
                    List.of(List.of("u", "https://a.com"), List.of("u", "https://b.com")),
                    "", "sig");

            // Act
            String value = Nip98Validator.getSingleTag(event, "u");

            // Assert
            assertThat(value).isNull();
        }
    }

    // ── exactUrlMatch tests ─────────────────────────────────────────────────

    @Nested
    @DisplayName("exactUrlMatch")
    class ExactUrlMatchTests {

        @Test
        @DisplayName("identical URLs match")
        void identicalUrls() {
            assertThat(Nip98Validator.exactUrlMatch(
                    "https://example.com/api/auth", "https://example.com/api/auth"
            )).isTrue();
        }

        @Test
        @DisplayName("different hosts do not match")
        void differentHosts() {
            assertThat(Nip98Validator.exactUrlMatch(
                    "https://example.com/api", "https://other.com/api"
            )).isFalse();
        }

        @Test
        @DisplayName("different paths do not match")
        void differentPaths() {
            assertThat(Nip98Validator.exactUrlMatch(
                    "https://example.com/api/v1", "https://example.com/api/v2"
            )).isFalse();
        }

        @Test
        @DisplayName("URLs with dot segments are normalized")
        void normalizedPaths() {
            assertThat(Nip98Validator.exactUrlMatch(
                    "https://example.com/a/../b", "https://example.com/b"
            )).isTrue();
        }
    }

    // ── sha256Hex tests ─────────────────────────────────────────────────────

    @Nested
    @DisplayName("sha256Hex")
    class Sha256HexTests {

        @Test
        @DisplayName("known input produces expected SHA-256 hex digest")
        void knownPair() {
            // Arrange
            byte[] input = "hello".getBytes(StandardCharsets.UTF_8);
            // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
            String expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

            // Act
            String result = Nip98Validator.sha256Hex(input);

            // Assert
            assertThat(result).isEqualTo(expected);
        }

        @Test
        @DisplayName("empty input produces correct hash")
        void emptyInput() {
            // Arrange
            byte[] input = new byte[0];
            // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            String expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

            // Act
            String result = Nip98Validator.sha256Hex(input);

            // Assert
            assertThat(result).isEqualTo(expected);
        }
    }
}
