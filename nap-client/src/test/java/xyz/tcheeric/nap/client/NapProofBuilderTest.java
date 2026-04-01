package xyz.tcheeric.nap.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import nostr.crypto.schnorr.Schnorr;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link NapProofBuilder}.
 */
class NapProofBuilderTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();

    private String privKeyHex;
    private String pubKeyHex;
    private final String url = "https://example.com/auth/complete";
    private final String challenge = "test-challenge-value";
    private final String challengeId = "test-challenge-id";
    private final long createdAt = Instant.now().getEpochSecond();
    private final byte[] bodyBytes = "{\"challenge_id\":\"test-challenge-id\"}".getBytes(StandardCharsets.UTF_8);

    @BeforeEach
    void setUp() throws Exception {
        byte[] privKey = new byte[32];
        new SecureRandom().nextBytes(privKey);
        privKeyHex = HEX.formatHex(privKey);
        byte[] pubKey = Schnorr.genPubKey(privKey);
        pubKeyHex = HEX.formatHex(pubKey);
    }

    @Test
    void buildAuthorizationHeader_returnsNostrPrefixedString() {
        // Arrange
        NapProofBuilder builder = new NapProofBuilder()
                .privateKey(privKeyHex)
                .pubkey(pubKeyHex)
                .url(url)
                .method("POST")
                .challenge(challenge)
                .challengeId(challengeId)
                .body(bodyBytes)
                .createdAt(createdAt);

        // Act
        String header = builder.buildAuthorizationHeader();

        // Assert
        assertThat(header).startsWith("Nostr ");
        String base64Part = header.substring("Nostr ".length());
        assertThat(base64Part).isNotBlank();
        // Verify it is valid base64
        byte[] decoded = Base64.getDecoder().decode(base64Part);
        assertThat(decoded).isNotEmpty();
    }

    @Test
    void buildAuthorizationHeader_base64DecodesToValidEventJson() throws Exception {
        // Arrange
        NapProofBuilder builder = new NapProofBuilder()
                .privateKey(privKeyHex)
                .pubkey(pubKeyHex)
                .url(url)
                .method("POST")
                .challenge(challenge)
                .challengeId(challengeId)
                .body(bodyBytes)
                .createdAt(createdAt);

        // Act
        String header = builder.buildAuthorizationHeader();
        String base64Part = header.substring("Nostr ".length());
        String json = new String(Base64.getDecoder().decode(base64Part), StandardCharsets.UTF_8);
        JsonNode event = MAPPER.readTree(json);

        // Assert
        assertThat(event.has("id")).isTrue();
        assertThat(event.get("id").asText()).hasSize(64);
        assertThat(event.get("pubkey").asText()).isEqualTo(pubKeyHex);
        assertThat(event.get("created_at").asLong()).isEqualTo(createdAt);
        assertThat(event.get("kind").asInt()).isEqualTo(27235);
        assertThat(event.get("content").asText()).isEmpty();
        assertThat(event.has("sig")).isTrue();
        assertThat(event.get("sig").asText()).hasSize(128);

        // Verify tags contain expected entries
        JsonNode tags = event.get("tags");
        assertThat(tags.isArray()).isTrue();
        assertThat(tags.size()).isGreaterThanOrEqualTo(5);

        assertThat(tags.get(0).get(0).asText()).isEqualTo("u");
        assertThat(tags.get(0).get(1).asText()).isEqualTo(url);
        assertThat(tags.get(1).get(0).asText()).isEqualTo("method");
        assertThat(tags.get(1).get(1).asText()).isEqualTo("POST");
        assertThat(tags.get(2).get(0).asText()).isEqualTo("payload");
        assertThat(tags.get(3).get(0).asText()).isEqualTo("challenge");
        assertThat(tags.get(3).get(1).asText()).isEqualTo(challenge);
        assertThat(tags.get(4).get(0).asText()).isEqualTo("challenge_id");
        assertThat(tags.get(4).get(1).asText()).isEqualTo(challengeId);
    }

    @Test
    void buildAuthorizationHeader_signatureIsVerifiable() throws Exception {
        // Arrange
        NapProofBuilder builder = new NapProofBuilder()
                .privateKey(privKeyHex)
                .pubkey(pubKeyHex)
                .url(url)
                .method("POST")
                .challenge(challenge)
                .challengeId(challengeId)
                .body(bodyBytes)
                .createdAt(createdAt);

        // Act
        String header = builder.buildAuthorizationHeader();
        String base64Part = header.substring("Nostr ".length());
        String json = new String(Base64.getDecoder().decode(base64Part), StandardCharsets.UTF_8);
        JsonNode event = MAPPER.readTree(json);

        byte[] message = HEX.parseHex(event.get("id").asText());
        byte[] pubKey = HEX.parseHex(event.get("pubkey").asText());
        byte[] sig = HEX.parseHex(event.get("sig").asText());

        // Assert
        boolean valid = Schnorr.verify(message, pubKey, sig);
        assertThat(valid).isTrue();
    }
}
