package xyz.tcheeric.nap.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import nostr.crypto.schnorr.Schnorr;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Builds NIP-98 proofs for NAP authentication — used in integration tests.
 */
public final class NapProofBuilder {

    private static final Logger log = LoggerFactory.getLogger(NapProofBuilder.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();

    private String privateKeyHex;
    private String pubkeyHex;
    private String url;
    private String method = "POST";
    private String challenge;
    private String challengeId;
    private byte[] bodyBytes;
    private long createdAt = Instant.now().getEpochSecond();

    public NapProofBuilder privateKey(String hex) { this.privateKeyHex = hex; return this; }
    public NapProofBuilder pubkey(String hex) { this.pubkeyHex = hex; return this; }
    public NapProofBuilder url(String url) { this.url = url; return this; }
    public NapProofBuilder method(String method) { this.method = method; return this; }
    public NapProofBuilder challenge(String challenge) { this.challenge = challenge; return this; }
    public NapProofBuilder challengeId(String challengeId) { this.challengeId = challengeId; return this; }
    public NapProofBuilder body(byte[] bytes) { this.bodyBytes = bytes; return this; }
    public NapProofBuilder body(String json) { this.bodyBytes = json.getBytes(StandardCharsets.UTF_8); return this; }
    public NapProofBuilder createdAt(long epochSeconds) { this.createdAt = epochSeconds; return this; }

    /**
     * Builds the NIP-98 signed event and returns the Authorization header value.
     *
     * @return "Nostr {base64-encoded-event}"
     */
    public String buildAuthorizationHeader() {
        try {
            String payloadHash = sha256Hex(bodyBytes);

            // Build the event tags
            ArrayNode tags = MAPPER.createArrayNode();
            tags.add(MAPPER.createArrayNode().add("u").add(url));
            tags.add(MAPPER.createArrayNode().add("method").add(method.toUpperCase()));
            tags.add(MAPPER.createArrayNode().add("payload").add(payloadHash));
            tags.add(MAPPER.createArrayNode().add("challenge").add(challenge));
            tags.add(MAPPER.createArrayNode().add("challenge_id").add(challengeId));

            // Build the serialized event for hashing: [0, pubkey, created_at, kind, tags, content]
            ArrayNode serialized = MAPPER.createArrayNode();
            serialized.add(0);
            serialized.add(pubkeyHex);
            serialized.add(createdAt);
            serialized.add(27235);
            serialized.add(tags);
            serialized.add("");

            String serializedJson = MAPPER.writeValueAsString(serialized);
            byte[] eventIdBytes = sha256(serializedJson.getBytes(StandardCharsets.UTF_8));
            String eventId = HEX.formatHex(eventIdBytes);

            // Sign the event ID
            byte[] privateKey = HEX.parseHex(privateKeyHex);
            byte[] signature = Schnorr.sign(eventIdBytes, privateKey, generateAuxRand());
            String sig = HEX.formatHex(signature);

            // Build the full event JSON
            ObjectNode event = MAPPER.createObjectNode();
            event.put("id", eventId);
            event.put("pubkey", pubkeyHex);
            event.put("created_at", createdAt);
            event.put("kind", 27235);
            event.set("tags", tags);
            event.put("content", "");
            event.put("sig", sig);

            String eventJson = MAPPER.writeValueAsString(event);
            String base64Event = Base64.getEncoder().encodeToString(eventJson.getBytes(StandardCharsets.UTF_8));

            return "Nostr " + base64Event;
        } catch (Exception e) {
            throw new RuntimeException("Failed to build NIP-98 proof", e);
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private static String sha256Hex(byte[] data) {
        return HEX.formatHex(sha256(data));
    }

    private static byte[] generateAuxRand() {
        byte[] rand = new byte[32];
        new java.security.SecureRandom().nextBytes(rand);
        return rand;
    }
}
