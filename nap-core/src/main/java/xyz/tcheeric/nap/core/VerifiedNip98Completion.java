package xyz.tcheeric.nap.core;

public record VerifiedNip98Completion(
        Nip98Event event,
        String challenge,
        String challengeId,
        String payload
) {
}
