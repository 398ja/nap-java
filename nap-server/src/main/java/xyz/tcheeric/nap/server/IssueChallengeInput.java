package xyz.tcheeric.nap.server;

public record IssueChallengeInput(String npub, String authUrl, String authMethod) {

    public IssueChallengeInput(String npub, String authUrl) {
        this(npub, authUrl, "POST");
    }
}
