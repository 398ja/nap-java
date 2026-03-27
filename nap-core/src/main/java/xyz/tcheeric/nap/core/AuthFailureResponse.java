package xyz.tcheeric.nap.core;

public record AuthFailureResponse(String status, String message) {

    public static AuthFailureResponse authenticationFailed() {
        return new AuthFailureResponse("error", "authentication failed");
    }
}
