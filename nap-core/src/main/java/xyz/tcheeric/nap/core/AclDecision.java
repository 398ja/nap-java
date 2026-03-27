package xyz.tcheeric.nap.core;

import java.util.List;

public record AclDecision(boolean allowed, List<String> roles, List<String> permissions) {

    public static AclDecision allowed(List<String> roles, List<String> permissions) {
        return new AclDecision(true, roles, permissions);
    }

    public static AclDecision denied() {
        return new AclDecision(false, List.of(), List.of());
    }

    public static AclDecision denied(String reason) {
        return new AclDecision(false, List.of(), List.of());
    }
}
