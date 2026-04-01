package xyz.tcheeric.nap.core;

public record AclRecord(String appId, String pubkey, String role, boolean suspended) {
}
