package xyz.tcheeric.nap.server.acl;

public record AclRecord(String appId, String pubkey, String role, boolean suspended) {
}
