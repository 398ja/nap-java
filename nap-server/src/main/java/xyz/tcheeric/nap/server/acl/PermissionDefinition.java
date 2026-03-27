package xyz.tcheeric.nap.server.acl;

public record PermissionDefinition(String key, String description, boolean stepUpRequired) {
}
