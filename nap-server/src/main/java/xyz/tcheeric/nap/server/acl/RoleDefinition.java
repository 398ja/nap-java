package xyz.tcheeric.nap.server.acl;

import java.util.Set;

public record RoleDefinition(String key, String description, Set<String> permissions) {
}
