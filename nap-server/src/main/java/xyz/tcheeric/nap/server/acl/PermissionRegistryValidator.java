package xyz.tcheeric.nap.server.acl;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Validates a PermissionRegistry at startup. Fails fast if the registry is invalid.
 */
public final class PermissionRegistryValidator {

    private PermissionRegistryValidator() {
    }

    public static void validate(PermissionRegistry registry) {
        Set<String> permKeys = new HashSet<>();
        for (PermissionDefinition perm : registry.permissions()) {
            if (!permKeys.add(perm.key())) {
                throw new IllegalStateException(
                        "Duplicate permission key: " + perm.key() + " in registry " + registry.appId());
            }
        }

        Set<String> roleKeys = new HashSet<>();
        for (RoleDefinition role : registry.roles()) {
            if (!roleKeys.add(role.key())) {
                throw new IllegalStateException(
                        "Duplicate role key: " + role.key() + " in registry " + registry.appId());
            }
        }

        if (!roleKeys.contains(registry.defaultRole())) {
            throw new IllegalStateException(
                    "defaultRole '" + registry.defaultRole() + "' does not reference a declared role in registry " + registry.appId());
        }

        for (RoleDefinition role : registry.roles()) {
            Set<String> unknownPerms = role.permissions().stream()
                    .filter(p -> !permKeys.contains(p))
                    .collect(Collectors.toSet());
            if (!unknownPerms.isEmpty()) {
                throw new IllegalStateException(
                        "Role '" + role.key() + "' references unknown permissions: " + unknownPerms
                                + " in registry " + registry.appId());
            }
        }
    }
}
