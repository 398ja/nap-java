package xyz.tcheeric.nap.server.acl;

import java.util.Set;

record DefaultPermissionRegistry(
        String appId,
        Set<PermissionDefinition> permissions,
        Set<RoleDefinition> roles,
        String defaultRole
) implements PermissionRegistry {
}
