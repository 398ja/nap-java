package xyz.tcheeric.nap.server.acl;

import java.util.List;
import java.util.Set;

public interface PermissionRegistry {

    String appId();

    Set<PermissionDefinition> permissions();

    Set<RoleDefinition> roles();

    String defaultRole();

    static PermissionRegistry of(String appId, List<PermissionDefinition> permissions,
                                  List<RoleDefinition> roles, String defaultRole) {
        return new DefaultPermissionRegistry(appId, Set.copyOf(permissions), Set.copyOf(roles), defaultRole);
    }
}
