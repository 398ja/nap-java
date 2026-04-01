package xyz.tcheeric.nap.server.acl;

import org.junit.jupiter.api.Test;
import xyz.tcheeric.nap.core.AclDecision;
import xyz.tcheeric.nap.core.AclRecord;
import xyz.tcheeric.nap.server.store.InMemoryAclStore;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AclTest {

    private static final String APP_ID = "test-app";
    private static final String PUBKEY = "abc123pubkey";
    private static final String NPUB = "npub1dummy";

    // -- shared helpers --

    private static PermissionDefinition perm(String key) {
        return new PermissionDefinition(key, key + " description", false);
    }

    private static RoleDefinition role(String key, String... perms) {
        return new RoleDefinition(key, key + " description", Set.of(perms));
    }

    private static PermissionRegistry validRegistry() {
        return PermissionRegistry.of(
                APP_ID,
                List.of(perm("read"), perm("write")),
                List.of(role("user", "read"), role("admin", "read", "write")),
                "user"
        );
    }

    // ========== PermissionRegistryValidator ==========

    @Test
    void validator_validRegistry_noException() {
        // Arrange
        var registry = validRegistry();

        // Act & Assert
        PermissionRegistryValidator.validate(registry);
        // no exception means success
    }

    @Test
    void validator_duplicatePermissionKey_throws() {
        // Arrange
        var registry = PermissionRegistry.of(
                APP_ID,
                List.of(perm("read"), new PermissionDefinition("read", "duplicate", true)),
                List.of(role("user", "read")),
                "user"
        );

        // Act & Assert
        assertThatThrownBy(() -> PermissionRegistryValidator.validate(registry))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Duplicate permission key: read");
    }

    @Test
    void validator_duplicateRoleKey_throws() {
        // Arrange
        var registry = PermissionRegistry.of(
                APP_ID,
                List.of(perm("read")),
                List.of(role("user", "read"), new RoleDefinition("user", "duplicate", Set.of("read"))),
                "user"
        );

        // Act & Assert
        assertThatThrownBy(() -> PermissionRegistryValidator.validate(registry))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Duplicate role key: user");
    }

    @Test
    void validator_defaultRoleNotInRoles_throws() {
        // Arrange
        var registry = PermissionRegistry.of(
                APP_ID,
                List.of(perm("read")),
                List.of(role("admin", "read")),
                "user"
        );

        // Act & Assert
        assertThatThrownBy(() -> PermissionRegistryValidator.validate(registry))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("defaultRole 'user' does not reference a declared role");
    }

    @Test
    void validator_roleReferencesUnknownPermission_throws() {
        // Arrange
        var registry = PermissionRegistry.of(
                APP_ID,
                List.of(perm("read")),
                List.of(role("user", "read", "delete")),
                "user"
        );

        // Act & Assert
        assertThatThrownBy(() -> PermissionRegistryValidator.validate(registry))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Role 'user' references unknown permissions:")
                .hasMessageContaining("delete");
    }

    // ========== RegistryAclResolver ==========

    @Test
    void resolver_noRecord_autoProvisionTrue_createsAndAllows() {
        // Arrange
        var store = new InMemoryAclStore();
        var resolver = RegistryAclResolver.create(validRegistry(), store, true);

        // Act
        AclDecision decision = resolver.resolve(NPUB, PUBKEY);

        // Assert
        assertThat(decision.allowed()).isTrue();
        assertThat(decision.roles()).containsExactly("user");
        assertThat(decision.permissions()).containsExactly("read");
        assertThat(store.findByPubkey(APP_ID, PUBKEY)).isPresent();
    }

    @Test
    void resolver_noRecord_autoProvisionFalse_denied() {
        // Arrange
        var store = new InMemoryAclStore();
        var resolver = RegistryAclResolver.create(validRegistry(), store, false);

        // Act
        AclDecision decision = resolver.resolve(NPUB, PUBKEY);

        // Assert
        assertThat(decision.allowed()).isFalse();
        assertThat(store.findByPubkey(APP_ID, PUBKEY)).isEmpty();
    }

    @Test
    void resolver_suspendedRecord_denied() {
        // Arrange
        var store = new InMemoryAclStore();
        store.create(new AclRecord(APP_ID, PUBKEY, "user", true));
        var resolver = RegistryAclResolver.create(validRegistry(), store);

        // Act
        AclDecision decision = resolver.resolve(NPUB, PUBKEY);

        // Assert
        assertThat(decision.allowed()).isFalse();
    }

    @Test
    void resolver_unknownRole_denied() {
        // Arrange
        var store = new InMemoryAclStore();
        store.create(new AclRecord(APP_ID, PUBKEY, "ghost", false));
        var resolver = RegistryAclResolver.create(validRegistry(), store);

        // Act
        AclDecision decision = resolver.resolve(NPUB, PUBKEY);

        // Assert
        assertThat(decision.allowed()).isFalse();
    }

    @Test
    void resolver_validRole_allowed() {
        // Arrange
        var store = new InMemoryAclStore();
        store.create(new AclRecord(APP_ID, PUBKEY, "admin", false));
        var resolver = RegistryAclResolver.create(validRegistry(), store);

        // Act
        AclDecision decision = resolver.resolve(NPUB, PUBKEY);

        // Assert
        assertThat(decision.allowed()).isTrue();
        assertThat(decision.roles()).containsExactly("admin");
        assertThat(decision.permissions()).containsExactlyInAnyOrder("read", "write");
    }
}
