package xyz.tcheeric.nap.jdbc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.tcheeric.nap.server.acl.AclRecord;
import xyz.tcheeric.nap.server.acl.AclStore;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

/**
 * PostgreSQL-backed AclStore using plain JDBC.
 */
public final class JdbcAclStore implements AclStore {

    private static final Logger log = LoggerFactory.getLogger(JdbcAclStore.class);
    private final DataSource dataSource;

    public JdbcAclStore(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public Optional<AclRecord> findByPubkey(String appId, String pubkey) {
        String sql = "SELECT * FROM nap_acl WHERE app_id = ? AND pubkey = ?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, appId);
            ps.setString(2, pubkey);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(new AclRecord(
                            rs.getString("app_id"),
                            rs.getString("pubkey"),
                            rs.getString("role"),
                            rs.getBoolean("suspended")
                    ));
                }
                return Optional.empty();
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to find ACL record", e);
        }
    }

    @Override
    public void create(AclRecord record) {
        String sql = "INSERT INTO nap_acl (app_id, pubkey, role, suspended) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, record.appId());
            ps.setString(2, record.pubkey());
            ps.setString(3, record.role());
            ps.setBoolean(4, record.suspended());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to create ACL record", e);
        }
    }
}
