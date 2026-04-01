package xyz.tcheeric.nap.jdbc;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.core.SessionStore;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

/**
 * PostgreSQL-backed SessionStore using plain JDBC.
 */
public final class JdbcSessionStore implements SessionStore {

    private static final Logger log = LoggerFactory.getLogger(JdbcSessionStore.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<List<String>> LIST_TYPE = new TypeReference<>() {};

    private final DataSource dataSource;

    public JdbcSessionStore(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public SessionRecord createForChallenge(SessionRecord record) {
        String sql = """
                INSERT INTO nap_sessions (session_id, challenge_id, access_token, principal_npub,
                    principal_pubkey, roles, permissions, issued_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, ?)
                ON CONFLICT (challenge_id) DO NOTHING
                """;
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, record.sessionId());
            ps.setString(2, record.challengeId());
            ps.setString(3, record.accessToken());
            ps.setString(4, record.principalNpub());
            ps.setString(5, record.principalPubkey());
            ps.setString(6, toJson(record.roles()));
            ps.setString(7, toJson(record.permissions()));
            ps.setLong(8, record.issuedAt());
            ps.setLong(9, record.expiresAt());
            int rows = ps.executeUpdate();
            if (rows == 0) {
                // Already exists — return existing
                return findByChallengeId(record.challengeId()).orElse(record);
            }
            return record;
        } catch (SQLException e) {
            throw new RuntimeException("Failed to create session", e);
        }
    }

    @Override
    public Optional<SessionRecord> getBySessionId(String sessionId) {
        return findBy("session_id", sessionId);
    }

    @Override
    public Optional<SessionRecord> getByAccessToken(String accessToken) {
        return findBy("access_token", accessToken);
    }

    @Override
    public void revokeBySessionId(String sessionId, long nowUnix) {
        String sql = "UPDATE nap_sessions SET revoked_at = ? WHERE session_id = ? AND revoked_at IS NULL";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, nowUnix);
            ps.setString(2, sessionId);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to revoke session", e);
        }
    }

    @Override
    public int revokeByPrincipal(String pubkey, long nowUnix) {
        String sql = "UPDATE nap_sessions SET revoked_at = ? WHERE principal_pubkey = ? AND revoked_at IS NULL";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, nowUnix);
            ps.setString(2, pubkey);
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to revoke sessions by principal", e);
        }
    }

    private Optional<SessionRecord> findByChallengeId(String challengeId) {
        return findBy("challenge_id", challengeId);
    }

    private Optional<SessionRecord> findBy(String column, String value) {
        String sql = "SELECT * FROM nap_sessions WHERE " + column + " = ? AND revoked_at IS NULL";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, value);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapRow(rs));
                }
                return Optional.empty();
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to find session", e);
        }
    }

    private SessionRecord mapRow(ResultSet rs) throws SQLException {
        return new SessionRecord(
                rs.getString("session_id"),
                rs.getString("challenge_id"),
                rs.getString("access_token"),
                rs.getString("principal_npub"),
                rs.getString("principal_pubkey"),
                fromJson(rs.getString("roles")),
                fromJson(rs.getString("permissions")),
                rs.getLong("issued_at"),
                rs.getLong("expires_at"),
                rs.getObject("revoked_at") != null ? rs.getLong("revoked_at") : null,
                rs.getString("step_up_token"),
                rs.getObject("step_up_expires_at") != null ? rs.getLong("step_up_expires_at") : null
        );
    }

    private String toJson(List<String> list) {
        try {
            return MAPPER.writeValueAsString(list);
        } catch (JsonProcessingException e) {
            return "[]";
        }
    }

    private List<String> fromJson(String json) {
        try {
            return MAPPER.readValue(json, LIST_TYPE);
        } catch (Exception e) {
            return List.of();
        }
    }
}
