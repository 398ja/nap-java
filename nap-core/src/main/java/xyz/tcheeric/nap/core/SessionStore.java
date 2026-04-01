package xyz.tcheeric.nap.core;

import java.util.Optional;

public interface SessionStore {

    SessionRecord createForChallenge(SessionRecord record);

    Optional<SessionRecord> getBySessionId(String sessionId);

    Optional<SessionRecord> getByAccessToken(String accessToken);

    void revokeBySessionId(String sessionId, long nowUnix);

    int revokeByPrincipal(String pubkey, long nowUnix);
}
