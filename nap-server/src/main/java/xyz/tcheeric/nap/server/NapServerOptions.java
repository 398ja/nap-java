package xyz.tcheeric.nap.server;

import xyz.tcheeric.nap.core.ChallengeStore;
import xyz.tcheeric.nap.core.SessionStore;

import java.security.SecureRandom;
import java.time.Clock;

public record NapServerOptions(
        ChallengeStore challengeStore,
        SessionStore sessionStore,
        AclResolver aclResolver,
        EventReplayGuard eventReplayGuard,
        Clock clock,
        SecureRandom random,
        int challengeTtlSeconds,
        int sessionTtlSeconds,
        int resultCacheTtlSeconds,
        int maxClockSkewSeconds,
        int lowerBoundGraceSeconds,
        int upperBoundGraceSeconds
) {

    public static final int DEFAULT_CHALLENGE_TTL_SECONDS = 60;
    public static final int DEFAULT_SESSION_TTL_SECONDS = 3600;
    public static final int DEFAULT_RESULT_CACHE_TTL_SECONDS = 30;
    public static final int DEFAULT_MAX_CLOCK_SKEW_SECONDS = 60;
    public static final int DEFAULT_LOWER_BOUND_GRACE_SECONDS = 30;
    public static final int DEFAULT_UPPER_BOUND_GRACE_SECONDS = 5;

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private ChallengeStore challengeStore;
        private SessionStore sessionStore;
        private AclResolver aclResolver;
        private EventReplayGuard eventReplayGuard = EventReplayGuard.inMemory();
        private Clock clock = Clock.systemUTC();
        private SecureRandom random = new SecureRandom();
        private int challengeTtlSeconds = DEFAULT_CHALLENGE_TTL_SECONDS;
        private int sessionTtlSeconds = DEFAULT_SESSION_TTL_SECONDS;
        private int resultCacheTtlSeconds = DEFAULT_RESULT_CACHE_TTL_SECONDS;
        private int maxClockSkewSeconds = DEFAULT_MAX_CLOCK_SKEW_SECONDS;
        private int lowerBoundGraceSeconds = DEFAULT_LOWER_BOUND_GRACE_SECONDS;
        private int upperBoundGraceSeconds = DEFAULT_UPPER_BOUND_GRACE_SECONDS;

        public Builder challengeStore(ChallengeStore store) { this.challengeStore = store; return this; }
        public Builder sessionStore(SessionStore store) { this.sessionStore = store; return this; }
        public Builder aclResolver(AclResolver resolver) { this.aclResolver = resolver; return this; }
        public Builder eventReplayGuard(EventReplayGuard replayGuard) { this.eventReplayGuard = replayGuard; return this; }
        public Builder clock(Clock clock) { this.clock = clock; return this; }
        public Builder random(SecureRandom random) { this.random = random; return this; }
        public Builder challengeTtlSeconds(int ttl) { this.challengeTtlSeconds = ttl; return this; }
        public Builder sessionTtlSeconds(int ttl) { this.sessionTtlSeconds = ttl; return this; }
        public Builder resultCacheTtlSeconds(int ttl) { this.resultCacheTtlSeconds = ttl; return this; }
        public Builder maxClockSkewSeconds(int skew) { this.maxClockSkewSeconds = skew; return this; }
        public Builder lowerBoundGraceSeconds(int grace) { this.lowerBoundGraceSeconds = grace; return this; }
        public Builder upperBoundGraceSeconds(int grace) { this.upperBoundGraceSeconds = grace; return this; }

        public NapServerOptions build() {
            if (challengeStore == null) throw new IllegalStateException("challengeStore is required");
            if (sessionStore == null) throw new IllegalStateException("sessionStore is required");
            if (aclResolver == null) aclResolver = new AllowAllAclResolver();
            if (eventReplayGuard == null) eventReplayGuard = EventReplayGuard.inMemory();
            return new NapServerOptions(
                    challengeStore, sessionStore, aclResolver, eventReplayGuard, clock, random,
                    challengeTtlSeconds, sessionTtlSeconds, resultCacheTtlSeconds,
                    maxClockSkewSeconds, lowerBoundGraceSeconds, upperBoundGraceSeconds
            );
        }
    }
}
