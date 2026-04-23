package xyz.tcheeric.nap.spring.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "nap")
public record NapProperties(
        boolean enabled,
        String externalBaseUrl,
        int challengeTtlSeconds,
        int sessionTtlSeconds,
        int sessionIdleTtlSeconds,
        int sessionAbsoluteTtlSeconds,
        int resultCacheTtlSeconds,
        int maxClockSkewSeconds,
        int stepUpTtlSeconds,
        int aclRefreshIntervalSeconds,
        List<String> protectedPathPrefixes,
        CookieProperties cookie
) {

    // Spec 006: sliding idle = 15 min; absolute cap = 12 h.
    public static final int DEFAULT_SESSION_IDLE_TTL_SECONDS = 900;
    public static final int DEFAULT_SESSION_ABSOLUTE_TTL_SECONDS = 43200;

    public NapProperties {
        if (challengeTtlSeconds <= 0) challengeTtlSeconds = 60;
        if (sessionTtlSeconds <= 0) sessionTtlSeconds = 3600;
        // New sliding-window knobs. If unset (i.e. the caller still uses the old
        // single sessionTtlSeconds), fall back to sessionTtlSeconds for both, so
        // the server keeps its pre-006 non-sliding behavior until operators opt in.
        if (sessionIdleTtlSeconds <= 0) sessionIdleTtlSeconds = sessionTtlSeconds;
        if (sessionAbsoluteTtlSeconds <= 0) sessionAbsoluteTtlSeconds = sessionTtlSeconds;
        if (resultCacheTtlSeconds <= 0) resultCacheTtlSeconds = 30;
        if (maxClockSkewSeconds <= 0) maxClockSkewSeconds = 60;
        if (stepUpTtlSeconds <= 0) stepUpTtlSeconds = 600;
        if (aclRefreshIntervalSeconds <= 0) aclRefreshIntervalSeconds = 300;
        if (protectedPathPrefixes == null) protectedPathPrefixes = List.of();
        if (cookie == null) cookie = new CookieProperties("merchant_session", true, true, "Lax", "/", "", 0);
        // Default cookie maxAge to the (effective) absolute session cap so the
        // browser retains the cookie for the full server-side lifetime.
        if (cookie.maxAgeSeconds() <= 0) {
            cookie = new CookieProperties(
                    cookie.name(), cookie.httpOnly(), cookie.secure(), cookie.sameSite(),
                    cookie.path(), cookie.domain(), sessionAbsoluteTtlSeconds
            );
        }
    }

    public record CookieProperties(
            String name,
            boolean httpOnly,
            boolean secure,
            String sameSite,
            String path,
            String domain,
            int maxAgeSeconds
    ) {
        public CookieProperties {
            if (name == null || name.isBlank()) name = "merchant_session";
            if (sameSite == null) sameSite = "Lax";
            if (path == null) path = "/";
            // maxAgeSeconds ≤ 0 is treated as "unset" by the enclosing NapProperties
            // compact constructor, which populates it from sessionAbsoluteTtlSeconds.
        }
    }
}
