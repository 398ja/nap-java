package xyz.tcheeric.nap.spring.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "nap")
public record NapProperties(
        boolean enabled,
        String externalBaseUrl,
        int challengeTtlSeconds,
        int sessionTtlSeconds,
        int resultCacheTtlSeconds,
        int maxClockSkewSeconds,
        int stepUpTtlSeconds,
        int aclRefreshIntervalSeconds,
        List<String> protectedPathPrefixes,
        CookieProperties cookie
) {

    public NapProperties {
        if (challengeTtlSeconds <= 0) challengeTtlSeconds = 60;
        if (sessionTtlSeconds <= 0) sessionTtlSeconds = 3600;
        if (resultCacheTtlSeconds <= 0) resultCacheTtlSeconds = 30;
        if (maxClockSkewSeconds <= 0) maxClockSkewSeconds = 60;
        if (stepUpTtlSeconds <= 0) stepUpTtlSeconds = 600;
        if (aclRefreshIntervalSeconds <= 0) aclRefreshIntervalSeconds = 300;
        if (protectedPathPrefixes == null) protectedPathPrefixes = List.of();
        if (cookie == null) cookie = new CookieProperties("merchant_session", true, true, "Lax", "/", "", 3600);
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
            if (maxAgeSeconds <= 0) maxAgeSeconds = 3600;
        }
    }
}
