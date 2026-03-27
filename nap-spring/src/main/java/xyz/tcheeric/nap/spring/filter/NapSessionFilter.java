package xyz.tcheeric.nap.spring.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.server.SessionStore;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * Validates NAP session cookies on protected paths and populates Spring SecurityContext.
 */
public class NapSessionFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(NapSessionFilter.class);

    private final SessionStore sessionStore;
    private final String cookieName;
    private final List<String> protectedPrefixes;

    public NapSessionFilter(SessionStore sessionStore, String cookieName, List<String> protectedPrefixes) {
        this.sessionStore = sessionStore;
        this.cookieName = cookieName;
        this.protectedPrefixes = protectedPrefixes;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                     FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        boolean isProtected = protectedPrefixes.stream().anyMatch(path::startsWith);

        if (!isProtected) {
            filterChain.doFilter(request, response);
            return;
        }

        String sessionId = extractCookie(request);
        if (sessionId == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        var session = sessionStore.getByAccessToken(sessionId);
        if (session.isEmpty()) {
            // Try by session ID as fallback
            session = sessionStore.getBySessionId(sessionId);
        }

        if (session.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        var record = session.get();
        SecurityContextHolder.getContext().setAuthentication(new NapAuthenticationToken(record));

        filterChain.doFilter(request, response);
    }

    private String extractCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        return Arrays.stream(request.getCookies())
                .filter(c -> cookieName.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }

    /**
     * Spring Security authentication token backed by a NAP session.
     */
    public static class NapAuthenticationToken extends AbstractAuthenticationToken {
        private final SessionRecord session;

        public NapAuthenticationToken(SessionRecord session) {
            super(toAuthorities(session.permissions()));
            this.session = session;
            setAuthenticated(true);
        }

        @Override
        public Object getCredentials() {
            return session.accessToken();
        }

        @Override
        public Object getPrincipal() {
            return session.principalPubkey();
        }

        public SessionRecord getSession() {
            return session;
        }

        public String getPubkey() {
            return session.principalPubkey();
        }

        private static Collection<GrantedAuthority> toAuthorities(List<String> permissions) {
            return permissions.stream()
                    .map(SimpleGrantedAuthority::new)
                    .map(GrantedAuthority.class::cast)
                    .toList();
        }
    }
}
