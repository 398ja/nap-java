package xyz.tcheeric.nap.spring.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * Captures raw request body bytes on the /auth/complete path for NIP-98 payload hash verification.
 *
 * <p>Only activates on the auth complete path to avoid memory pressure from body buffering
 * on high-throughput endpoints.
 */
public class NapServletFilter extends OncePerRequestFilter {

    public static final String RAW_BODY_ATTRIBUTE = "nap.raw.body";

    private final String completePath;

    public NapServletFilter(String completePath) {
        this.completePath = completePath;
    }

    public NapServletFilter() {
        this("/auth/complete");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                     FilterChain filterChain) throws ServletException, IOException {
        if (request.getRequestURI().endsWith(completePath)) {
            byte[] body = request.getInputStream().readAllBytes();
            request.setAttribute(RAW_BODY_ATTRIBUTE, body);
            filterChain.doFilter(new CachedBodyRequestWrapper(request, body), response);
        } else {
            filterChain.doFilter(request, response);
        }
    }

    private static class CachedBodyRequestWrapper extends HttpServletRequestWrapper {
        private final byte[] body;

        CachedBodyRequestWrapper(HttpServletRequest request, byte[] body) {
            super(request);
            this.body = body;
        }

        @Override
        public jakarta.servlet.ServletInputStream getInputStream() {
            ByteArrayInputStream bais = new ByteArrayInputStream(body);
            return new jakarta.servlet.ServletInputStream() {
                @Override public int read() { return bais.read(); }
                @Override public boolean isFinished() { return bais.available() == 0; }
                @Override public boolean isReady() { return true; }
                @Override public void setReadListener(jakarta.servlet.ReadListener listener) {}
            };
        }

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(new InputStreamReader(getInputStream()));
        }
    }
}
