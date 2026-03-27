package xyz.tcheeric.nap.spring.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import xyz.tcheeric.nap.core.AuthInitRequest;
import xyz.tcheeric.nap.server.*;
import xyz.tcheeric.nap.spring.config.NapProperties;
import xyz.tcheeric.nap.spring.filter.NapServletFilter;

import java.util.Arrays;
import java.util.Map;

/**
 * NAP v2 authentication endpoints: init, complete, session, logout.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class NapAuthController {

    private static final Logger log = LoggerFactory.getLogger(NapAuthController.class);

    private final NapServer napServer;
    private final NapProperties properties;
    private final ObjectMapper objectMapper;

    public NapAuthController(NapServer napServer, NapProperties properties, ObjectMapper objectMapper) {
        this.napServer = napServer;
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/init")
    public ResponseEntity<?> init(@RequestBody Map<String, String> body) {
        String npub = body.get("npub");
        String pubkey = body.get("pubkey");

        if ((npub == null || npub.isBlank()) && (pubkey == null || pubkey.isBlank())) {
            return ResponseEntity.badRequest()
                    .body(Map.of("status", "error", "message", "npub or pubkey is required"));
        }

        String authUrl = properties.externalBaseUrl() + "/api/v1/auth/complete";

        IssueChallengeResult result = napServer.issueChallenge(new IssueChallengeInput(
                npub != null ? npub : pubkey, authUrl));

        return switch (result) {
            case IssueChallengeResult.Success s -> ResponseEntity.ok(Map.of(
                    "challenge_id", s.value().challengeId(),
                    "challenge", s.value().challenge(),
                    "auth_url", s.value().authUrl(),
                    "auth_method", s.value().authMethod(),
                    "issued_at", s.value().issuedAt(),
                    "expires_at", s.value().expiresAt()
            ));
            case IssueChallengeResult.Failure f -> ResponseEntity.badRequest()
                    .body(Map.of("status", "error", "code", f.code().name()));
        };
    }

    @PostMapping("/complete")
    public ResponseEntity<?> complete(
            @RequestParam(value = "step_up", required = false, defaultValue = "false") boolean stepUp,
            HttpServletRequest request,
            HttpServletResponse response) {

        byte[] rawBody = (byte[]) request.getAttribute(NapServletFilter.RAW_BODY_ATTRIBUTE);
        if (rawBody == null) {
            return ResponseEntity.badRequest()
                    .body(Map.of("status", "error", "message", "Request body not captured"));
        }

        String authUrl = properties.externalBaseUrl() + "/api/v1/auth/complete";
        String authorization = request.getHeader("Authorization");

        VerifyCompletionOutcome outcome = napServer.verifyCompletion(new VerifyCompletionInput(
                authorization, "POST", authUrl, rawBody));

        return switch (outcome) {
            case VerifyCompletionOutcome.Success s -> {
                setCookie(response, s.session().sessionId());
                var successResponse = napServer.toPublicAuthSuccess(s.session());
                yield ResponseEntity.ok(successResponse);
            }
            case VerifyCompletionOutcome.Failure f -> {
                log.warn("nap_complete_failed code={}", f.code());
                yield ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(napServer.toPublicAuthFailure().body());
            }
            case VerifyCompletionOutcome.MalformedRequest m ->
                    ResponseEntity.badRequest()
                            .body(Map.of("status", "error", "message", "bad request"));
        };
    }

    @GetMapping("/session")
    public ResponseEntity<?> checkSession(HttpServletRequest request) {
        String sessionId = extractCookie(request);
        if (sessionId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("status", "error", "message", "No session"));
        }

        // Note: session validation is handled through the NapSessionFilter
        return ResponseEntity.ok(Map.of("status", "ok"));
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        String sessionId = extractCookie(request);
        if (sessionId != null) {
            log.info("nap_logout");
        }

        clearCookie(response);
    }

    private void setCookie(HttpServletResponse response, String sessionId) {
        var cookieProps = properties.cookie();
        Cookie cookie = new Cookie(cookieProps.name(), sessionId);
        cookie.setHttpOnly(cookieProps.httpOnly());
        cookie.setSecure(cookieProps.secure());
        cookie.setPath(cookieProps.path());
        cookie.setMaxAge(cookieProps.maxAgeSeconds());
        cookie.setAttribute("SameSite", cookieProps.sameSite());
        if (cookieProps.domain() != null && !cookieProps.domain().isBlank()) {
            cookie.setDomain(cookieProps.domain());
        }
        response.addCookie(cookie);
    }

    private void clearCookie(HttpServletResponse response) {
        var cookieProps = properties.cookie();
        Cookie cookie = new Cookie(cookieProps.name(), "");
        cookie.setHttpOnly(cookieProps.httpOnly());
        cookie.setSecure(cookieProps.secure());
        cookie.setPath(cookieProps.path());
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    private String extractCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        return Arrays.stream(request.getCookies())
                .filter(c -> properties.cookie().name().equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }
}
