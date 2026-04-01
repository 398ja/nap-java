package xyz.tcheeric.nap.spring.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import xyz.tcheeric.nap.core.AuthFailureResponse;
import xyz.tcheeric.nap.core.AuthInitResponse;
import xyz.tcheeric.nap.core.AuthSuccessResponse;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.server.IssueChallengeInput;
import xyz.tcheeric.nap.server.IssueChallengeResult;
import xyz.tcheeric.nap.server.NapServer;
import xyz.tcheeric.nap.server.VerifyCompletionInput;
import xyz.tcheeric.nap.server.VerifyCompletionOutcome;
import xyz.tcheeric.nap.spring.config.NapProperties;
import xyz.tcheeric.nap.spring.filter.NapServletFilter;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Verifies auth completion preserves Authorization-header compatibility while supporting body proof fallback.
 */
class NapAuthControllerTest {

    private final NapServer napServer = mock(NapServer.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final NapProperties properties = new NapProperties(
            true,
            "https://account.imani.casa",
            60,
            3600,
            30,
            60,
            600,
            300,
            List.of("/internal/v1/merchants"),
            new NapProperties.CookieProperties("merchant_session", true, true, "Lax", "/", "", 3600)
    );

    @Test
    void complete_usesBodyProofWhenAuthorizationHeaderIsMissing() {
        String requestBody = """
                {"challenge_id":"challenge-123","proof":"Nostr legacy-proof"}
                """;
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/complete");
        request.setAttribute(NapServletFilter.RAW_BODY_ATTRIBUTE, requestBody.getBytes());
        MockHttpServletResponse response = new MockHttpServletResponse();

        SessionRecord session = SessionRecord.create(
                "session-1",
                "challenge-123",
                "access-token",
                "npub1test",
                "a".repeat(64),
                List.of("merchant"),
                List.of("read"),
                1_700_000_000L,
                1_700_003_600L
        );
        when(napServer.verifyCompletion(any())).thenReturn(VerifyCompletionOutcome.success(session));
        when(napServer.toPublicAuthSuccess(session)).thenReturn(new AuthSuccessResponse(
                "ok",
                session.accessToken(),
                "Bearer",
                session.expiresAt(),
                new AuthSuccessResponse.Principal(session.principalNpub(), session.principalPubkey()),
                session.roles(),
                session.permissions()
        ));

        NapAuthController controller = new NapAuthController(napServer, properties, objectMapper);
        Object body = controller.complete(false, request, response).getBody();

        var captor = forClass(VerifyCompletionInput.class);
        verify(napServer).verifyCompletion(captor.capture());
        VerifyCompletionInput completionInput = captor.getValue();
        assertThat(completionInput.authorization()).isEqualTo("Nostr legacy-proof");
        assertThat(completionInput.method()).isEqualTo("POST");
        assertThat(completionInput.url()).isEqualTo("https://account.imani.casa/api/v1/auth/complete");
        assertThat(completionInput.rawBody()).isEqualTo(requestBody.getBytes());
        assertThat(response.getCookie("merchant_session")).isNotNull();
        assertThat(body).isNotNull();
    }

    @Test
    void init_validNpub_returnsSuccess() {
        // Arrange
        AuthInitResponse initResponse = new AuthInitResponse(
                "challenge-1", "nip98-challenge", "https://account.imani.casa/api/v1/auth/complete",
                "NIP-98", 1_700_000_000L, 1_700_000_060L
        );
        when(napServer.issueChallenge(any(IssueChallengeInput.class)))
                .thenReturn(new IssueChallengeResult.Success(initResponse));

        NapAuthController controller = new NapAuthController(napServer, properties, objectMapper);

        // Act
        ResponseEntity<?> response = controller.init(Map.of("npub", "npub1testpubkey"));

        // Assert
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isNotNull();
    }

    @Test
    void init_missingNpubAndPubkey_returnsBadRequest() {
        // Arrange
        NapAuthController controller = new NapAuthController(napServer, properties, objectMapper);

        // Act
        ResponseEntity<?> response = controller.init(Map.of());

        // Assert
        assertThat(response.getStatusCode().value()).isEqualTo(400);
    }

    @Test
    void complete_malformedBody_returnsBadRequest() {
        // Arrange
        when(napServer.verifyCompletion(any())).thenReturn(VerifyCompletionOutcome.malformed());

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/complete");
        request.setAttribute(NapServletFilter.RAW_BODY_ATTRIBUTE, "{}".getBytes());
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        NapAuthController controller = new NapAuthController(napServer, properties, objectMapper);

        // Act
        ResponseEntity<?> response = controller.complete(false, request, servletResponse);

        // Assert
        assertThat(response.getStatusCode().value()).isEqualTo(400);
    }

    @Test
    void complete_failure_returnsUnauthorized() {
        // Arrange
        when(napServer.verifyCompletion(any()))
                .thenReturn(new VerifyCompletionOutcome.Failure(
                        xyz.tcheeric.nap.core.NapErrorCode.NAP_COMPLETE_INVALID_SIGNATURE, false));
        when(napServer.toPublicAuthFailure())
                .thenReturn(new NapServer.PublicFailureResponse(401, AuthFailureResponse.authenticationFailed()));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/complete");
        request.setAttribute(NapServletFilter.RAW_BODY_ATTRIBUTE, "{}".getBytes());
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        NapAuthController controller = new NapAuthController(napServer, properties, objectMapper);

        // Act
        ResponseEntity<?> response = controller.complete(false, request, servletResponse);

        // Assert
        assertThat(response.getStatusCode().value()).isEqualTo(401);
    }

    @Test
    void checkSession_noCookie_returnsUnauthorized() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/auth/session");

        NapAuthController controller = new NapAuthController(napServer, properties, objectMapper);

        // Act
        ResponseEntity<?> response = controller.checkSession(request);

        // Assert
        assertThat(response.getStatusCode().value()).isEqualTo(401);
    }

    @Test
    void logout_clearsCookie() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/logout");
        MockHttpServletResponse response = new MockHttpServletResponse();

        NapAuthController controller = new NapAuthController(napServer, properties, objectMapper);

        // Act
        controller.logout(request, response);

        // Assert
        jakarta.servlet.http.Cookie cookie = response.getCookie("merchant_session");
        assertThat(cookie).isNotNull();
        assertThat(cookie.getMaxAge()).isEqualTo(0);
    }
}
