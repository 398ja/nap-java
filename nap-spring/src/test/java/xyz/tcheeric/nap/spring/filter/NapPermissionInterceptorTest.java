package xyz.tcheeric.nap.spring.filter;

import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.method.HandlerMethod;
import xyz.tcheeric.nap.spring.annotation.RequiresPermission;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies @RequiresPermission endpoints are rejected when the authenticated principal lacks the required authority.
 */
class NapPermissionInterceptorTest {

    private final NapPermissionInterceptor interceptor = new NapPermissionInterceptor();

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void preHandle_returnsForbiddenWhenPermissionIsMissing() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("merchant", null, "read")
        );
        HandlerMethod handlerMethod = new HandlerMethod(new TestController(),
                TestController.class.getDeclaredMethod("adminEndpoint"));
        var request = new org.springframework.mock.web.MockHttpServletRequest("POST", "/internal/v1/merchants/test/suspend");
        var response = new org.springframework.mock.web.MockHttpServletResponse();

        boolean allowed = interceptor.preHandle(request, response, handlerMethod);

        assertThat(allowed).isFalse();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    void preHandle_allowsRequestWhenPermissionMatches() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("merchant", null, "admin")
        );
        HandlerMethod handlerMethod = new HandlerMethod(new TestController(),
                TestController.class.getDeclaredMethod("adminEndpoint"));
        var request = new org.springframework.mock.web.MockHttpServletRequest("POST", "/internal/v1/merchants/test/suspend");
        var response = new org.springframework.mock.web.MockHttpServletResponse();

        boolean allowed = interceptor.preHandle(request, response, handlerMethod);

        assertThat(allowed).isTrue();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }

    private static class TestController {

        @RequiresPermission("admin")
        public void adminEndpoint() {
        }
    }
}
