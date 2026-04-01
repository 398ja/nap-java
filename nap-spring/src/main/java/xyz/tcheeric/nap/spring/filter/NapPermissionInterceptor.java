package xyz.tcheeric.nap.spring.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.core.Authentication;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import xyz.tcheeric.nap.spring.annotation.RequiresPermission;

/**
 * Enforces {@link RequiresPermission} declarations on MVC handler methods.
 */
public class NapPermissionInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }

        RequiresPermission annotation = findAnnotation(handlerMethod);
        if (annotation == null) {
            return true;
        }

        Authentication authentication = org.springframework.security.core.context.SecurityContextHolder
                .getContext()
                .getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }

        boolean allowed = authentication.getAuthorities().stream()
                .map(org.springframework.security.core.GrantedAuthority::getAuthority)
                .anyMatch(annotation.value()::equals);
        if (allowed) {
            return true;
        }

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        return false;
    }

    private RequiresPermission findAnnotation(HandlerMethod handlerMethod) {
        RequiresPermission methodAnnotation = AnnotatedElementUtils.findMergedAnnotation(
                handlerMethod.getMethod(), RequiresPermission.class);
        if (methodAnnotation != null) {
            return methodAnnotation;
        }
        return AnnotatedElementUtils.findMergedAnnotation(
                handlerMethod.getBeanType(), RequiresPermission.class);
    }
}
