package xyz.tcheeric.nap.spring.annotation;

import java.lang.annotation.*;

/**
 * Marks an endpoint as requiring a step-up re-authentication token.
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequiresStepUp {
}
