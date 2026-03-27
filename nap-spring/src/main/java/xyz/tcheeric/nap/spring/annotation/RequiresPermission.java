package xyz.tcheeric.nap.spring.annotation;

import java.lang.annotation.*;

/**
 * Marks an endpoint as requiring a specific NAP permission.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequiresPermission {
    String value();
}
