package xyz.tcheeric.nap.spring.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import xyz.tcheeric.nap.core.ChallengeStore;
import xyz.tcheeric.nap.core.SessionStore;
import xyz.tcheeric.nap.server.AclResolver;
import xyz.tcheeric.nap.server.AllowAllAclResolver;
import xyz.tcheeric.nap.server.EventReplayGuard;
import xyz.tcheeric.nap.server.NapServer;
import xyz.tcheeric.nap.server.NapServerOptions;
import xyz.tcheeric.nap.server.store.InMemoryChallengeStore;
import xyz.tcheeric.nap.server.store.InMemorySessionStore;
import xyz.tcheeric.nap.spring.controller.NapAuthController;
import xyz.tcheeric.nap.spring.filter.NapPermissionInterceptor;

@AutoConfiguration(after = JacksonAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "nap", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(NapProperties.class)
public class NapAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public ChallengeStore challengeStore() {
        return new InMemoryChallengeStore();
    }

    @Bean
    @ConditionalOnMissingBean
    public SessionStore sessionStore() {
        return new InMemorySessionStore();
    }

    @Bean
    @ConditionalOnMissingBean
    public AclResolver aclResolver() {
        return new AllowAllAclResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    public NapServer napServer(ChallengeStore challengeStore, SessionStore sessionStore,
                               AclResolver aclResolver,
                               NapProperties properties,
                               ObjectProvider<EventReplayGuard> replayGuardProvider) {
        return NapServer.create(NapServerOptions.builder()
                .challengeStore(challengeStore)
                .sessionStore(sessionStore)
                .aclResolver(aclResolver)
                .eventReplayGuard(replayGuardProvider.getIfAvailable(EventReplayGuard::inMemory))
                .challengeTtlSeconds(properties.challengeTtlSeconds())
                .sessionTtlSeconds(properties.sessionTtlSeconds())
                .resultCacheTtlSeconds(properties.resultCacheTtlSeconds())
                .maxClockSkewSeconds(properties.maxClockSkewSeconds())
                .build());
    }

    @Bean
    @ConditionalOnMissingBean
    public NapAuthController napAuthController(NapServer napServer, NapProperties properties,
                                               com.fasterxml.jackson.databind.ObjectMapper objectMapper) {
        return new NapAuthController(napServer, properties, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean(name = "napPermissionInterceptor")
    public HandlerInterceptor napPermissionInterceptor() {
        return new NapPermissionInterceptor();
    }

    @Bean
    @ConditionalOnMissingBean(name = "napPermissionWebMvcConfigurer")
    public WebMvcConfigurer napPermissionWebMvcConfigurer(HandlerInterceptor napPermissionInterceptor) {
        return new WebMvcConfigurer() {
            @Override
            public void addInterceptors(InterceptorRegistry registry) {
                registry.addInterceptor(napPermissionInterceptor);
            }
        };
    }
}
