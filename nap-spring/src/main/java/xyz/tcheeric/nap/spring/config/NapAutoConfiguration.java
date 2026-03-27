package xyz.tcheeric.nap.spring.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import xyz.tcheeric.nap.server.*;
import xyz.tcheeric.nap.server.store.InMemoryChallengeStore;
import xyz.tcheeric.nap.server.store.InMemorySessionStore;

@AutoConfiguration
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
                               AclResolver aclResolver, NapProperties properties) {
        return NapServer.create(NapServerOptions.builder()
                .challengeStore(challengeStore)
                .sessionStore(sessionStore)
                .aclResolver(aclResolver)
                .challengeTtlSeconds(properties.challengeTtlSeconds())
                .sessionTtlSeconds(properties.sessionTtlSeconds())
                .resultCacheTtlSeconds(properties.resultCacheTtlSeconds())
                .maxClockSkewSeconds(properties.maxClockSkewSeconds())
                .build());
    }
}
