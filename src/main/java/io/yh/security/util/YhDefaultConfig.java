package io.yh.security.util;

import io.yh.security.config.FilterContext;
import io.yh.security.config.SecurityProperties;
import io.yh.security.config.cookie.CookieProvider;
import io.yh.security.config.cookie.CookieProviderBasic;
import io.yh.security.config.jwt.JwtProvider;
import io.yh.security.config.jwt.JwtProviderBasic;
import io.yh.security.filter.OAuthSuccessHandler;
import io.yh.security.filter.SuccessHandler;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

@Configuration(proxyBeanMethods = false)
public class YhDefaultConfig {

    @Bean
    @ConditionalOnMissingBean(JwtProvider.class)
    public JwtProvider<?> yhJwtProvider() {
        return new JwtProviderBasic();
    }

    @Bean
    @ConditionalOnMissingBean(CookieProvider.class)
    public CookieProvider yhCookieProvider() {
        return new CookieProviderBasic();
    }

    @Bean
    @ConditionalOnMissingBean(SecurityProperties.class)
    public SecurityProperties yhJwtProperties() {
        return new SecurityProperties();
    }

    @Bean
    @ConditionalOnMissingBean(FilterContext.class)
    public FilterContext yhFilterContext(AuthenticationConfiguration authConfig,
                                         JwtProvider<?> jwtProvider,
                                         CookieProvider cookieProvider,
                                         SecurityProperties properties) throws Exception {
        return FilterContext.builder()
                .authenticationManager(authConfig.getAuthenticationManager())
                .jwtProvider(jwtProvider)
                .cookieProvider(cookieProvider)
                .properties(properties)
                .build();
    }

    @Bean
    @ConditionalOnMissingBean(SimpleUrlAuthenticationSuccessHandler.class)
    public SimpleUrlAuthenticationSuccessHandler yhOAuthSuccessHandler(FilterContext context) {
        return new OAuthSuccessHandler(context);
    }

    @Bean
    @ConditionalOnMissingBean(SuccessHandler.class)
    public SuccessHandler yhSuccessHandler(FilterContext context) {
        return new SuccessHandler(context);
    }
}
