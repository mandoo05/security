package io.yh.security.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "yh-jwt")
public class SecurityProperties {
    private String jwtSecret;
    private String refreshSecret;

    private String jwtHeaderString = "Authorization";
    private String refreshHeaderString = "Refresh";
    private String tokenPrefix = "Bearer ";

    private int accessTokenExpiration = 3600000;
    private int refreshTokenExpiration = 604800000;

    private String issuer;
    private String algorithm;
}
