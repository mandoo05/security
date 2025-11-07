package io.yh.security.filter;

import io.jsonwebtoken.Claims;
import io.yh.security.config.FilterContext;
import io.yh.security.config.SecurityProperties;
import io.yh.security.config.cookie.CookieProvider;
import io.yh.security.config.jwt.JwtProvider;
import io.yh.security.member.model.YhMemberDetails;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

import javax.crypto.SecretKey;

@RequiredArgsConstructor
public class SuccessHandler {

    private final JwtProvider jwtProvider;
    private final CookieProvider cookieProvider;
    private final SecurityProperties properties;

    public SuccessHandler(FilterContext context) {
        this.jwtProvider = context.jwtProvider();
        this.cookieProvider = context.cookieProvider();
        this.properties = context.properties();
    }

    public void successHandler(HttpServletRequest request,
                               HttpServletResponse response,
                               YhMemberDetails memberDetails) {
        String accessToken = properties.getTokenPrefix() + buildJwtToken(memberDetails);
        response.addHeader(properties.getJwtHeaderString(), accessToken);

        String refreshToken = buildRefreshToken(memberDetails);
        Cookie refreshTokenCookie = cookieProvider.buildCookie(properties.getRefreshHeaderString(), refreshToken, properties.getRefreshTokenExpiration());
        refreshTokenCookie.setPath("/");
        response.addCookie(refreshTokenCookie);

        response.setStatus(HttpStatus.OK.value());
    }

    private String buildJwtToken(YhMemberDetails member) {
        SecretKey jwtKey = jwtProvider.getKey(properties.getJwtSecret());
        Claims jwtClaims = jwtProvider.createJwtClaims(member);
        return jwtProvider.createToken(jwtClaims, properties.getAccessTokenExpiration(), jwtKey);
    }

    private String buildRefreshToken(YhMemberDetails member) {
        SecretKey refreshKey = jwtProvider.getKey(properties.getRefreshSecret());
        Claims refreshClaims = jwtProvider.createRefreshClaims(member);
        return jwtProvider.createToken(refreshClaims, properties.getAccessTokenExpiration(), refreshKey);
    }
}
