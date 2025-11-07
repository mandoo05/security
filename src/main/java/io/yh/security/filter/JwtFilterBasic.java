package io.yh.security.filter;

import io.yh.security.config.FilterContext;
import io.yh.security.config.SecurityProperties;
import io.yh.security.config.jwt.JwtProvider;
import io.yh.security.member.model.YhMemberDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;

@RequiredArgsConstructor
public class JwtFilterBasic extends OncePerRequestFilter {

    private final JwtProvider<YhMemberDetails> jwtProvider;
    private final SecurityProperties properties;

    public JwtFilterBasic(FilterContext context) {
        this.jwtProvider = (JwtProvider<YhMemberDetails>) context.jwtProvider();
        this.properties = context.properties();
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String header = request.getHeader(properties.getJwtHeaderString());

        if (header == null || header.isBlank()
                || header.equalsIgnoreCase("null")
                || header.equalsIgnoreCase("undefined")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.replace(properties.getTokenPrefix(), "").trim();
        if (token.isEmpty()) {
            filterChain.doFilter(request, response);
            return;
        }

        SecretKey key = jwtProvider.getKey(properties.getJwtSecret());
        YhMemberDetails memberDetails = jwtProvider.parseJwtToken(token, key);

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                memberDetails,
                null,
                memberDetails.getAuthorities()
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }
}
