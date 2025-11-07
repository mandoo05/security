package io.yh.security.config.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import java.util.Map;

public class JwtProviderBasic extends JwtProvider<Map<String, Object>> {

    @Override
    public Claims buildClaims(Map<String, Object> member) {
        Claims claims = Jwts.claims();
        claims.putAll(member);
        return claims;
    }

    @Override
    public Map<String, Object> parseClaims(Claims claims) {
        return claims;
    }
}
