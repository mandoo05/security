package io.yh.security.config.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.yh.security.member.infra.YhMember;
import io.yh.security.member.model.YhMemberDetails;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;

public abstract class JwtProvider {
    public SecretKey getKey(String secretKey) {
        return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    public Claims createJwtClaims(YhMemberDetails memberDetails) {
        return buildJwtClaim(memberDetails);
    }

    public Claims buildJwtClaim(YhMemberDetails memberDetails) {
        return buildClaim(memberDetails);
    }

    public YhMemberDetails parseJwtToken(String token, SecretKey key) {
        Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
        YhMember member = buildJwtYhMember(claims);
        return new YhMemberDetails(member);
    }

    public YhMember buildJwtYhMember(Claims claims) {
        return buildYhMember(claims);
    }


    public Claims createRefreshClaims(YhMemberDetails memberDetails) {
        return buildRefreshClaim(memberDetails);
    }

    public Claims buildRefreshClaim(YhMemberDetails memberDetails) {
        return buildClaim(memberDetails);
    }

    public YhMemberDetails parseRefreshToken(String token, SecretKey key) {
        Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
        YhMember member = buildRefreshYhMember(claims);
        return new YhMemberDetails(member);
    }

    public YhMember buildRefreshYhMember(Claims claims) {
        return buildYhMember(claims);
    }

    public abstract YhMember buildYhMember(Claims claims);
    public abstract Claims buildClaim(YhMemberDetails memberDetails);

    public String createToken(
            Claims claims, int validityInMilliseconds, SecretKey key) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(key)
                .compact();
    }
}
