package io.yh.security.config.jwt;

import io.jsonwebtoken.Claims;
import io.yh.security.member.infra.YhMember;
import io.yh.security.member.model.YhMemberDetails;

public class JwtProviderBasic extends JwtProvider {
    @Override
    public YhMember buildYhMember(Claims claims) {
        return null;
    }

    @Override
    public Claims buildClaim(YhMemberDetails memberDetails) {
        return null;
    }
}
