package io.yh.security.member.social;

public interface YhOAuthMemberDetails {
    String getProviderId();
    String getEmail();
    String getName();
    String getPicture();

    default java.util.Map<String, Object> getAttributes() {
        return java.util.Map.of(
                "email", getEmail(),
                "name", getName(),
                "picture", getPicture()
        );
    }
}
