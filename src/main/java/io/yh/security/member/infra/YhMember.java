package io.yh.security.member.infra;

import java.util.Set;
import java.util.UUID;

public interface YhMember {
    UUID getId();
    String getUsername();
    String getPassword();
    String getProvider();
    String getEmail();
    String getName();
    String getPicture();
    String getStatus();
    Set<String> getRoles();
}
