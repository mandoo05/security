package io.yh.security.member.model;

import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@AllArgsConstructor
public class YhMemberDetails<T> implements UserDetails, OAuth2User {

    private final T member;
    private final Function<T, String> usernameExtractor;
    private final Function<T, String> passwordExtractor;
    private final Function<T, Set<String>> roleExtractor;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<String> roles = roleExtractor.apply(member);
        if (roles == null) return Set.of();
        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
    }

    @Override
    public String getPassword() {
        return passwordExtractor.apply(member);
    }

    @Override
    public String getUsername() {
        return usernameExtractor.apply(member);
    }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }

    @Override
    public Map<String, Object> getAttributes() {
        return Map.of();
    }

    @Override
    public String getName() {
        return getUsername();
    }
}
