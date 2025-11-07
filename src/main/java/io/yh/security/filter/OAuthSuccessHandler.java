package io.yh.security.filter;

import io.yh.security.config.FilterContext;
import io.yh.security.member.model.YhMemberDetails;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import java.io.IOException;

@RequiredArgsConstructor
public class OAuthSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final SuccessHandler successHandler;

    public OAuthSuccessHandler(FilterContext context) {
        this.successHandler = new SuccessHandler(context);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        YhMemberDetails memberDetails = (YhMemberDetails) authentication.getPrincipal();
        successHandler.successHandler(request, response, memberDetails);
    }
}
