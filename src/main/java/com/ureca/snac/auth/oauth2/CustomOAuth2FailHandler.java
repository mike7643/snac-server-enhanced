package com.ureca.snac.auth.oauth2;

import com.ureca.snac.auth.config.OAuthRedirectProperties;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomOAuth2FailHandler implements AuthenticationFailureHandler {

    private final OAuthRedirectProperties oAuthRedirectProperties;

    /**
     * Handles an OAuth2 authentication failure by extracting an OAuth error code (when available)
     * and redirecting the client to the configured OAuth redirect URI with the error code as a
     * query parameter.
     *
     * <p>If the exception contains an OAuth2 error, that error's code is used; otherwise
     * the literal "unknown_error" is appended.</p>
     *
     * @param request   the current HTTP request
     * @param response  the current HTTP response
     * @param exception the authentication exception that triggered the failure
     * @throws IOException if sending the redirect fails
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException{
        String errorCode = "unknown_error";
        if (exception instanceof OAuth2AuthenticationException oauthEx && oauthEx.getError() != null) {
            errorCode = oauthEx.getError().getErrorCode();
        }

        log.info("errorCode={}", errorCode);
        String redirectUrl = UriComponentsBuilder.fromUriString(oAuthRedirectProperties.getRedirectUri())
                .queryParam("error", errorCode)
                .build().toUriString();

        log.info("redirectUrl={}", redirectUrl);
        response.sendRedirect(redirectUrl);
    }
}
