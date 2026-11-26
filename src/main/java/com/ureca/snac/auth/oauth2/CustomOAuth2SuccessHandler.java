package com.ureca.snac.auth.oauth2;

import com.ureca.snac.auth.config.OAuthRedirectProperties;
import com.ureca.snac.auth.dto.CustomOAuth2User;
import com.ureca.snac.auth.service.oauth2.SocialLoginTokenRegistry;
import com.ureca.snac.auth.util.JWTUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomOAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;
    private final OAuthRedirectProperties oAuthRedirectProperties;
    private final SocialLoginTokenRegistry socialLoginTokenRegistry;

    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        log.info("OAuth2 로그인 성공. CustomOAuth2SuccessHandler 시작");

        log.debug("요청 URI: {}", request.getRequestURI());

        CustomOAuth2User user = (CustomOAuth2User) authentication.getPrincipal();

        String provider   = user.getProvider();
        String providerId = user.getProviderId();

        log.info("provider: {}, providerId: {}", provider, providerId);

        String email = user.getEmail();
        String role = authentication.getAuthorities().iterator().next().getAuthority();
        log.info("사용자 이메일: {}, 권한: {}", email, role);

        // social 토큰은 1회용: 토큰 ID를 등록해 두고 /api/social-login 교환 시 소비한다.
        String tokenId = UUID.randomUUID().toString();
        socialLoginTokenRegistry.register(tokenId, jwtUtil.socialTokenTtl());
        String socialToken = jwtUtil.createSocialToken(tokenId, email, role, provider, providerId);

        String redirectUrl = UriComponentsBuilder.fromUriString(oAuthRedirectProperties.getRedirectUri())
                .queryParam("social", socialToken)
                .build().toUriString();

        // 토큰이 포함된 URL 은 로그에 남기지 않는다.
        log.info("social 토큰 발급 후 프론트로 리다이렉트");
        response.sendRedirect(redirectUrl);

        log.info("CustomOAuth2SuccessHandler 처리 완료");
    }
}
