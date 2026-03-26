package com.ureca.snac.auth.service;

import com.ureca.snac.auth.dto.CustomOAuth2User;
import com.ureca.snac.auth.oauth2.SocialProvider;
import com.ureca.snac.auth.service.oauth2.OAuth2Flow;
import com.ureca.snac.auth.service.oauth2.OAuth2FlowResolver;
import com.ureca.snac.auth.service.oauth2.OAuth2ProfileService;
import com.ureca.snac.auth.service.oauth2.SocialAccountService;
import com.ureca.snac.auth.service.oauth2.SocialOAuthTokenStore;
import com.ureca.snac.member.entity.Member;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;


@Service
@Slf4j
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    // 소셜 provider access token은 unlink 시 즉시 사용되므로 매우 짧게 보관한다.
    private static final Duration SOCIAL_ACCESS_TOKEN_TTL = Duration.ofMinutes(1);

    private final OAuth2ProfileService oAuth2ProfileService;
    private final OAuth2FlowResolver oAuth2FlowResolver;
    private final SocialOAuthTokenStore socialOAuthTokenStore;
    private final SocialAccountService socialAccountService;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 1) OAuth provider에서 사용자 attribute를 조회한다.
        log.info("loadUser 메소드 시작");
        String accessToken = userRequest.getAccessToken().getTokenValue();
        log.debug("OAuth2 accessToken={}", accessToken);

        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.debug("OAuth2 사용자 정보={}", oAuth2User.getAttributes());

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        SocialProvider provider = SocialProvider.fromValue(registrationId);
        log.info("registrationId: {}", registrationId);

        // Provider별 응답 스키마 차이를 숨기고 providerId를 일관되게 추출한다.
        String providerId = oAuth2ProfileService.extractProviderId(provider, oAuth2User.getAttributes());
        log.info("provider: {}, providerId: {}", provider, providerId);

        // 2) state 토큰 해석 결과로 연동 / 로그인 플로우를 분기한다.
        OAuth2Flow flow = oAuth2FlowResolver.resolveCurrentRequestFlow();
        // 3) unlink 등 후속 동작에 사용하기 위해 소셜 access token을 단기 보관한다.
        socialOAuthTokenStore.saveAccessToken(provider, providerId, accessToken, SOCIAL_ACCESS_TOKEN_TTL);

        if (flow.linking()) {
            // 4-1) 연동 플로우: state의 이메일 계정과 providerId를 연결한다.
            Member member = socialAccountService.linkOrGetMember(provider, providerId, flow.emailFromState());
            return new CustomOAuth2User(member, registrationId, providerId, oAuth2User.getAttributes());
        }

        // 4-2) 로그인 플로우: 이미 연동된 계정을 찾아 principal을 구성한다.
        Member existingMember = socialAccountService.getLinkedMemberForLogin(provider, providerId);
        log.info("기존 회원 로그인: email={}", existingMember.getEmail());
        return new CustomOAuth2User(existingMember, provider.getValue(), providerId, oAuth2User.getAttributes());
    }
}
