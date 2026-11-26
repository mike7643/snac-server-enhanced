package com.ureca.snac.auth.service;

import com.ureca.snac.auth.dto.TokenDto;
import com.ureca.snac.auth.exception.SocialLoginException;
import com.ureca.snac.auth.oauth2.SocialProvider;
import com.ureca.snac.auth.service.oauth2.SocialLoginTokenRegistry;
import com.ureca.snac.auth.util.JWTUtil;
import com.ureca.snac.common.BaseCode;
import com.ureca.snac.member.entity.Member;
import com.ureca.snac.member.entity.SocialLink;
import com.ureca.snac.member.repository.SocialLinkRepository;
import com.ureca.snac.support.JwtTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SocialLoginServiceImplTest {

    private static final String EMAIL = "user@snac.com";
    private static final String TOKEN_ID = "token-id";

    @Mock
    private TokenIssuer tokenIssuer;

    @Mock
    private SocialLinkRepository socialLinkRepository;

    @Mock
    private SocialLoginTokenRegistry socialLoginTokenRegistry;

    private final JWTUtil jwtUtil = JwtTestFactory.jwtUtil();
    private SocialLoginServiceImpl socialLoginService;

    @BeforeEach
    void setUp() {
        socialLoginService = new SocialLoginServiceImpl(jwtUtil, tokenIssuer, socialLoginTokenRegistry, socialLinkRepository);
    }

    @Test
    void 처음_사용하는_소셜_토큰이면_로그인_토큰을_발급한다() {
        // given
        String socialToken = jwtUtil.createSocialToken(TOKEN_ID, EMAIL, "USER", "kakao", "12345");
        when(socialLoginTokenRegistry.consume(TOKEN_ID)).thenReturn(true);
        SocialLink socialLink = mock(SocialLink.class);
        Member member = mock(Member.class);
        when(member.getEmail()).thenReturn(EMAIL);
        when(socialLink.getMember()).thenReturn(member);
        when(socialLinkRepository.findByProviderAndProviderId(SocialProvider.KAKAO, "12345"))
                .thenReturn(Optional.of(socialLink));
        when(tokenIssuer.issue(EMAIL, "USER")).thenReturn(new TokenDto("access", "refresh"));

        // when
        TokenDto tokenDto = socialLoginService.socialLogin(socialToken);

        // then
        assertThat(tokenDto.getAccessToken()).isEqualTo("access");
    }

    @Test
    void 이미_교환에_사용된_소셜_토큰은_재사용할_수_없다() {
        // given
        String socialToken = jwtUtil.createSocialToken(TOKEN_ID, EMAIL, "USER", "kakao", "12345");
        when(socialLoginTokenRegistry.consume(TOKEN_ID)).thenReturn(false);

        // when & then
        assertSocialLoginFails(socialToken, BaseCode.SOCIAL_TOKEN_INVALID);
        verifyNoInteractions(socialLinkRepository, tokenIssuer);
    }

    @Test
    void 위조된_소셜_토큰은_만료가_아닌_유효하지_않은_토큰으로_거절한다() {
        // given
        String forged = JwtTestFactory.jwtUtil(JwtTestFactory.OTHER_SECRET)
                .createSocialToken(TOKEN_ID, EMAIL, "ADMIN", "kakao", "12345");

        // when & then
        assertSocialLoginFails(forged, BaseCode.SOCIAL_TOKEN_INVALID);
        verifyNoInteractions(socialLoginTokenRegistry);
    }

    @Test
    void 만료된_소셜_토큰은_만료로_거절한다() {
        // given
        String expired = jwtUtil.createJwtForSocial(TOKEN_ID, JWTUtil.SOCIAL, EMAIL, "USER", "kakao", "12345", -1_000L);

        // when & then
        assertSocialLoginFails(expired, BaseCode.TOKEN_EXPIRED);
    }

    @Test
    void 액세스_토큰으로는_소셜_로그인을_할_수_없다() {
        // given
        String access = jwtUtil.createAccessToken(EMAIL, "USER");

        // when & then
        assertSocialLoginFails(access, BaseCode.SOCIAL_TOKEN_INVALID);
        verify(socialLoginTokenRegistry, never()).consume(any());
        verify(tokenIssuer, never()).issue(anyString(), anyString());
    }

    private void assertSocialLoginFails(String token, BaseCode expected) {
        assertThatThrownBy(() -> socialLoginService.socialLogin(token))
                .isInstanceOf(SocialLoginException.class)
                .extracting(e -> ((SocialLoginException) e).getBaseCode())
                .isEqualTo(expected);
    }
}
