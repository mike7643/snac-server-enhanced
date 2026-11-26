package com.ureca.snac.auth.service;

import com.ureca.snac.auth.dto.TokenDto;
import com.ureca.snac.auth.exception.RefreshTokenException;
import com.ureca.snac.auth.refresh.Refresh;
import com.ureca.snac.auth.repository.RefreshRepository;
import com.ureca.snac.auth.util.JWTUtil;
import com.ureca.snac.common.BaseCode;
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
class ReissueServiceImplTest {

    private static final String EMAIL = "user@snac.com";

    @Mock
    private RefreshRepository refreshRepository;

    @Mock
    private TokenIssuer tokenIssuer;

    private final JWTUtil jwtUtil = JwtTestFactory.jwtUtil();
    private ReissueServiceImpl reissueService;

    @BeforeEach
    void setUp() {
        reissueService = new ReissueServiceImpl(jwtUtil, refreshRepository, tokenIssuer);
    }

    @Test
    void 저장된_리프레시_토큰이면_새_토큰을_발급한다() {
        // given
        String refresh = jwtUtil.createRefreshToken(EMAIL, "USER");
        when(refreshRepository.findByRefresh(refresh)).thenReturn(Optional.of(new Refresh(EMAIL, refresh)));
        when(tokenIssuer.issue(EMAIL, "USER")).thenReturn(new TokenDto("access", "refresh"));

        // when
        TokenDto tokenDto = reissueService.reissue(refresh);

        // then
        assertThat(tokenDto.getAccessToken()).isEqualTo("access");
    }

    @Test
    void 이미_회전되어_저장소에_없는_리프레시_토큰은_거절한다() {
        // given
        String rotatedOut = jwtUtil.createRefreshToken(EMAIL, "USER");
        when(refreshRepository.findByRefresh(rotatedOut)).thenReturn(Optional.empty());

        // when & then
        assertReissueFails(rotatedOut, BaseCode.INVALID_REFRESH_TOKEN);
        verify(tokenIssuer, never()).issue(anyString(), anyString());
    }

    @Test
    void 위조된_리프레시_토큰은_서버_에러가_아닌_INVALID_REFRESH_TOKEN_으로_거절한다() {
        // given
        String forged = JwtTestFactory.jwtUtil(JwtTestFactory.OTHER_SECRET).createRefreshToken(EMAIL, "ADMIN");

        // when & then
        assertReissueFails(forged, BaseCode.INVALID_REFRESH_TOKEN);
        verifyNoInteractions(refreshRepository, tokenIssuer);
    }

    @Test
    void 형식이_잘못된_토큰은_INVALID_REFRESH_TOKEN_으로_거절한다() {
        assertReissueFails("broken.token.value", BaseCode.INVALID_REFRESH_TOKEN);
    }

    @Test
    void 액세스_토큰으로는_재발급할_수_없다() {
        // given
        String access = jwtUtil.createAccessToken(EMAIL, "USER");

        // when & then
        assertReissueFails(access, BaseCode.INVALID_REFRESH_TOKEN);
    }

    @Test
    void 만료된_리프레시_토큰은_저장소에서_지우고_거절한다() {
        // given
        String expired = jwtUtil.createJwt(JWTUtil.REFRESH, EMAIL, "USER", -1_000L);
        Refresh stored = new Refresh(EMAIL, expired);
        when(refreshRepository.findByRefresh(expired)).thenReturn(Optional.of(stored));

        // when & then
        assertReissueFails(expired, BaseCode.REFRESH_TOKEN_EXPIRED);
        verify(refreshRepository).delete(stored);
    }

    @Test
    void 저장된_사용자와_토큰_사용자가_다르면_거절한다() {
        // given
        String refresh = jwtUtil.createRefreshToken(EMAIL, "USER");
        when(refreshRepository.findByRefresh(refresh)).thenReturn(Optional.of(new Refresh("other@snac.com", refresh)));

        // when & then
        assertReissueFails(refresh, BaseCode.INVALID_REFRESH_TOKEN);
        verify(tokenIssuer, never()).issue(any(), any());
    }

    private void assertReissueFails(String refresh, BaseCode expected) {
        assertThatThrownBy(() -> reissueService.reissue(refresh))
                .isInstanceOf(RefreshTokenException.class)
                .extracting(e -> ((RefreshTokenException) e).getBaseCode())
                .isEqualTo(expected);
    }
}
