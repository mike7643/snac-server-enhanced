package com.ureca.snac.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ureca.snac.auth.util.JWTUtil;
import com.ureca.snac.support.JwtTestFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;

class JWTFilterTest {

    private static final String EMAIL = "user@snac.com";

    private final JWTUtil jwtUtil = JwtTestFactory.jwtUtil();
    private final JWTFilter jwtFilter = new JWTFilter(new ObjectMapper().findAndRegisterModules(), jwtUtil);

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void 유효한_액세스_토큰이면_인증_정보를_등록하고_다음_필터로_넘긴다() throws Exception {
        // given
        String token = jwtUtil.createAccessToken(EMAIL, "USER");

        // when
        Result result = doFilter(token);

        // then
        assertThat(result.passed()).isTrue();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo(EMAIL);
    }

    @Test
    void 만료된_토큰이면_401_TOKEN_EXPIRED_로_응답한다() throws Exception {
        // given
        String token = jwtUtil.createJwt(JWTUtil.ACCESS, EMAIL, "USER", -1_000L);

        // when
        Result result = doFilter(token);

        // then
        assertThat(result.passed()).isFalse();
        assertThat(result.response().getStatus()).isEqualTo(401);
        assertThat(result.response().getContentAsString()).contains("TOKEN_EXPIRED_401");
    }

    @Test
    void 다른_키로_서명된_위조_토큰이면_예외_대신_401_TOKEN_INVALID_로_응답한다() throws Exception {
        // given
        String forged = JwtTestFactory.jwtUtil(JwtTestFactory.OTHER_SECRET).createAccessToken(EMAIL, "ADMIN");

        // when
        Result result = doFilter(forged);

        // then
        assertThat(result.passed()).isFalse();
        assertThat(result.response().getStatus()).isEqualTo(401);
        assertThat(result.response().getContentAsString()).contains("TOKEN_INVALID_401");
    }

    @Test
    void 형식이_잘못된_토큰이면_401_TOKEN_INVALID_로_응답한다() throws Exception {
        // when
        Result result = doFilter("not-a-jwt");

        // then
        assertThat(result.passed()).isFalse();
        assertThat(result.response().getStatus()).isEqualTo(401);
        assertThat(result.response().getContentAsString()).contains("TOKEN_INVALID_401");
    }

    @Test
    void 리프레시_토큰으로는_API에_접근할_수_없다() throws Exception {
        // given
        String refresh = jwtUtil.createRefreshToken(EMAIL, "USER");

        // when
        Result result = doFilter(refresh);

        // then
        assertThat(result.passed()).isFalse();
        assertThat(result.response().getStatus()).isEqualTo(401);
    }

    @Test
    void 카테고리가_없는_토큰도_NPE_없이_401로_응답한다() throws Exception {
        // given
        String noCategory = jwtUtil.createJwt(null, EMAIL, "USER", 60_000L);

        // when
        Result result = doFilter(noCategory);

        // then
        assertThat(result.passed()).isFalse();
        assertThat(result.response().getStatus()).isEqualTo(401);
    }

    @Test
    void 토큰이_없으면_인증_없이_다음_필터로_넘긴다() throws Exception {
        // when
        Result result = doFilter(null);

        // then
        assertThat(result.passed()).isTrue();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    private Result doFilter(String token) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/member/me");
        if (token != null) {
            request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        }
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        jwtFilter.doFilter(request, response, chain);
        return new Result(chain.getRequest() != null, response);
    }

    private record Result(boolean passed, MockHttpServletResponse response) {
    }
}
