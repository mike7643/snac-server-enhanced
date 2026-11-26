package com.ureca.snac.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ureca.snac.auth.dto.CustomUserDetails;
import com.ureca.snac.auth.util.JWTUtil;
import com.ureca.snac.common.ApiResponse;
import com.ureca.snac.common.BaseCode;
import com.ureca.snac.member.entity.Member;
import com.ureca.snac.member.Role;
import com.ureca.snac.auth.util.TokenClaims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final ObjectMapper objectMapper;
    private final JWTUtil jwtUtil;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();

        return path.equals("/api/social-login");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        // 토큰이 없다면 다음 필터로 넘김
        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        String accessToken = header.substring(7);

        // 서명/만료 검증 (위변조, 형식 오류 토큰도 500 이 아닌 401 로 응답)
        TokenClaims claims;
        try {
            claims = jwtUtil.parse(accessToken);
        } catch (ExpiredJwtException e) {
            sendErrorResponse(response, BaseCode.TOKEN_EXPIRED);
            return;
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("유효하지 않은 액세스 토큰: {}", e.getClass().getSimpleName());
            sendErrorResponse(response, BaseCode.TOKEN_INVALID);
            return;
        }

        // 토큰이 access 맞는지 확인 (refresh, social 토큰으로 API 접근 차단)
        Role role = resolveRole(claims.role());
        if (!claims.isCategory(JWTUtil.ACCESS) || claims.username() == null || role == null) {
            sendErrorResponse(response, BaseCode.TOKEN_INVALID);
            return;
        }

        Member member = Member.builder()
                .email(claims.username())
                .role(role)
                .build();
        CustomUserDetails customUserDetails = new CustomUserDetails(member);

        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }


    private Role resolveRole(String role) {
        if (role == null) {
            return null;
        }
        try {
            return Role.valueOf(role);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private void sendErrorResponse(HttpServletResponse response, BaseCode code) throws IOException {
        response.setContentType("application/json; charset=UTF-8");
        response.setStatus(code.getStatus().value());
        ApiResponse<Void> apiResponse = ApiResponse.error(code);
        String responseBody = objectMapper.writeValueAsString(apiResponse);
        response.getWriter().print(responseBody);
        response.getWriter().flush();
    }
}