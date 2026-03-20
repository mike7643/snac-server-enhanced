package com.ureca.snac.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ureca.snac.auth.repository.RefreshRepository;
import com.ureca.snac.auth.service.AuthCookieService;
import com.ureca.snac.auth.util.JWTUtil;
import com.ureca.snac.common.ApiResponse;
import com.ureca.snac.common.BaseCode;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

@RequiredArgsConstructor
public class CustomLogoutFilter extends GenericFilterBean {

    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;
    private final AuthCookieService authCookieService;
    private final ObjectMapper objectMapper;

    /**
     * Forwards the generic servlet request and response to the HTTP-specific overload of `doFilter`.
     *
     * @param request the incoming ServletRequest forwarded as an HttpServletRequest
     * @param response the outgoing ServletResponse forwarded as an HttpServletResponse
     * @param chain the filter chain to continue processing
     * @throws IOException if an I/O error occurs during filtering
     * @throws ServletException if a servlet error occurs during filtering
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    /**
     * Handles logout requests sent to POST /api/logout by validating the refresh token,
     * removing it from persistence if present, expiring the refresh cookie, and writing
     * a JSON logout success or error response.
     *
     * <p>The method short-circuits and delegates to the filter chain for non-/api/logout
     * paths or non-POST methods. For logout requests it validates that a refresh token
     * is present, not expired, and categorized as a refresh token; on validation failure
     * it sends an appropriate error response and returns immediately.</p>
     *
     * @param request the incoming HTTP request
     * @param response the HTTP response to be written to
     * @param filterChain the filter chain to delegate to for non-logout requests
     * @throws IOException if an I/O error occurs while writing the response
     * @throws ServletException if the filter chain processing throws a servlet error
     */
    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        String requestUri = request.getRequestURI();
        if (!requestUri.startsWith("/api/logout")) {
            filterChain.doFilter(request, response);
            return;
        }
        String requestMethod = request.getMethod();
        if (!requestMethod.equals("POST")) {
            filterChain.doFilter(request, response);
            return;
        }

        String refresh = authCookieService.extractRefreshToken(request);

        // 널 체크
        if (refresh == null) {
            sendErrorResponse(response, BaseCode.REFRESH_TOKEN_NULL);
            return;
        }

        // 만료 체크
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {
            sendErrorResponse(response, BaseCode.REFRESH_TOKEN_EXPIRED);
            return;
        }

        // 리프레시 맞는지 체크
        if (!"refresh".equals(jwtUtil.getCategory(refresh))) {
            sendErrorResponse(response, BaseCode.INVALID_REFRESH_TOKEN);
            return;
        }

        //레디스에 토큰 존재하면 삭제
        refreshRepository.findByRefresh(refresh).ifPresent(refreshRepository::delete);


        response.addCookie(authCookieService.expireRefreshCookie());


        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json; charset=UTF-8");
        ApiResponse<Void> apiResponse = ApiResponse.ok(BaseCode.LOGOUT_SUCCESS);
        String responseBody = objectMapper.writeValueAsString(apiResponse);
        response.getWriter().print(responseBody);
        response.getWriter().flush();
    }

    /**
     * Write a JSON error response based on the given BaseCode.
     *
     * Sets the HTTP status and content type, serializes ApiResponse.error(baseCode),
     * and writes it to the response writer.
     *
     * @param response the HttpServletResponse to populate
     * @param baseCode the error code and associated HTTP status used to build the response body
     * @throws IOException if an I/O error occurs while writing the response
     */
    private void sendErrorResponse(HttpServletResponse response, BaseCode baseCode) throws IOException {
        response.setStatus(baseCode.getStatus().value());
        response.setContentType("application/json; charset=UTF-8");
        ApiResponse<Void> apiResponse = ApiResponse.error(baseCode);
        String responseBody = objectMapper.writeValueAsString(apiResponse);
        response.getWriter().print(responseBody);
        response.getWriter().flush();
    }
}
