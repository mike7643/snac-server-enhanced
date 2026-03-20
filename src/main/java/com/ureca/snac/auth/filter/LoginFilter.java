package com.ureca.snac.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ureca.snac.auth.dto.TokenDto;
import com.ureca.snac.auth.dto.request.LoginRequest;
import com.ureca.snac.auth.service.TokenIssuer;
import com.ureca.snac.auth.util.CookieUtil;
import com.ureca.snac.common.ApiResponse;
import com.ureca.snac.common.BaseCode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final TokenIssuer tokenIssuer;
    private final ObjectMapper objectMapper;

    public LoginFilter(AuthenticationManager authenticationManager, TokenIssuer tokenIssuer, ObjectMapper objectMapper) {
        this.authenticationManager = authenticationManager;
        this.tokenIssuer = tokenIssuer;
        this.objectMapper = objectMapper;

        setFilterProcessesUrl("/api/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // JSON 파싱해야됨.. 필터 단이라서 @RequestBody 없음

        LoginRequest loginRequest;
        try {
            loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        String username = loginRequest.getEmail();
        String password = loginRequest.getPassword();

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

        return authenticationManager.authenticate(authToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException {
        String username = authentication.getName();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iter = authorities.iterator();
        GrantedAuthority auth = iter.next();
        String role = auth.getAuthority();

        TokenDto tokenDto = tokenIssuer.issue(username, role);

        response.setHeader(HttpHeaders.AUTHORIZATION,"Bearer "+ tokenDto.getAccessToken());
        response.addCookie(CookieUtil.createCookie("refresh", tokenDto.getRefreshToken()));

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json; charset=UTF-8");
        ApiResponse<Void> apiResponse = ApiResponse.ok(BaseCode.LOGIN_SUCCESS);
        String responseBody = objectMapper.writeValueAsString(apiResponse);
        response.getWriter().print(responseBody);
        response.getWriter().flush();
    }
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException {

        response.setContentType("application/json; charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        ApiResponse<Void> apiResponse = ApiResponse.error(BaseCode.LOGIN_FAILED);
        String responseBody = objectMapper.writeValueAsString(apiResponse);
        response.getWriter().print(responseBody);
        response.getWriter().flush();
    }
}
