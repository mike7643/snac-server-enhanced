package com.ureca.snac.auth.service.oauth2;

import com.ureca.snac.auth.util.JWTUtil;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2FlowResolver {

    private final JWTUtil jwtUtil;

    public OAuth2Flow resolveCurrentRequestFlow() {
        // OAuth2 callback 컨텍스트가 없으면 기본적으로 로그인 플로우로 본다.
        ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs == null) {
            log.info("요청 컨텍스트 없음, 로그인 플로우로 처리");
            return OAuth2Flow.login();
        }

        HttpServletRequest request = attrs.getRequest();
        String state = request.getParameter("state");

        try {
            // state가 JWT로 정상 해석되면 연동 플로우로 간주한다.
            String emailFromState = jwtUtil.getUsername(state);
            log.info("state 디코딩 성공, 연동 플로우: email={}", emailFromState);
            return OAuth2Flow.linking(emailFromState);
        } catch (JwtException | IllegalArgumentException e) {
            // state가 없거나 유효하지 않으면 로그인 플로우로 간주한다.
            log.info("state 디코딩 실패, 로그인 플로우");
            return OAuth2Flow.login();
        }
    }
}
