package com.ureca.snac.auth.controller;

import com.ureca.snac.auth.dto.TokenDto;
import com.ureca.snac.auth.exception.SocialLoginException;
import com.ureca.snac.auth.service.AuthCookieService;
import com.ureca.snac.auth.service.SocialLoginService;
import com.ureca.snac.common.ApiResponse;
import com.ureca.snac.common.BaseCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class SocialLoginController implements SocialLoginControllerSwagger {

    private final SocialLoginService socialLoginService;
    private final AuthCookieService authCookieService;

    /**
     * Handle social login by exchanging the incoming social access token for application tokens
     * and attaching them to the HTTP response.
     *
     * @param request  the incoming HTTP request; must include an `Authorization` header with the
     *                 value `Bearer <social-token>` containing the social provider's access token
     * @param response the HTTP response which will be modified to include an `Authorization`
     *                 header with `Bearer <accessToken>` and a refresh-token cookie
     * @return         a 200 OK ResponseEntity wrapping an ApiResponse with `BaseCode.OAUTH_LOGIN_SUCCESS`
     */
    @Override
    @PostMapping("/social-login")
    public ResponseEntity<ApiResponse<Void>> socialLogin(HttpServletRequest request, HttpServletResponse response) {
        String socialToken = extractSocialToken(request);

        TokenDto tokenDto = socialLoginService.socialLogin(socialToken);

        response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + tokenDto.getAccessToken());
        response.addCookie(authCookieService.createRefreshCookie(tokenDto.getRefreshToken()));

        return ResponseEntity.ok(ApiResponse.ok(BaseCode.OAUTH_LOGIN_SUCCESS));
    }

    private String extractSocialToken(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        throw new SocialLoginException(BaseCode.SOCIAL_TOKEN_INVALID);
    }
}
