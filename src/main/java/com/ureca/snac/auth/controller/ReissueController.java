package com.ureca.snac.auth.controller;

import com.ureca.snac.auth.dto.TokenDto;
import com.ureca.snac.auth.service.AuthCookieService;
import com.ureca.snac.auth.service.ReissueService;
import com.ureca.snac.common.ApiResponse;
import com.ureca.snac.common.BaseCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class ReissueController implements ReissueControllerSwagger {

    private final ReissueService reissueService;
    private final AuthCookieService authCookieService;

    /**
     * Handles token reissuance by exchanging the request's refresh token for new access and refresh tokens
     * and sending them to the client.
     *
     * The method extracts the refresh token from the incoming request, obtains new tokens from the service,
     * sets the `Authorization` response header with the new access token, and adds a refresh-token cookie to the response.
     *
     * @param request  the incoming HTTP request (used to extract the refresh token)
     * @param response the HTTP response to which the new access token header and refresh cookie are written
     * @return a ResponseEntity containing an ApiResponse<Void> that indicates reissue success
     */
    @Override
    public ResponseEntity<ApiResponse<Void>> reissue(HttpServletRequest request, HttpServletResponse response) {
        String refresh = authCookieService.extractRefreshToken(request);

        TokenDto tokenDto = reissueService.reissue(refresh);

        response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + tokenDto.getAccessToken());
        response.addCookie(authCookieService.createRefreshCookie(tokenDto.getRefreshToken()));

        return ResponseEntity.ok(ApiResponse.ok(BaseCode.REISSUE_SUCCESS));
    }
}
