package com.ureca.snac.auth.service;

import com.ureca.snac.auth.dto.TokenDto;
import com.ureca.snac.auth.exception.RefreshTokenException;
import com.ureca.snac.auth.refresh.Refresh;
import com.ureca.snac.auth.util.JWTUtil;
import com.ureca.snac.auth.repository.RefreshRepository;
import com.ureca.snac.common.BaseCode;
import com.ureca.snac.auth.util.TokenClaims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ReissueServiceImpl implements ReissueService {

    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;
    private final TokenIssuer tokenIssuer;

    @Override
    public TokenDto reissue(String refresh) {

        // 1. 리프레시 토큰 있는지 검증
        if (refresh == null) {
            throw new RefreshTokenException(BaseCode.REFRESH_TOKEN_NULL);
        }

        // 2. 서명/만료 췍
        TokenClaims claims;
        try {
            claims = jwtUtil.parse(refresh);
        } catch (ExpiredJwtException e) {
            refreshRepository.findByRefresh(refresh).ifPresent(refreshRepository::delete);
            throw new RefreshTokenException(BaseCode.REFRESH_TOKEN_EXPIRED);
        } catch (JwtException | IllegalArgumentException e) {
            throw new RefreshTokenException(BaseCode.INVALID_REFRESH_TOKEN);
        }

        // 3. 리프레시 토큰 맞는지 췍
        if (!claims.isCategory(JWTUtil.REFRESH)) {
            throw new RefreshTokenException(BaseCode.INVALID_REFRESH_TOKEN);
        }

        // 4. 레디스에 저장된 토큰인지 확인 (이미 회전되어 폐기된 토큰이면 거절)
        String username = claims.username();
        Refresh storedRefresh = refreshRepository.findByRefresh(refresh)
                .orElseThrow(() -> new RefreshTokenException(BaseCode.INVALID_REFRESH_TOKEN));

        if (!storedRefresh.getEmail().equals(username)) {
            throw new RefreshTokenException(BaseCode.INVALID_REFRESH_TOKEN);
        }
        String role = claims.role();

        // 5. 새 access/refresh 발급 + refresh 저장
        return tokenIssuer.issue(username, role);
    }

}
