package com.ureca.snac.auth.service;

import com.ureca.snac.auth.dto.TokenDto;
import com.ureca.snac.auth.exception.SocialLoginException;
import com.ureca.snac.auth.util.JWTUtil;
import com.ureca.snac.common.BaseCode;
import com.ureca.snac.member.entity.Member;
import com.ureca.snac.auth.oauth2.SocialProvider;
import com.ureca.snac.member.entity.SocialLink;
import com.ureca.snac.member.repository.SocialLinkRepository;
import com.ureca.snac.auth.util.TokenClaims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class SocialLoginServiceImpl implements SocialLoginService {

    private final JWTUtil jwtUtil;
    private final TokenIssuer tokenIssuer;
    private final SocialLinkRepository socialLinkRepository;

    @Override
    @Transactional
    public TokenDto socialLogin(String socialToken) {
        log.info("소셜 로그인 요청 시작");
        if (socialToken == null) {
            // 소셜 토큰이 없는 경우
            log.warn("소셜 토큰 누락으로 로그인 실패");
            throw new SocialLoginException(BaseCode.SOCIAL_TOKEN_INVALID);
        }

        TokenClaims claims;
        try {
            claims = jwtUtil.parse(socialToken);
        } catch (ExpiredJwtException e) {
            // 토큰이 만료된 경우
            log.warn("소셜 토큰 만료");
            throw new SocialLoginException(BaseCode.TOKEN_EXPIRED);
        } catch (JwtException | IllegalArgumentException e) {
            // 서명 불일치, 형식 오류 등 (기존에는 만료로 응답하던 문제 수정)
            log.warn("유효하지 않은 소셜 토큰: {}", e.getClass().getSimpleName());
            throw new SocialLoginException(BaseCode.SOCIAL_TOKEN_INVALID);
        }

        // 토큰 카테고리가 social 인지
        if (!claims.isCategory(JWTUtil.SOCIAL)) {
            // 유효하지 않은 토큰인 경우
            log.warn("잘못된 토큰 카테고리: {}", claims.category());
            throw new SocialLoginException(BaseCode.SOCIAL_TOKEN_INVALID);
        }

        SocialProvider provider = SocialProvider.fromValue(claims.provider());
        String providerId = claims.providerId();
        log.info("프로바이더={}, providerId={} 로 멤버 조회 시도", provider, providerId);

        SocialLink socialLink = socialLinkRepository
                .findByProviderAndProviderId(provider, providerId)
                .orElseThrow(() ->{
                    log.warn("DB에 일치하는 소셜 계정 없음: provider={}, providerId={}", provider, providerId);
                    return new SocialLoginException(BaseCode.SOCIAL_TOKEN_INVALID);
                });
        Member member = socialLink.getMember();

        String username = claims.username();
        if(!member.getEmail().equals(username)){
            log.warn("토큰 사용자 불일치: 토큰 username={}, member.email={}", username, member.getEmail());
            throw new SocialLoginException(BaseCode.SOCIAL_TOKEN_INVALID);
        }

        String role = claims.role();
        log.info("소셜 로그인 검증 완료: email={}, role={}", username, role);

        log.info("토큰 재발급 완료: email={}", username);
        return tokenIssuer.issue(username, role);
    }
}
