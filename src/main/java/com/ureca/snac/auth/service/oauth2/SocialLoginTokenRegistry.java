package com.ureca.snac.auth.service.oauth2;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * 소셜 로그인 성공 후 프론트로 전달하는 social 토큰을 1회용으로 관리한다.
 * social 토큰은 리다이렉트 URL 쿼리로 전달되어 브라우저 기록/프록시 로그에 남을 수 있으므로,
 * 발급 시 토큰 ID(jti)를 등록하고 로그인 교환 시 삭제해서 재사용을 막는다.
 */
@Component
@RequiredArgsConstructor
public class SocialLoginTokenRegistry {

    private static final String KEY_PREFIX = "social_login_token:";

    private final StringRedisTemplate stringRedisTemplate;

    public void register(String tokenId, Duration ttl) {
        stringRedisTemplate.opsForValue().set(KEY_PREFIX + tokenId, "1", ttl);
    }

    /**
     * DEL 은 단일 명령이라 동시에 같은 토큰으로 교환을 시도해도 한 요청만 true 를 받는다.
     *
     * @return 등록된 토큰을 이번 요청에서 소비했으면 true, 미등록이거나 이미 사용되었으면 false
     */
    public boolean consume(String tokenId) {
        if (tokenId == null) {
            return false;
        }
        return Boolean.TRUE.equals(stringRedisTemplate.delete(KEY_PREFIX + tokenId));
    }
}
