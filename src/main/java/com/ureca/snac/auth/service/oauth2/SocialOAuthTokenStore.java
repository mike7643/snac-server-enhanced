package com.ureca.snac.auth.service.oauth2;

import com.ureca.snac.auth.oauth2.SocialProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Slf4j
@Component
@RequiredArgsConstructor
public class SocialOAuthTokenStore {

    private final StringRedisTemplate stringRedisTemplate;

    public void saveAccessToken(SocialProvider provider, String providerId, String accessToken, Duration ttl) {
        // provider + providerId 조합 키로 저장해 unlink 시 정확한 토큰을 조회할 수 있게 한다.
        String redisKey = buildKey(provider, providerId);
        stringRedisTemplate.opsForValue().set(redisKey, accessToken, ttl);
        log.info("소셜 계정에서 내려준 AccessToken Redis 저장: {} = {}", redisKey, accessToken);
    }

    private String buildKey(SocialProvider provider, String providerId) {
        return provider + ":" + providerId;
    }
}
