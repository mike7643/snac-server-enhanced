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
    private final SocialOAuthRedisKeyFactory keyFactory;

    public void saveAccessToken(SocialProvider provider, String providerId, String accessToken, Duration ttl) {
        String redisKey = keyFactory.accessTokenKey(provider, providerId);
        stringRedisTemplate.opsForValue().set(redisKey, accessToken, ttl);
        log.info("소셜 계정에서 내려준 AccessToken Redis 저장: {} = {}", redisKey, accessToken);
    }

    public String getAccessToken(SocialProvider provider, String providerId) {
        String redisKey = keyFactory.accessTokenKey(provider, providerId);
        return stringRedisTemplate.opsForValue().get(redisKey);
    }

    public void deleteAccessToken(SocialProvider provider, String providerId) {
        String redisKey = keyFactory.accessTokenKey(provider, providerId);
        stringRedisTemplate.delete(redisKey);
    }
}
