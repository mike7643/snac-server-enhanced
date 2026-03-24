package com.ureca.snac.auth.service.oauth2;

import com.ureca.snac.auth.oauth2.SocialProvider;
import org.springframework.stereotype.Component;

@Component
public class SocialOAuthRedisKeyFactory {

    public String accessTokenKey(SocialProvider provider, String providerId) {
        return provider.name() + ":" + providerId;
    }
}
