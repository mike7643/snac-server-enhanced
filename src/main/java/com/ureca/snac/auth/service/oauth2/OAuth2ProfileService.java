package com.ureca.snac.auth.service.oauth2;

import com.ureca.snac.auth.dto.response.GoogleResponse;
import com.ureca.snac.auth.dto.response.KakaoResponse;
import com.ureca.snac.auth.dto.response.NaverResponse;
import com.ureca.snac.auth.dto.response.OAuth2Response;
import com.ureca.snac.auth.oauth2.SocialProvider;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class OAuth2ProfileService {

    public String extractProviderId(SocialProvider provider, Map<String, Object> attributes) {
        // provider마다 attribute 구조가 달라서, 어댑터 응답 객체로 통일해 providerId를 꺼낸다.
        OAuth2Response response = switch (provider) {
            case NAVER -> new NaverResponse(attributes);
            case GOOGLE -> new GoogleResponse(attributes);
            case KAKAO -> new KakaoResponse(attributes);
        };
        return response.getProviderId();
    }
}
