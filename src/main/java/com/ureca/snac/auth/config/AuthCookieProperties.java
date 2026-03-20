package com.ureca.snac.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "auth.cookie") // 타입 변환을 위해서
public class AuthCookieProperties {

    private String cookieName = "refresh";
    private String domain = "snac-app.com";
    private String path = "/";
    private int maxAgeSeconds = 24 * 60 * 60;
    private boolean secure = false;
    private boolean httpOnly = true;
}
