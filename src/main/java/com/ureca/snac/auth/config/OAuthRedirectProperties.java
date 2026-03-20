package com.ureca.snac.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "auth.oauth")
public class OAuthRedirectProperties {

    private String redirectUri = "https://snac-app.com/certification";
}
