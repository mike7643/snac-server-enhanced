package com.ureca.snac.auth.service;

import com.ureca.snac.auth.config.AuthCookieProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
@RequiredArgsConstructor
public class AuthCookieService {

    private final AuthCookieProperties properties;

    public Cookie createRefreshCookie(String refreshToken) {
        return buildCookie(properties.getCookieName(), refreshToken, properties.getMaxAgeSeconds());
    }

    public Cookie expireRefreshCookie() {
        return buildCookie(properties.getCookieName(), null, 0);
    }

    public String extractRefreshToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }

        for (Cookie cookie : cookies) {
            if (properties.getCookieName().equals(cookie.getName())) {
                return cookie.getValue();
            }
        }

        return null;
    }

    private Cookie buildCookie(String name, String value, int maxAgeSeconds) {
        Cookie cookie = new Cookie(name, value);
        cookie.setMaxAge(maxAgeSeconds);
        cookie.setPath(properties.getPath());
        cookie.setHttpOnly(properties.isHttpOnly());
        cookie.setSecure(properties.isSecure());
        if (StringUtils.hasText(properties.getDomain())) {
            cookie.setDomain(properties.getDomain());
        }
        return cookie;
    }
}
