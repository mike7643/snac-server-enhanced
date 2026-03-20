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

    /**
     * Create a cookie containing the refresh token using the service's configured cookie settings.
     *
     * @param refreshToken the refresh token to store as the cookie value
     * @return a Cookie named per configuration with the given value and configured path, domain (if set), max age, HttpOnly, and Secure flags
     */
    public Cookie createRefreshCookie(String refreshToken) {
        return buildCookie(properties.getCookieName(), refreshToken, properties.getMaxAgeSeconds());
    }

    /**
     * Create a cookie that instructs the client to remove the stored refresh token.
     *
     * @return a Cookie with the configured refresh cookie name, a null value and max-age 0; the cookie's path, domain (if configured), HttpOnly and Secure flags are set from properties
     */
    public Cookie expireRefreshCookie() {
        return buildCookie(properties.getCookieName(), null, 0);
    }

    /**
     * Retrieves the refresh token value from the request's cookies by the configured cookie name.
     *
     * @param request the HTTP servlet request to inspect for cookies
     * @return the refresh token value if present, or {@code null} if no cookies are present or the cookie is not found
     */
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

    /**
     * Construct a Cookie with the given name, value, and max-age, applying path, HttpOnly,
     * secure flag, and optional domain from AuthCookieProperties.
     *
     * @param name the cookie name
     * @param value the cookie value, may be null to clear the cookie
     * @param maxAgeSeconds the cookie max-age in seconds (0 to expire)
     * @return the configured Cookie instance
     */
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
