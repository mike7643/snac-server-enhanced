package com.ureca.snac.auth.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;

@Component
public class JWTUtil {

    public static final String ACCESS = "access";
    public static final String REFRESH = "refresh";
    public static final String SOCIAL = "social";

    private SecretKey secretKey;

    @Value("${spring.jwt.access-expiration}")
    private long accessExpirationMs;

    @Value("${spring.jwt.refresh-expiration}")
    private long refreshExpirationMs;

    @Value("${spring.jwt.social-expiration}")
    private long socialExpirationMs;

    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    /**
     * 서명과 만료를 검증하고 클레임을 꺼낸다.
     *
     * @throws io.jsonwebtoken.ExpiredJwtException 만료된 토큰
     * @throws io.jsonwebtoken.JwtException        서명 불일치, 형식 오류 등 유효하지 않은 토큰
     * @throws IllegalArgumentException            토큰이 비어 있는 경우
     */
    public TokenClaims parse(String token) {
        // JWT의 서명(시그니처)을 서버의 Secret Key로 대조한다. 서명이 다르거나 만료되었으면 예외가 발생한다.
        Claims claims = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
        return new TokenClaims(
                claims.getId(),
                claims.get("category", String.class),
                claims.get("username", String.class),
                claims.get("role", String.class),
                claims.get("provider", String.class),
                claims.get("providerId", String.class)
        );
    }

    public String createJwt(String category, String username, String role, Long expiredMs) {
        return Jwts.builder()
                .claim("category", category)
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))//언제 발행 ?
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey) // 시그니처를 만들어서 암호화 진행
                .compact();
    }

    public String createJwtForSocial(String tokenId, String category, String username, String role, String provider, String providerId, Long expiredMs) {
        return Jwts.builder()
                .id(tokenId)
                .claim("category", category)
                .claim("username", username)
                .claim("role", role)
                .claim("provider", provider)
                .claim("providerId", providerId)
                .issuedAt(new Date(System.currentTimeMillis()))//언제 발행 ?
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey) // 시그니처를 만들어서 암호화 진행
                .compact();
    }

    public String createAccessToken(String username, String role) {
        return createJwt(ACCESS, username, role, accessExpirationMs);
    }

    public String createRefreshToken(String username, String role) {
        return createJwt(REFRESH, username, role, refreshExpirationMs);
    }

    public String createSocialToken(String tokenId, String username, String role, String provider, String providerId) {
        return createJwtForSocial(tokenId, SOCIAL, username, role, provider, providerId, socialExpirationMs);
    }

    public Duration socialTokenTtl() {
        return Duration.ofMillis(socialExpirationMs);
    }
}
