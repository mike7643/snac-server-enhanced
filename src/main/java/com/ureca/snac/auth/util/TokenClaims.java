package com.ureca.snac.auth.util;

/**
 * 서명 검증을 마친 JWT 의 클레임.
 * 클레임마다 토큰을 다시 파싱하지 않도록 한 번에 꺼내 담는다.
 */
public record TokenClaims(String category, String username, String role, String provider, String providerId) {

    public boolean isCategory(String expected) {
        return expected.equals(category);
    }
}
