package com.ureca.snac.support;

import com.ureca.snac.auth.util.JWTUtil;
import org.springframework.test.util.ReflectionTestUtils;

public final class JwtTestFactory {

    public static final String SECRET = "snac-test-secret-key-must-be-at-least-32-bytes";
    public static final String OTHER_SECRET = "another-secret-key-for-forged-token-32bytes!";

    private JwtTestFactory() {
    }

    public static JWTUtil jwtUtil() {
        return jwtUtil(SECRET);
    }

    public static JWTUtil jwtUtil(String secret) {
        JWTUtil jwtUtil = new JWTUtil(secret);
        ReflectionTestUtils.setField(jwtUtil, "accessExpirationMs", 60_000L);
        ReflectionTestUtils.setField(jwtUtil, "refreshExpirationMs", 60_000L);
        ReflectionTestUtils.setField(jwtUtil, "socialExpirationMs", 60_000L);
        return jwtUtil;
    }
}
