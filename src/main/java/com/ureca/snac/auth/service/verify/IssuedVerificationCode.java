package com.ureca.snac.auth.service.verify;

import java.time.Duration;

public record IssuedVerificationCode(String code, Duration ttl) {

    public long ttlMinutes() {
        return Math.max(1, ttl.toMinutes());
    }
}
