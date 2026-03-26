package com.ureca.snac.auth.service.verify;

import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class SmsVerificationPolicy implements VerificationPolicy {

    private static final Duration CODE_TTL = Duration.ofMinutes(3);
    private static final Duration VERIFIED_FLAG_TTL = Duration.ofMinutes(10);

    @Override
    public VerificationChannel channel() {
        return VerificationChannel.SMS;
    }

    @Override
    public Duration codeTtl() {
        return CODE_TTL;
    }

    @Override
    public Duration verifiedFlagTtl() {
        return VERIFIED_FLAG_TTL;
    }
}
