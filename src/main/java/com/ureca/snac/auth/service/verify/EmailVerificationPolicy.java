package com.ureca.snac.auth.service.verify;

import com.ureca.snac.common.BaseCode;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class EmailVerificationPolicy implements VerificationPolicy {

    private static final Duration CODE_TTL = Duration.ofMinutes(3);
    private static final Duration VERIFIED_FLAG_TTL = Duration.ofMinutes(10);
    private static final int MAX_ATTEMPTS = 5;
    private static final Duration RESEND_COOLDOWN = Duration.ofMinutes(1);
    private static final int DAILY_SEND_LIMIT = 10;

    @Override
    public VerificationChannel channel() {
        return VerificationChannel.EMAIL;
    }

    @Override
    public Duration codeTtl() {
        return CODE_TTL;
    }

    @Override
    public Duration verifiedFlagTtl() {
        return VERIFIED_FLAG_TTL;
    }

    @Override
    public int maxAttempts() {
        return MAX_ATTEMPTS;
    }

    @Override
    public Duration resendCooldown() {
        return RESEND_COOLDOWN;
    }

    @Override
    public int dailySendLimit() {
        return DAILY_SEND_LIMIT;
    }

    @Override
    public BaseCode expiredCode() {
        return BaseCode.EMAIL_CODE_VERIFICATION_EXPIRED;
    }

    @Override
    public BaseCode mismatchCode() {
        return BaseCode.EMAIL_CODE_VERIFICATION_MISMATCH;
    }

    @Override
    public BaseCode attemptsExceededCode() {
        return BaseCode.EMAIL_CODE_VERIFICATION_ATTEMPTS_EXCEEDED;
    }
}
