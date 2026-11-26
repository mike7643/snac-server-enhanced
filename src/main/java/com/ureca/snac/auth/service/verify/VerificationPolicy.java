package com.ureca.snac.auth.service.verify;

import com.ureca.snac.common.BaseCode;

import java.time.Duration;

public interface VerificationPolicy {

    VerificationChannel channel();

    Duration codeTtl();

    Duration verifiedFlagTtl();

    // 하나의 인증코드로 허용하는 최대 검증 시도 횟수 (초과 시 코드 폐기)
    int maxAttempts();

    // 같은 대상에게 인증코드를 다시 보낼 수 있을 때까지의 대기 시간
    Duration resendCooldown();

    // 하루(첫 발송 시점부터 24시간) 동안 같은 대상에게 보낼 수 있는 최대 발송 횟수
    int dailySendLimit();

    BaseCode expiredCode();

    BaseCode mismatchCode();

    BaseCode attemptsExceededCode();
}
