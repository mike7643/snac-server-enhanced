package com.ureca.snac.auth.service.verify;

import java.time.Duration;

public interface VerificationPolicy {

    VerificationChannel channel();

    Duration codeTtl();

    Duration verifiedFlagTtl();
}
