package com.ureca.snac.auth.service.verify;

import com.ureca.snac.common.BaseCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
class EmailServiceImpl implements EmailService {

    private final VerificationCodeService verificationCodeService;

    @Override
    public void verifyCode(String email, String code) {
        verificationCodeService.verifyCode(
                VerificationChannel.EMAIL,
                email,
                code,
                BaseCode.EMAIL_CODE_VERIFICATION_EXPIRED,
                BaseCode.EMAIL_CODE_VERIFICATION_MISMATCH
        );
        log.info("Email < {} > 검증 완료되었음", email);
    }

    @Override
    public boolean isEmailVerified(String email) {
        return verificationCodeService.isVerified(VerificationChannel.EMAIL, email);
    }
}
