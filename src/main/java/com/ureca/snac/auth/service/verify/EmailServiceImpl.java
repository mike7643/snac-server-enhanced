package com.ureca.snac.auth.service.verify;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;


@Slf4j
@Service
@RequiredArgsConstructor
class EmailServiceImpl implements EmailService {

    private final VerificationCodeService verificationCodeService;

    @Override
    public void reserveCodeSend(String email) {
        verificationCodeService.reserveSend(VerificationChannel.EMAIL, email);
    }

    @Override
    public void verifyCode(String email, String code) {
        verificationCodeService.verifyCode(VerificationChannel.EMAIL, email, code);
        log.info("Email < {} > 검증 완료되었음", email);
    }

    @Override
    public boolean isEmailVerified(String email) {
        return verificationCodeService.isVerified(VerificationChannel.EMAIL, email);
    }
}
