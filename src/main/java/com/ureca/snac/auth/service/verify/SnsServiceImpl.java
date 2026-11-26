package com.ureca.snac.auth.service.verify;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SnsServiceImpl implements SnsService {

    private final VerificationCodeService verificationCodeService;

    @Override
    public void reserveCodeSend(String phoneNumber) {
        verificationCodeService.reserveSend(VerificationChannel.SMS, phoneNumber);
    }

    @Override
    public void verifyCode(String phoneNumber, String code) {
        verificationCodeService.verifyCode(VerificationChannel.SMS, phoneNumber, code);
    }

    @Override
    public boolean isPhoneVerified(String phoneNumber) {
        return verificationCodeService.isVerified(VerificationChannel.SMS, phoneNumber);
    }
}
