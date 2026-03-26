package com.ureca.snac.auth.service.verify;

import com.ureca.snac.common.BaseCode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SnsServiceImpl implements SnsService {

    private final VerificationCodeService verificationCodeService;

    @Override
    public void verifyCode(String phoneNumber, String code) {
        verificationCodeService.verifyCode(
                VerificationChannel.SMS,
                phoneNumber,
                code,
                BaseCode.SMS_CODE_VERIFICATION_EXPIRED,
                BaseCode.SMS_CODE_VERIFICATION_MISMATCH
        );
    }

    @Override
    public boolean isPhoneVerified(String phoneNumber) {
        return verificationCodeService.isVerified(VerificationChannel.SMS, phoneNumber);
    }
}
