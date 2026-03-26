package com.ureca.snac.auth.service.verify;

public interface SnsService {
    void verifyCode(String phoneNumber, String code);

    boolean isPhoneVerified(String phoneNumber);
}
