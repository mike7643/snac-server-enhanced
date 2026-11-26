package com.ureca.snac.auth.service.verify;

public interface SnsService {
    // 발송 한도를 예약하고 인증 문자 발송을 요청한다. (실제 발송은 메시지 큐 리스너에서 처리)
    void sendVerificationCode(String phoneNumber);

    void verifyCode(String phoneNumber, String code);

    boolean isPhoneVerified(String phoneNumber);

    // 인증 완료 상태를 1회성으로 소비한다. 이미 사용했거나 인증되지 않았다면 false
    boolean consumePhoneVerification(String phoneNumber);
}
