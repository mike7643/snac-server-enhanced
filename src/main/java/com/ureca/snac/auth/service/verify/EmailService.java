package com.ureca.snac.auth.service.verify;


public interface EmailService {
    // 발송 한도를 예약하고 인증 메일 발송을 요청한다. (실제 발송은 메시지 큐 리스너에서 처리)
    void sendVerificationCode(String email);

    void verifyCode(String email, String code);

    boolean isEmailVerified(String email);
}
