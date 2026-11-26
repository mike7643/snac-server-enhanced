package com.ureca.snac.auth.service.verify;

import com.ureca.snac.auth.exception.EmailSendFailedException;
import com.ureca.snac.config.RabbitMQConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.AmqpException;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;


@Slf4j
@Service
@RequiredArgsConstructor
class EmailServiceImpl implements EmailService {

    private final VerificationCodeService verificationCodeService;
    private final RabbitTemplate rabbitTemplate;

    @Override
    public void sendVerificationCode(String email) {
        String reservationId = verificationCodeService.reserveSend(VerificationChannel.EMAIL, email);
        try {
            rabbitTemplate.convertAndSend(RabbitMQConfig.EMAIL_EXCHANGE, RabbitMQConfig.EMAIL_ROUTING_KEY, email);
        } catch (AmqpException e) {
            // 발송 요청 자체가 실패했으면 한도를 소비하지 않도록 예약을 되돌린다.
            verificationCodeService.releaseSend(VerificationChannel.EMAIL, email, reservationId);
            log.error("인증 메일 발송 요청 발행 실패", e);
            throw new EmailSendFailedException();
        }
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
