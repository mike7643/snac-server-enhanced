package com.ureca.snac.auth.service.verify;

import com.ureca.snac.auth.exception.SmsSendFailedException;
import com.ureca.snac.config.RabbitMQConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.AmqpException;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class SnsServiceImpl implements SnsService {

    private final VerificationCodeService verificationCodeService;
    private final RabbitTemplate rabbitTemplate;

    @Override
    public void sendVerificationCode(String phoneNumber) {
        verificationCodeService.reserveSend(VerificationChannel.SMS, phoneNumber);
        try {
            rabbitTemplate.convertAndSend(RabbitMQConfig.SMS_EXCHANGE, RabbitMQConfig.SMS_AUTH_ROUTING_KEY, phoneNumber);
        } catch (AmqpException e) {
            // 발송 요청 자체가 실패했으면 한도를 소비하지 않도록 예약을 되돌린다.
            verificationCodeService.releaseSend(VerificationChannel.SMS, phoneNumber);
            log.error("인증 문자 발송 요청 발행 실패", e);
            throw new SmsSendFailedException();
        }
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
