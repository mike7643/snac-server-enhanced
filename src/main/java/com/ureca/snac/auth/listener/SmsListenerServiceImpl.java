package com.ureca.snac.auth.listener;

import com.ureca.snac.auth.exception.SmsSendFailedException;
import com.ureca.snac.auth.service.verify.IssuedVerificationCode;
import com.ureca.snac.auth.service.verify.VerificationChannel;
import com.ureca.snac.auth.service.verify.VerificationCodeService;
import com.ureca.snac.config.RabbitMQConfig;
import com.ureca.snac.trade.dto.TradeMessageDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.PublishRequest;
import software.amazon.awssdk.services.sns.model.PublishResponse;

@Slf4j
@Service
@Profile("!scheduler")
@RequiredArgsConstructor
public class SmsListenerServiceImpl implements SmsListenerService {

    private final SnsClient snsClient;
    private final VerificationCodeService verificationCodeService;

    @RabbitListener(queues = RabbitMQConfig.SMS_TRADE_QUEUE)
    public void sendSms(TradeMessageDto tradeMessageDto) {
        for (String phoneNumber : tradeMessageDto.getPhoneList()) {
            String formatPhoneNumber = formatToE164(phoneNumber);

            try {
                PublishResponse response = snsClient.publish(PublishRequest.builder()
                        .message(tradeMessageDto.getMessage())
                        .phoneNumber(formatPhoneNumber)
                        .build());
                log.info("RabbitMQ Sent message {} to {} with messageId {}", tradeMessageDto.getMessage(), phoneNumber, response.messageId());

                Thread.sleep(3000);

            } catch (Exception e) {
                log.error("Error sending SMS to {}: {}", formatPhoneNumber, e.getMessage(), e);
                throw new SmsSendFailedException();
            }
        }
    }

    @RabbitListener(queues = RabbitMQConfig.SMS_AUTH_QUEUE)
    public void sendVerificationCode(String phoneNumber) {
        IssuedVerificationCode issued = verificationCodeService.generateAndStoreCode(VerificationChannel.SMS, phoneNumber);
        String message = String.format("[SNAC] 인증번호[%s]를 입력해주세요. (%d분간 유효)", issued.code(), issued.ttlMinutes());
        String formatPhoneNumber = formatToE164(phoneNumber);

        try {
            PublishResponse response = snsClient.publish(PublishRequest.builder()
                    .message(message)
                    .phoneNumber(formatPhoneNumber)
                    .build());

            // 인증번호가 로그에 남지 않도록 메시지 본문은 기록하지 않는다.
            log.info("Sent verification sms to {} with messageId {}", maskPhoneNumber(phoneNumber), response.messageId());
        } catch (Exception e) {
            log.error("Error sending SMS to {}: {}", formatPhoneNumber, e.getMessage(), e);
            throw new SmsSendFailedException();
        }
    }

    private String maskPhoneNumber(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.length() < 4) {
            return "****";
        }
        return "*".repeat(phoneNumber.length() - 4) + phoneNumber.substring(phoneNumber.length() - 4);
    }

    private String formatToE164(String phoneNumber) {
        if (phoneNumber.startsWith("0")) {
            return "+82" + phoneNumber.substring(1);
        }
        return phoneNumber;
    }
}
