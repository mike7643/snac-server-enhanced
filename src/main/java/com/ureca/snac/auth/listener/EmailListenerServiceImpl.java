package com.ureca.snac.auth.listener;

import com.ureca.snac.auth.exception.EmailSendFailedException;
import com.ureca.snac.auth.service.verify.VerificationChannel;
import com.ureca.snac.auth.service.verify.VerificationCodeService;
import com.ureca.snac.auth.util.EmailTool;
import com.ureca.snac.config.RabbitMQConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@Profile("!scheduler")
@RequiredArgsConstructor
public class EmailListenerServiceImpl implements EmailListenerService {

    private final VerificationCodeService verificationCodeService;
    private final EmailTool emailTool;

    @Override
    @RabbitListener(queues = RabbitMQConfig.EMAIL_QUEUE)
    public void sendVerificationCode(String email) {
        String verificationCode = verificationCodeService.generateAndStoreCode(VerificationChannel.EMAIL, email);
        String title = "[SNAC] 이메일 인증 코드";
        String message = String.format("""
            안녕하세요, SNAC입니다.
            요청하신 이메일 인증번호는 다음과 같습니다.
            
            인증번호: %s
            
            SNAC 앱으로 돌아가 화면에 이 인증번호를 입력해주세요.
            인증번호는 5분간 유효합니다.
            
            본인이 요청하지 않으셨다면 이 메일을 무시하셔도 됩니다.
            
            감사합니다.
            SNAC 팀 드림
            """, verificationCode);

        try {
            emailTool.sendEmail(email, title, message);
            log.info("Sent verification email to {}", email);
        } catch (Exception e) {
            log.error("Error sending email to {}: {}", email, e.getMessage(), e);
            throw new EmailSendFailedException();
        }
    }
}
