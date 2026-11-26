package com.ureca.snac.auth.service.verify;

import com.ureca.snac.auth.exception.EmailSendFailedException;
import com.ureca.snac.auth.exception.SmsSendFailedException;
import com.ureca.snac.auth.exception.VerificationSendLimitException;
import com.ureca.snac.common.BaseCode;
import com.ureca.snac.config.RabbitMQConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.amqp.AmqpConnectException;
import org.springframework.amqp.rabbit.core.RabbitTemplate;

import java.net.ConnectException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EmailServiceImplTest {

    private static final String EMAIL = "user@snac.com";

    @InjectMocks
    private EmailServiceImpl emailService;

    @Mock
    private VerificationCodeService verificationCodeService;

    @Mock
    private RabbitTemplate rabbitTemplate;

    @Test
    void 발송_요청_발행에_성공하면_예약을_유지한다() {
        // when
        emailService.sendVerificationCode(EMAIL);

        // then
        verify(verificationCodeService).reserveSend(VerificationChannel.EMAIL, EMAIL);
        verify(rabbitTemplate).convertAndSend(RabbitMQConfig.EMAIL_EXCHANGE, RabbitMQConfig.EMAIL_ROUTING_KEY, (Object) EMAIL);
        verify(verificationCodeService, never()).releaseSend(any(), anyString());
    }

    @Test
    void 발송_요청_발행에_실패하면_예약을_되돌린다() {
        // given
        doThrow(new AmqpConnectException(new ConnectException("down")))
                .when(rabbitTemplate).convertAndSend(anyString(), anyString(), (Object) anyString());

        // when & then
        assertThrows(EmailSendFailedException.class, () -> emailService.sendVerificationCode(EMAIL));
        verify(verificationCodeService).releaseSend(VerificationChannel.EMAIL, EMAIL);
    }

    @Test
    void 발송_한도에_걸리면_발행하지_않는다() {
        // given
        doThrow(new VerificationSendLimitException(BaseCode.VERIFICATION_RESEND_TOO_EARLY))
                .when(verificationCodeService).reserveSend(VerificationChannel.EMAIL, EMAIL);

        // when & then
        assertThrows(VerificationSendLimitException.class, () -> emailService.sendVerificationCode(EMAIL));
        verifyNoInteractions(rabbitTemplate);
    }

    @Test
    void 문자_발송_요청_발행에_실패해도_예약을_되돌린다() {
        // given
        SnsServiceImpl snsService = new SnsServiceImpl(verificationCodeService, rabbitTemplate);
        doThrow(new AmqpConnectException(new ConnectException("down")))
                .when(rabbitTemplate).convertAndSend(anyString(), anyString(), (Object) anyString());

        // when & then
        assertThrows(SmsSendFailedException.class, () -> snsService.sendVerificationCode("01012345678"));
        verify(verificationCodeService).releaseSend(VerificationChannel.SMS, "01012345678");
    }
}
