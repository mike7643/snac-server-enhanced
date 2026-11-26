package com.ureca.snac.member.service;

import com.ureca.snac.auth.exception.EmailNotVerifiedException;
import com.ureca.snac.auth.exception.PhoneNotVerifiedException;
import com.ureca.snac.auth.service.verify.EmailService;
import com.ureca.snac.auth.service.verify.SnsService;
import com.ureca.snac.auth.service.verify.VerificationCodeService;
import com.ureca.snac.auth.service.verify.VerificationSubject;
import com.ureca.snac.member.dto.request.JoinRequest;
import com.ureca.snac.member.exception.EmailDuplicateException;
import com.ureca.snac.member.repository.MemberRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.LocalDate;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JoinServiceImplTest {

    private static final String EMAIL = "user@snac.com";
    private static final String PHONE = "01012345678";

    @InjectMocks
    private JoinServiceImpl joinService;

    @Mock
    private MemberRepository memberRepository;

    @Mock
    private BCryptPasswordEncoder passwordEncoder;

    @Mock
    private SnsService snsService;

    @Mock
    private EmailService emailService;

    @Mock
    private VerificationCodeService verificationCodeService;

    @Mock
    private RabbitTemplate rabbitTemplate;

    private JoinRequest joinRequest;

    @BeforeEach
    void setUp() {
        joinRequest = JoinRequest.builder()
                .email(EMAIL)
                .password("password1!")
                .name("정유민")
                .phone(PHONE)
                .nickname("snac")
                .birthDate(LocalDate.of(2000, 1, 1))
                .build();
    }

    @Test
    void 회원가입에_성공하면_휴대폰과_이메일_인증_상태를_함께_소비한다() {
        // given
        givenBothVerified();
        when(verificationCodeService.consumeVerified(any(VerificationSubject[].class))).thenReturn(true);

        // when
        joinService.joinProcess(joinRequest);

        // then
        verify(verificationCodeService).consumeVerified(
                VerificationSubject.phone(PHONE), VerificationSubject.email(EMAIL));
        verify(memberRepository).save(any());
    }

    @Test
    void 동시에_다른_요청이_인증_상태를_먼저_소비하면_가입하지_않는다() {
        // given : 확인 시점에는 인증 완료였지만 소비 직전에 다른 요청이 사용
        givenBothVerified();
        when(verificationCodeService.consumeVerified(any(VerificationSubject[].class))).thenReturn(false);
        when(snsService.isPhoneVerified(PHONE)).thenReturn(true, false);

        // when & then
        assertThrows(PhoneNotVerifiedException.class, () -> joinService.joinProcess(joinRequest));
        verify(memberRepository, never()).save(any());
    }

    @Test
    void 이메일이_중복이면_인증_상태를_소비하지_않는다() {
        // given
        givenBothVerified();
        when(memberRepository.existsByEmail(EMAIL)).thenReturn(true);

        // when & then : 다른 이메일로 다시 시도할 때 휴대폰 인증을 다시 받지 않아도 된다
        assertThrows(EmailDuplicateException.class, () -> joinService.joinProcess(joinRequest));
        verify(verificationCodeService, never()).consumeVerified(any(VerificationSubject[].class));
    }

    @Test
    void 이메일_인증이_안되었으면_가입하지_않는다() {
        // given
        when(snsService.isPhoneVerified(PHONE)).thenReturn(true);
        when(emailService.isEmailVerified(EMAIL)).thenReturn(false);

        // when & then
        assertThrows(EmailNotVerifiedException.class, () -> joinService.joinProcess(joinRequest));
        verify(verificationCodeService, never()).consumeVerified(any(VerificationSubject[].class));
        verify(memberRepository, never()).save(any());
    }

    private void givenBothVerified() {
        when(snsService.isPhoneVerified(PHONE)).thenReturn(true);
        when(emailService.isEmailVerified(EMAIL)).thenReturn(true);
    }
}
