package com.ureca.snac.auth.service.verify;

import com.ureca.snac.auth.exception.VerificationFailedException;
import com.ureca.snac.auth.exception.VerificationSendLimitException;
import com.ureca.snac.common.BaseCode;
import com.ureca.snac.common.exception.BaseCustomException;
import com.ureca.snac.support.ConcurrentExecutor;
import com.ureca.snac.support.RedisContainerSupport;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class VerificationCodeServiceTest extends RedisContainerSupport {

    private static final String SUCCESS = "SUCCESS";
    private static final String EMAIL = "user@snac.com";

    private final VerificationCodeService verificationCodeService = createService(new EmailVerificationPolicy());

    @Test
    void 올바른_코드로_검증하면_인증_완료_상태가_된다() {
        // given
        String code = verificationCodeService.generateAndStoreCode(VerificationChannel.EMAIL, EMAIL).code();

        // when
        verificationCodeService.verifyCode(VerificationChannel.EMAIL, EMAIL, code);

        // then
        assertThat(verificationCodeService.isVerified(VerificationChannel.EMAIL, EMAIL)).isTrue();
    }

    @Test
    void 같은_코드로_동시에_검증해도_성공은_한_번뿐이다() throws Exception {
        // given
        String code = verificationCodeService.generateAndStoreCode(VerificationChannel.EMAIL, EMAIL).code();

        // when
        List<String> results = ConcurrentExecutor.run(100,
                i -> () -> attemptVerify(EMAIL, code));

        // then
        assertThat(count(results, SUCCESS)).isEqualTo(1);
        assertThat(count(results, BaseCode.EMAIL_CODE_VERIFICATION_EXPIRED.name())).isEqualTo(99);
        assertThat(verificationCodeService.isVerified(VerificationChannel.EMAIL, EMAIL)).isTrue();
    }

    @Test
    void 오답이_최대_시도_횟수에_도달하면_코드가_폐기되어_정답도_통과하지_못한다() {
        // given
        String code = verificationCodeService.generateAndStoreCode(VerificationChannel.EMAIL, EMAIL).code();
        String wrong = wrongCodeOf(code);

        // when : 4번째까지는 불일치, 5번째 오답에서 코드 폐기
        for (int i = 0; i < 4; i++) {
            assertThat(attemptVerify(EMAIL, wrong)).isEqualTo(BaseCode.EMAIL_CODE_VERIFICATION_MISMATCH.name());
        }
        assertThat(attemptVerify(EMAIL, wrong)).isEqualTo(BaseCode.EMAIL_CODE_VERIFICATION_ATTEMPTS_EXCEEDED.name());

        // then
        assertThat(attemptVerify(EMAIL, code)).isEqualTo(BaseCode.EMAIL_CODE_VERIFICATION_EXPIRED.name());
        assertThat(verificationCodeService.isVerified(VerificationChannel.EMAIL, EMAIL)).isFalse();
    }

    @Test
    void 오답을_동시에_대량으로_보내도_오답_판정_기회는_최대_시도_횟수를_넘지_않는다() throws Exception {
        // given
        String code = verificationCodeService.generateAndStoreCode(VerificationChannel.EMAIL, EMAIL).code();
        int maxAttempts = new EmailVerificationPolicy().maxAttempts();

        // when : 서로 다른 오답 200개를 동시에 대입
        List<String> results = ConcurrentExecutor.run(200,
                i -> () -> attemptVerify(EMAIL, bruteForceGuess(code, i)));

        // then : 코드와 비교된 요청은 정확히 maxAttempts 번, 나머지는 이미 폐기된 코드로 판정
        assertThat(count(results, BaseCode.EMAIL_CODE_VERIFICATION_MISMATCH.name())).isEqualTo(maxAttempts - 1);
        assertThat(count(results, BaseCode.EMAIL_CODE_VERIFICATION_ATTEMPTS_EXCEEDED.name())).isEqualTo(1);
        assertThat(count(results, BaseCode.EMAIL_CODE_VERIFICATION_EXPIRED.name())).isEqualTo(200 - maxAttempts);
        assertThat(attemptVerify(EMAIL, code)).isEqualTo(BaseCode.EMAIL_CODE_VERIFICATION_EXPIRED.name());
    }

    @Test
    void 새_코드를_발급하면_이전_실패_횟수가_초기화된다() {
        // given
        String firstCode = verificationCodeService.generateAndStoreCode(VerificationChannel.EMAIL, EMAIL).code();
        for (int i = 0; i < 4; i++) {
            attemptVerify(EMAIL, wrongCodeOf(firstCode));
        }

        // when
        String secondCode = verificationCodeService.generateAndStoreCode(VerificationChannel.EMAIL, EMAIL).code();

        // then : 초기화되지 않았다면 다음 오답에서 바로 폐기된다
        assertThat(attemptVerify(EMAIL, wrongCodeOf(secondCode))).isEqualTo(BaseCode.EMAIL_CODE_VERIFICATION_MISMATCH.name());
        assertThat(attemptVerify(EMAIL, secondCode)).isEqualTo(SUCCESS);
    }

    @Test
    void 실패_횟수_키는_코드보다_오래_남지_않는다() {
        // given
        String code = verificationCodeService.generateAndStoreCode(VerificationChannel.EMAIL, EMAIL).code();

        // when
        attemptVerify(EMAIL, wrongCodeOf(code));

        // then
        Long codeTtl = redisTemplate.getExpire(VerificationKeys.code(VerificationChannel.EMAIL, EMAIL));
        Long attemptTtl = redisTemplate.getExpire(VerificationKeys.attempt(VerificationChannel.EMAIL, EMAIL));
        assertThat(attemptTtl).isPositive().isLessThanOrEqualTo(codeTtl);
    }

    @Test
    void 인증_완료_후에는_마커_문자열을_입력해도_검증에_성공하지_못한다() {
        // given
        String code = verificationCodeService.generateAndStoreCode(VerificationChannel.EMAIL, EMAIL).code();
        verificationCodeService.verifyCode(VerificationChannel.EMAIL, EMAIL, code);

        // when
        String result = attemptVerify(EMAIL, "__VERIFIED__");

        // then
        assertThat(result).isEqualTo(BaseCode.EMAIL_CODE_VERIFICATION_EXPIRED.name());
    }

    @Test
    void 재발송_대기_시간_안에_다시_요청하면_거절된다() {
        // given
        verificationCodeService.reserveSend(VerificationChannel.EMAIL, EMAIL);

        // when & then
        assertThatThrownBy(() -> verificationCodeService.reserveSend(VerificationChannel.EMAIL, EMAIL))
                .isInstanceOf(VerificationSendLimitException.class)
                .extracting(e -> ((BaseCustomException) e).getBaseCode())
                .isEqualTo(BaseCode.VERIFICATION_RESEND_TOO_EARLY);
    }

    @Test
    void 발송_요청이_동시에_몰려도_한_건만_예약된다() throws Exception {
        // when
        List<String> results = ConcurrentExecutor.run(50,
                i -> () -> attemptReserve(verificationCodeService, EMAIL));

        // then
        assertThat(count(results, SUCCESS)).isEqualTo(1);
        assertThat(count(results, BaseCode.VERIFICATION_RESEND_TOO_EARLY.name())).isEqualTo(49);
    }

    @Test
    void 일일_발송_한도를_넘으면_거절되고_거절된_요청은_횟수에_포함되지_않는다() throws Exception {
        // given : 재발송 대기 시간을 1ms 로 줄인 정책
        VerificationCodeService service = createService(new ShortCooldownPolicy(3));

        // when
        for (int i = 0; i < 3; i++) {
            assertThat(attemptReserve(service, EMAIL)).isEqualTo(SUCCESS);
            Thread.sleep(5);
        }
        String exceeded = attemptReserve(service, EMAIL);

        // then
        assertThat(exceeded).isEqualTo(BaseCode.VERIFICATION_DAILY_LIMIT_EXCEEDED.name());
        assertThat(redisTemplate.opsForValue().get(VerificationKeys.dailySend(VerificationChannel.EMAIL, EMAIL))).isEqualTo("3");
        assertThat(redisTemplate.getExpire(VerificationKeys.dailySend(VerificationChannel.EMAIL, EMAIL))).isPositive();
    }

    @Test
    void 발송_한도는_대상별로_따로_관리된다() {
        // given
        verificationCodeService.reserveSend(VerificationChannel.EMAIL, EMAIL);

        // when & then
        assertThat(attemptReserve(verificationCodeService, "other@snac.com")).isEqualTo(SUCCESS);
    }

    @Test
    void 발행_실패로_예약을_되돌리면_바로_다시_요청할_수_있고_일일_횟수도_복구된다() {
        // given
        verificationCodeService.reserveSend(VerificationChannel.EMAIL, EMAIL);

        // when
        verificationCodeService.releaseSend(VerificationChannel.EMAIL, EMAIL);

        // then
        assertThat(redisTemplate.opsForValue().get(VerificationKeys.dailySend(VerificationChannel.EMAIL, EMAIL))).isEqualTo("0");
        assertThat(attemptReserve(verificationCodeService, EMAIL)).isEqualTo(SUCCESS);
    }

    @Test
    void 집계_키가_없을_때_예약을_되돌려도_횟수가_음수가_되지_않는다() {
        // when
        verificationCodeService.releaseSend(VerificationChannel.EMAIL, EMAIL);

        // then
        assertThat(redisTemplate.hasKey(VerificationKeys.dailySend(VerificationChannel.EMAIL, EMAIL))).isFalse();
    }

    @Test
    void 대소문자만_다른_이메일로는_발송_한도를_우회할_수_없다() {
        // given
        verificationCodeService.reserveSend(VerificationChannel.EMAIL, "user@snac.com");

        // when & then
        assertThat(attemptReserve(verificationCodeService, "user@SNAC.COM")).isEqualTo(BaseCode.VERIFICATION_RESEND_TOO_EARLY.name());
        assertThat(attemptReserve(verificationCodeService, "USER@snac.com")).isEqualTo(BaseCode.VERIFICATION_RESEND_TOO_EARLY.name());
    }

    @Test
    void 이메일_도메인_대소문자가_달라도_같은_대상으로_검증된다() {
        // given
        String code = verificationCodeService.generateAndStoreCode(VerificationChannel.EMAIL, "user@SNAC.com").code();

        // when
        verificationCodeService.verifyCode(VerificationChannel.EMAIL, "user@snac.com", code);

        // then
        assertThat(verificationCodeService.isVerified(VerificationChannel.EMAIL, "user@Snac.Com")).isTrue();
    }

    @Test
    void 국제_형식과_국내_형식_휴대폰_번호는_같은_대상으로_처리된다() {
        // given
        String code = verificationCodeService.generateAndStoreCode(VerificationChannel.SMS, "+821012345678").code();

        // when
        verificationCodeService.verifyCode(VerificationChannel.SMS, "01012345678", code);

        // then
        assertThat(verificationCodeService.isVerified(VerificationChannel.SMS, "+821012345678")).isTrue();
    }

    @Test
    void 같은_대상의_키는_같은_해시태그를_쓰고_키_이름에_대상_값이_노출되지_않는다() {
        // given : 해시태그를 깨뜨릴 수 있는 문자가 섞인 주소
        String target = "}weird{@snac.com";

        // when
        String codeKey = VerificationKeys.code(VerificationChannel.EMAIL, target);
        String attemptKey = VerificationKeys.attempt(VerificationChannel.EMAIL, target);
        String cooldownKey = VerificationKeys.cooldown(VerificationChannel.EMAIL, target);
        String dailyKey = VerificationKeys.dailySend(VerificationChannel.EMAIL, target);

        // then
        assertThat(hashTagOf(codeKey)).isNotBlank().isEqualTo(hashTagOf(attemptKey));
        assertThat(hashTagOf(cooldownKey)).isNotBlank().isEqualTo(hashTagOf(dailyKey));
        assertThat(codeKey).doesNotContain("snac.com");
        String code = verificationCodeService.generateAndStoreCode(VerificationChannel.EMAIL, target).code();
        assertThat(attemptVerify(target, code)).isEqualTo(SUCCESS);
    }

    // Redis Cluster 규칙: 첫 '{' 와 그 뒤 첫 '}' 사이 문자열이 슬롯 계산에 쓰인다.
    private static String hashTagOf(String key) {
        int open = key.indexOf('{');
        int close = key.indexOf('}', open + 1);
        return key.substring(open + 1, close);
    }

    private String attemptVerify(String target, String code) {
        try {
            verificationCodeService.verifyCode(VerificationChannel.EMAIL, target, code);
            return SUCCESS;
        } catch (VerificationFailedException e) {
            return e.getBaseCode().name();
        }
    }

    private String attemptReserve(VerificationCodeService service, String target) {
        try {
            service.reserveSend(VerificationChannel.EMAIL, target);
            return SUCCESS;
        } catch (VerificationSendLimitException e) {
            return e.getBaseCode().name();
        }
    }

    private static long count(List<String> results, String value) {
        Map<String, Long> counts = results.stream()
                .collect(Collectors.groupingBy(Function.identity(), Collectors.counting()));
        return counts.getOrDefault(value, 0L);
    }

    private static String wrongCodeOf(String code) {
        return code.equals("000000") ? "111111" : "000000";
    }

    // 정답을 피해 서로 다른 6자리 오답을 만든다.
    private static String bruteForceGuess(String code, int index) {
        String guess = String.format("%06d", index);
        return guess.equals(code) ? String.format("%06d", 999_999 - index) : guess;
    }

    private static VerificationCodeService createService(VerificationPolicy emailPolicy) {
        NumericCodeGenerator generator = new NumericCodeGenerator();
        return new VerificationCodeService(
                redisTemplate,
                List.of(emailPolicy, new SmsVerificationPolicy()),
                List.of(new EmailVerificationTokenGenerator(generator), new SmsVerificationTokenGenerator(generator))
        );
    }

    private static class ShortCooldownPolicy extends EmailVerificationPolicy {
        private final int dailySendLimit;

        private ShortCooldownPolicy(int dailySendLimit) {
            this.dailySendLimit = dailySendLimit;
        }

        @Override
        public Duration resendCooldown() {
            return Duration.ofMillis(1);
        }

        @Override
        public int dailySendLimit() {
            return dailySendLimit;
        }
    }
}
