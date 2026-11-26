package com.ureca.snac.auth.service.verify;

import com.ureca.snac.auth.exception.VerificationFailedException;
import com.ureca.snac.auth.exception.VerificationSendLimitException;
import com.ureca.snac.common.BaseCode;
import com.ureca.snac.common.exception.InternalServerException;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class VerificationCodeService {
    private static final String VERIFIED_MARKER = "__VERIFIED__";
    private static final Duration DAILY_SEND_WINDOW = Duration.ofDays(1);

    // 검증 스크립트 반환값
    private static final long RESULT_ATTEMPTS_EXCEEDED = -2L;
    private static final long RESULT_EXPIRED = -1L;
    private static final long RESULT_MISMATCH = 0L;
    private static final long RESULT_MATCHED_AND_CONSUMED = 1L;

    // 발송 예약 스크립트 반환값
    private static final long SEND_DAILY_LIMIT_EXCEEDED = -2L;
    private static final long SEND_COOLDOWN = -1L;
    private static final long SEND_RESERVED = 1L;

    private static final DefaultRedisScript<Long> ISSUE_CODE_SCRIPT = createIssueCodeScript();
    private static final DefaultRedisScript<Long> CONSUME_CODE_SCRIPT = createConsumeCodeScript();
    private static final DefaultRedisScript<Long> RESERVE_SEND_SCRIPT = createReserveSendScript();
    private static final DefaultRedisScript<Long> RELEASE_SEND_SCRIPT = createReleaseSendScript();
    private static final DefaultRedisScript<Long> CONSUME_VERIFIED_SCRIPT = createConsumeVerifiedScript();

    private final StringRedisTemplate redisTemplate;
    private final Map<VerificationChannel, VerificationPolicy> policies;
    private final Map<VerificationChannel, VerificationTokenGenerator> tokenGenerators;

    public VerificationCodeService(StringRedisTemplate redisTemplate,
                                   List<VerificationPolicy> policies,
                                   List<VerificationTokenGenerator> tokenGenerators) {
        this.redisTemplate = redisTemplate;
        this.policies = policies.stream()
                .collect(Collectors.toUnmodifiableMap(VerificationPolicy::channel, Function.identity()));
        this.tokenGenerators = tokenGenerators.stream()
                .collect(Collectors.toUnmodifiableMap(VerificationTokenGenerator::channel, Function.identity()));
    }

    /**
     * 발송 요청 단계에서 재발송 대기 시간과 일일 발송 한도를 원자적으로 확인하고 1회분을 예약한다.
     * 메시지 큐에 발행하기 전에 호출해서, 한도를 넘는 요청은 문자/메일 비용이 발생하기 전에 거절한다.
     *
     * @return 이번 예약의 식별자 (발행 실패 시 이 예약만 되돌리기 위해 사용)
     */
    public String reserveSend(VerificationChannel channel, String target) {
        VerificationPolicy policy = getPolicy(channel);
        String reservationId = UUID.randomUUID().toString();
        Long result = executeScript(
                RESERVE_SEND_SCRIPT,
                List.of(VerificationKeys.cooldown(channel, target), VerificationKeys.dailySend(channel, target)),
                String.valueOf(toPositiveMillis(policy.resendCooldown())),
                String.valueOf(policy.dailySendLimit()),
                String.valueOf(DAILY_SEND_WINDOW.toMillis()),
                reservationId
        );

        if (result == SEND_COOLDOWN) {
            throw new VerificationSendLimitException(BaseCode.VERIFICATION_RESEND_TOO_EARLY);
        }
        if (result == SEND_DAILY_LIMIT_EXCEEDED) {
            throw new VerificationSendLimitException(BaseCode.VERIFICATION_DAILY_LIMIT_EXCEEDED);
        }
        if (result != SEND_RESERVED) {
            throw new InternalServerException(BaseCode.VERIFICATION_INTERNAL_ERROR);
        }
        return reservationId;
    }

    /**
     * 예약 후 메시지 발행에 실패했을 때 그 예약만 되돌린다.
     * 재발송 대기 키가 아직 이 예약의 것일 때만 대기를 풀고 일일 발송 횟수를 1 줄인다.
     * 발행이 지연되는 사이 대기 시간이 지나 다른 요청이 새로 예약했다면, 새 예약의 대기 키와 횟수는 건드리지 않는다.
     *
     * @return 예약을 되돌렸으면 true, 이미 이 예약의 대기 시간이 지나 되돌릴 것이 없으면 false
     */
    public boolean releaseSend(VerificationChannel channel, String target, String reservationId) {
        Long result = executeScript(
                RELEASE_SEND_SCRIPT,
                List.of(VerificationKeys.cooldown(channel, target), VerificationKeys.dailySend(channel, target)),
                reservationId
        );
        return result == 1L;
    }

    public IssuedVerificationCode generateAndStoreCode(VerificationChannel channel, String target) {
        // 채널별 정책(TTL)과 채널별 생성 전략(OTP/링크 토큰 등)을 조합해서 저장한다.
        // 새 코드를 발급하면 이전 코드에 누적된 실패 횟수도 함께 초기화한다.
        VerificationPolicy policy = getPolicy(channel);
        String code = getTokenGenerator(channel).generate();
        executeScript(
                ISSUE_CODE_SCRIPT,
                List.of(VerificationKeys.code(channel, target), VerificationKeys.attempt(channel, target)),
                code,
                String.valueOf(toPositiveMillis(policy.codeTtl()))
        );
        return new IssuedVerificationCode(code, policy.codeTtl());
    }

    public void verifyCode(VerificationChannel channel, String target, String inputCode) {
        VerificationPolicy policy = getPolicy(channel);
        // 스크립트 반환값: -2(시도 초과로 코드 폐기), -1(없음), 0(불일치), 1(일치+verified 상태 전이 완료)
        Long result = executeScript(
                CONSUME_CODE_SCRIPT,
                List.of(VerificationKeys.code(channel, target), VerificationKeys.attempt(channel, target)),
                inputCode,
                VERIFIED_MARKER,
                String.valueOf(toPositiveMillis(policy.verifiedFlagTtl())),
                String.valueOf(policy.maxAttempts())
        );

        if (result == RESULT_EXPIRED) {
            throw new VerificationFailedException(policy.expiredCode());
        }

        if (result == RESULT_MISMATCH) {
            throw new VerificationFailedException(policy.mismatchCode());
        }

        if (result == RESULT_ATTEMPTS_EXCEEDED) {
            throw new VerificationFailedException(policy.attemptsExceededCode());
        }

        if (result != RESULT_MATCHED_AND_CONSUMED) {
            throw new InternalServerException(BaseCode.VERIFICATION_INTERNAL_ERROR);
        }
    }

    public boolean isVerified(VerificationChannel channel, String target) {
        // 코드 키가 VERIFIED 마커 상태이면 검증 완료로 본다.
        String value = redisTemplate.opsForValue().get(VerificationKeys.code(channel, target));
        return VERIFIED_MARKER.equals(value);
    }

    /**
     * 인증 완료 상태를 사용하는 시점(회원가입, 비밀번호 재설정 등)에 1회성으로 소비한다.
     * 여러 대상을 넘기면 모두 인증 완료 상태일 때만 한꺼번에 소비하고, 하나라도 아니면 아무것도 소비하지 않는다.
     *
     * @return 소비에 성공하면 true, 인증 완료 상태가 아니거나 이미 소비되었으면 false
     */
    public boolean consumeVerified(VerificationSubject... subjects) {
        if (subjects.length == 0) {
            throw new InternalServerException(BaseCode.VERIFICATION_INTERNAL_ERROR);
        }
        List<String> keys = Arrays.stream(subjects)
                .map(subject -> VerificationKeys.code(subject.channel(), subject.target()))
                .toList();
        return executeScript(CONSUME_VERIFIED_SCRIPT, keys, VERIFIED_MARKER) == 1L;
    }

    private Long executeScript(DefaultRedisScript<Long> script, List<String> keys, Object... args) {
        Long result;
        try {
            result = redisTemplate.execute(script, keys, args);
        } catch (DataAccessException e) {
            throw new InternalServerException(BaseCode.VERIFICATION_INTERNAL_ERROR);
        }
        if (result == null) {
            throw new InternalServerException(BaseCode.VERIFICATION_INTERNAL_ERROR);
        }
        return result;
    }

    private static long toPositiveMillis(Duration duration) {
        return Math.max(1, duration.toMillis());
    }

    private VerificationPolicy getPolicy(VerificationChannel channel) {
        VerificationPolicy policy = policies.get(channel);
        if (policy == null) {
            throw new InternalServerException(BaseCode.VERIFICATION_INTERNAL_ERROR);
        }
        return policy;
    }

    private VerificationTokenGenerator getTokenGenerator(VerificationChannel channel) {
        VerificationTokenGenerator tokenGenerator = tokenGenerators.get(channel);
        if (tokenGenerator == null) {
            throw new InternalServerException(BaseCode.VERIFICATION_INTERNAL_ERROR);
        }
        return tokenGenerator;
    }

    private static DefaultRedisScript<Long> createIssueCodeScript() {
        // KEYS[1]=코드, KEYS[2]=실패 횟수 / ARGV[1]=코드, ARGV[2]=코드 TTL(ms)
        return script(
                "redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])\n"
                        + "redis.call('DEL', KEYS[2])\n"
                        + "return 1"
        );
    }

    private static DefaultRedisScript<Long> createConsumeCodeScript() {
        // KEYS[1]=코드, KEYS[2]=실패 횟수
        // ARGV[1]=입력 코드, ARGV[2]=verified 마커, ARGV[3]=verified TTL(ms), ARGV[4]=최대 시도 횟수
        // 조회 -> 비교 -> (실패 횟수 증가 | 코드 폐기 | verified 상태 전이)를 한 번에 수행해
        // 동시 요청이 몰려도 오답 판정 기회가 최대 시도 횟수를 넘지 않도록 한다.
        return script(
                "local v = redis.call('GET', KEYS[1])\n"
                        + "if (not v) or v == ARGV[2] then return -1 end\n"
                        + "if v ~= ARGV[1] then\n"
                        + "  local attempts = redis.call('INCR', KEYS[2])\n"
                        + "  if attempts == 1 then\n"
                        + "    local ttl = redis.call('PTTL', KEYS[1])\n"
                        + "    if ttl > 0 then redis.call('PEXPIRE', KEYS[2], ttl) end\n"
                        + "  end\n"
                        + "  if attempts >= tonumber(ARGV[4]) then\n"
                        + "    redis.call('DEL', KEYS[1], KEYS[2])\n"
                        + "    return -2\n"
                        + "  end\n"
                        + "  return 0\n"
                        + "end\n"
                        + "redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3])\n"
                        + "redis.call('DEL', KEYS[2])\n"
                        + "return 1"
        );
    }

    private static DefaultRedisScript<Long> createReserveSendScript() {
        // KEYS[1]=재발송 대기, KEYS[2]=일일 발송 횟수
        // ARGV[1]=재발송 대기(ms), ARGV[2]=일일 한도, ARGV[3]=일일 집계 구간(ms), ARGV[4]=예약 식별자
        // 한도에 걸린 요청은 횟수에 포함하지 않는다.
        return script(
                "if redis.call('EXISTS', KEYS[1]) == 1 then return -1 end\n"
                        + "local sent = tonumber(redis.call('GET', KEYS[2]) or '0')\n"
                        + "if sent >= tonumber(ARGV[2]) then return -2 end\n"
                        + "sent = redis.call('INCR', KEYS[2])\n"
                        + "if sent == 1 then redis.call('PEXPIRE', KEYS[2], ARGV[3]) end\n"
                        + "redis.call('SET', KEYS[1], ARGV[4], 'PX', ARGV[1])\n"
                        + "return 1"
        );
    }

    private static DefaultRedisScript<Long> createReleaseSendScript() {
        // KEYS[1]=재발송 대기, KEYS[2]=일일 발송 횟수 / ARGV[1]=예약 식별자
        // 대기 키가 살아 있는 동안에는 다른 예약이 끼어들 수 없으므로, 대기 키가 내 것이면 일일 횟수도 내 예약분이 포함된 구간이다.
        return script(
                "if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end\n"
                        + "redis.call('DEL', KEYS[1])\n"
                        + "local sent = tonumber(redis.call('GET', KEYS[2]) or '0')\n"
                        + "if sent > 0 then redis.call('DECR', KEYS[2]) end\n"
                        + "return 1"
        );
    }

    private static DefaultRedisScript<Long> createConsumeVerifiedScript() {
        // KEYS[n]=코드(인증 완료 시 마커 상태) / ARGV[1]=verified 마커
        // 확인과 삭제 사이에 다른 요청이 끼어들면 같은 인증 상태가 두 번 사용될 수 있어 한 번에 처리한다.
        // 서로 다른 대상(이메일+휴대폰)은 해시태그가 달라 Redis Cluster 에서는 같은 슬롯을 보장하지 않는다. (현재 단일 노드 운영)
        return script(
                "for _, key in ipairs(KEYS) do\n"
                        + "  if redis.call('GET', key) ~= ARGV[1] then return 0 end\n"
                        + "end\n"
                        + "for _, key in ipairs(KEYS) do redis.call('DEL', key) end\n"
                        + "return 1"
        );
    }

    private static DefaultRedisScript<Long> script(String text) {
        DefaultRedisScript<Long> script = new DefaultRedisScript<>();
        script.setResultType(Long.class);
        script.setScriptText(text);
        return script;
    }
}
