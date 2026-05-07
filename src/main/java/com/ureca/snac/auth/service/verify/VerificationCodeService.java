package com.ureca.snac.auth.service.verify;

import com.ureca.snac.auth.exception.VerificationFailedException;
import com.ureca.snac.common.BaseCode;
import com.ureca.snac.common.exception.InternalServerException;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class VerificationCodeService {
    private static final String VERIFIED_MARKER = "__VERIFIED__";
    private static final long RESULT_EXPIRED = -1L;
    private static final long RESULT_MISMATCH = 0L;
    private static final long RESULT_MATCHED_AND_CONSUMED = 1L;

    private static final DefaultRedisScript<Long> CONSUME_CODE_SCRIPT = createConsumeCodeScript();

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

    public String generateAndStoreCode(VerificationChannel channel, String target) {
        // 채널별 정책(TTL)과 채널별 생성 전략(OTP/링크 토큰 등)을 조합해서 저장한다.
        VerificationPolicy policy = getPolicy(channel);
        VerificationTokenGenerator tokenGenerator = getTokenGenerator(channel);
        String code = tokenGenerator.generate();
        redisTemplate.opsForValue().set(codeKey(channel, target), code, policy.codeTtl());
        return code;
    }

    public void verifyCode(VerificationChannel channel,
                           String target,
                           String inputCode,
                           BaseCode expiredCode,
                           BaseCode mismatchCode) {
        VerificationPolicy policy = getPolicy(channel);
        String key = codeKey(channel, target);
        String verifiedTtlSeconds = String.valueOf(Math.max(1, policy.verifiedFlagTtl().toSeconds())); // 초 단위 정수로 받음 ttl은
        // 스크립트 반환값: -1(없음), 0(불일치), 1(일치+verified 상태 전이 완료)
        Long result;
        try {
            result = redisTemplate.execute(
                    CONSUME_CODE_SCRIPT,
                    List.of(key),
                    inputCode,
                    VERIFIED_MARKER,
                    verifiedTtlSeconds
            );
        } catch (DataAccessException e) {
            throw new InternalServerException(BaseCode.VERIFICATION_INTERNAL_ERROR);
        }

        if (result == null) {
            throw new InternalServerException(BaseCode.VERIFICATION_INTERNAL_ERROR);
        }

        if (result == RESULT_EXPIRED) {
            throw new VerificationFailedException(expiredCode);
        }

        if (result == RESULT_MISMATCH) {
            throw new VerificationFailedException(mismatchCode);
        }

        if (result != RESULT_MATCHED_AND_CONSUMED) {
            throw new InternalServerException(BaseCode.VERIFICATION_INTERNAL_ERROR);
        }
    }

    public boolean isVerified(VerificationChannel channel, String target) {
        // 코드 키가 VERIFIED 마커 상태이면 검증 완료로 본다.
        String value = redisTemplate.opsForValue().get(codeKey(channel, target));
        return VERIFIED_MARKER.equals(value);
    }

    private String codeKey(VerificationChannel channel, String target) {
        return channel.keyPrefix() + ":code:" + target;
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

    private static DefaultRedisScript<Long> createConsumeCodeScript() {
        DefaultRedisScript<Long> script = new DefaultRedisScript<>();
        script.setResultType(Long.class);
        script.setScriptText(
                "local v = redis.call('GET', KEYS[1])\n"
                        + "if not v then return -1 end\n"
                        + "if v ~= ARGV[1] then return 0 end\n"
                        + "redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])\n"
                        + "return 1"
        );
        return script;
    }
}
