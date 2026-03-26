package com.ureca.snac.auth.service.verify;

import com.ureca.snac.auth.exception.VerificationFailedException;
import com.ureca.snac.common.BaseCode;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class VerificationCodeService {

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
        String storedCode = redisTemplate.opsForValue().get(key);

        if (storedCode == null) {
            throw new VerificationFailedException(expiredCode);
        }

        if (!storedCode.equals(inputCode)) {
            throw new VerificationFailedException(mismatchCode);
        }

        // 검증 성공 시 코드는 즉시 삭제하고, 검증 후 조회 가능한 verified 플래그만 남긴다.
        redisTemplate.delete(key);
        redisTemplate.opsForValue().set(verifiedKey(channel, target), "true", policy.verifiedFlagTtl());
    }

    public boolean isVerified(VerificationChannel channel, String target) {
        // true/false로 검증 완료 여부를 확인
        String flag = redisTemplate.opsForValue().get(verifiedKey(channel, target));
        return "true".equals(flag);
    }

    private String codeKey(VerificationChannel channel, String target) {
        return channel.keyPrefix() + ":code:" + target;
    }

    private String verifiedKey(VerificationChannel channel, String target) {
        return channel.keyPrefix() + ":verified:" + target;
    }

    private VerificationPolicy getPolicy(VerificationChannel channel) {
        VerificationPolicy policy = policies.get(channel);
        if (policy == null) {
            throw new IllegalArgumentException("Unsupported verification channel: " + channel);
        }
        return policy;
    }

    private VerificationTokenGenerator getTokenGenerator(VerificationChannel channel) {
        VerificationTokenGenerator tokenGenerator = tokenGenerators.get(channel);
        if (tokenGenerator == null) {
            throw new IllegalArgumentException("Unsupported verification token generator channel: " + channel);
        }
        return tokenGenerator;
    }
}
