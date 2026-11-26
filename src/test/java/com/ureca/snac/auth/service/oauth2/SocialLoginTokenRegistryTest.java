package com.ureca.snac.auth.service.oauth2;

import com.ureca.snac.support.ConcurrentExecutor;
import com.ureca.snac.support.RedisContainerSupport;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SocialLoginTokenRegistryTest extends RedisContainerSupport {

    private final SocialLoginTokenRegistry registry = new SocialLoginTokenRegistry(redisTemplate);

    @Test
    void 등록된_토큰은_한_번만_소비할_수_있다() {
        // given
        registry.register("token-id", Duration.ofMinutes(5));

        // when & then
        assertThat(registry.consume("token-id")).isTrue();
        assertThat(registry.consume("token-id")).isFalse();
    }

    @Test
    void 등록되지_않았거나_ID가_없는_토큰은_소비되지_않는다() {
        assertThat(registry.consume("unknown")).isFalse();
        assertThat(registry.consume(null)).isFalse();
    }

    @Test
    void 같은_토큰으로_동시에_교환을_시도해도_한_요청만_성공한다() throws Exception {
        // given
        registry.register("token-id", Duration.ofMinutes(5));

        // when
        List<Boolean> results = ConcurrentExecutor.run(50, i -> () -> registry.consume("token-id"));

        // then
        assertThat(results.stream().filter(Boolean::booleanValue).count()).isEqualTo(1);
    }

    @Test
    void 등록한_토큰은_TTL_이_지나면_사라진다() {
        // when
        registry.register("token-id", Duration.ofMinutes(5));

        // then
        assertThat(redisTemplate.getExpire("social_login_token:token-id")).isPositive().isLessThanOrEqualTo(300);
    }
}
