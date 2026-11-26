package com.ureca.snac.support;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Lua 스크립트와 원자성은 Mock 으로 검증할 수 없어서 실제 Redis 컨테이너를 띄워 테스트한다.
 * 컨테이너는 테스트 JVM 당 한 번만 띄우고, 각 테스트 전에 데이터를 비운다.
 */
public abstract class RedisContainerSupport {

    private static final GenericContainer<?> REDIS =
            new GenericContainer<>(DockerImageName.parse("redis:7.2-alpine")).withExposedPorts(6379);

    protected static final StringRedisTemplate redisTemplate;

    static {
        REDIS.start();
        LettuceConnectionFactory connectionFactory =
                new LettuceConnectionFactory(REDIS.getHost(), REDIS.getMappedPort(6379));
        connectionFactory.afterPropertiesSet();
        connectionFactory.start();
        redisTemplate = new StringRedisTemplate(connectionFactory);
    }

    @BeforeEach
    void flushRedis() {
        redisTemplate.execute((RedisCallback<Object>) connection -> {
            connection.serverCommands().flushAll();
            return null;
        });
    }
}
