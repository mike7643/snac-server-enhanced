package com.ureca.snac.auth.service.verify;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * 인증 관련 Redis 키 생성 규칙.
 * <p>
 * 대상 값(이메일/휴대폰 번호)을 그대로 쓰지 않고 SHA-256 해시를 해시태그로 사용한다.
 * - 같은 대상의 키들이 Redis Cluster 에서 항상 같은 슬롯에 놓여 다중 키 스크립트가 CROSSSLOT 으로 실패하지 않는다.
 *   (대상 값에 '{', '}' 가 섞여 해시태그가 깨지는 경우 방지)
 * - 키 이름에 개인정보가 노출되지 않는다.
 */
final class VerificationKeys {

    private VerificationKeys() {
    }

    static String code(VerificationChannel channel, String target) {
        return channel.keyPrefix() + ":code:" + tag(channel.normalize(target));
    }

    static String attempt(VerificationChannel channel, String target) {
        return channel.keyPrefix() + ":attempt:" + tag(channel.normalize(target));
    }

    static String cooldown(VerificationChannel channel, String target) {
        return channel.keyPrefix() + ":cooldown:" + tag(channel.rateLimitSubject(target));
    }

    static String dailySend(VerificationChannel channel, String target) {
        return channel.keyPrefix() + ":daily:" + tag(channel.rateLimitSubject(target));
    }

    private static String tag(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return "{" + HexFormat.of().formatHex(digest, 0, 16) + "}";
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 을 사용할 수 없습니다.", e);
        }
    }
}
