package com.ureca.snac.auth.service.verify;

import java.util.Locale;

public enum VerificationChannel {
    EMAIL("email") {
        // 도메인은 대소문자를 구분하지 않으므로(RFC 5321) 소문자로 맞추고, 로컬 파트는 그대로 둔다.
        @Override
        public String normalize(String target) {
            String trimmed = target.trim();
            int at = trimmed.lastIndexOf('@');
            if (at < 0) {
                return trimmed;
            }
            return trimmed.substring(0, at + 1) + trimmed.substring(at + 1).toLowerCase(Locale.ROOT);
        }

        // 발송 한도는 대소문자만 바꾼 주소로 우회하지 못하도록 전체를 소문자로 묶는다.
        @Override
        public String rateLimitSubject(String target) {
            return normalize(target).toLowerCase(Locale.ROOT);
        }
    },
    SMS("sms") {
        // +8210XXXXXXXX 와 010XXXXXXXX 는 같은 번호이므로 국내 형식으로 맞춘다.
        @Override
        public String normalize(String target) {
            String trimmed = target.trim();
            if (trimmed.startsWith("+82")) {
                return "0" + trimmed.substring(3);
            }
            return trimmed;
        }
    };

    private final String keyPrefix;

    VerificationChannel(String keyPrefix) {
        this.keyPrefix = keyPrefix;
    }

    public String keyPrefix() {
        return keyPrefix;
    }

    // 인증코드 발급/검증/인증 상태에 쓰는 대상 값
    public abstract String normalize(String target);

    // 발송 한도 집계에 쓰는 대상 값
    public String rateLimitSubject(String target) {
        return normalize(target);
    }
}
