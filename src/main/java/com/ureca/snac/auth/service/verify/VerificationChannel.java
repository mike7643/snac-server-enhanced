package com.ureca.snac.auth.service.verify;

public enum VerificationChannel {
    EMAIL("email"),
    SMS("sms");

    private final String keyPrefix;

    VerificationChannel(String keyPrefix) {
        this.keyPrefix = keyPrefix;
    }

    public String keyPrefix() {
        return keyPrefix;
    }
}
