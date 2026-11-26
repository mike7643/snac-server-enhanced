package com.ureca.snac.auth.service.verify;

public record VerificationSubject(VerificationChannel channel, String target) {

    public static VerificationSubject email(String email) {
        return new VerificationSubject(VerificationChannel.EMAIL, email);
    }

    public static VerificationSubject phone(String phoneNumber) {
        return new VerificationSubject(VerificationChannel.SMS, phoneNumber);
    }
}
