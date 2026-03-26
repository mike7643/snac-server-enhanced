package com.ureca.snac.auth.service.verify;

public interface VerificationTokenGenerator {

    VerificationChannel channel();

    String generate();
}
