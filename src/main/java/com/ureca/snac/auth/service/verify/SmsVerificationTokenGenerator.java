package com.ureca.snac.auth.service.verify;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SmsVerificationTokenGenerator implements VerificationTokenGenerator {

    private final NumericCodeGenerator numericCodeGenerator;

    @Override
    public VerificationChannel channel() {
        return VerificationChannel.SMS;
    }

    @Override
    public String generate() {
        return numericCodeGenerator.generate(6);
    }
}
