package com.ureca.snac.auth.service.verify;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class EmailVerificationTokenGenerator implements VerificationTokenGenerator {

    private final NumericCodeGenerator numericCodeGenerator;

    @Override
    public VerificationChannel channel() {
        return VerificationChannel.EMAIL;
    }

    @Override
    public String generate() {
        return numericCodeGenerator.generate(6);
    }
}
