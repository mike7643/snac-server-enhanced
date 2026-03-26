package com.ureca.snac.auth.service.verify;

import org.springframework.stereotype.Component;

import java.util.concurrent.ThreadLocalRandom;

@Component
public class NumericCodeGenerator {

    public String generate(int digits) {
        int min = (int) Math.pow(10, digits - 1);
        int maxExclusive = (int) Math.pow(10, digits);
        int number = ThreadLocalRandom.current().nextInt(min, maxExclusive);
        return String.valueOf(number);
    }
}
