package com.mpsp.cc_auth_service.utils;

import java.security.SecureRandom;

public class GeneratorUtils {
    private static final SecureRandom secureRandom = new SecureRandom();

    public static String generateOTP(int OTP_LENGTH) {
        StringBuilder otp = new StringBuilder(OTP_LENGTH);

        for (int i = 0; i < OTP_LENGTH; i++) {
            int randomDigit = secureRandom.nextInt(10);  // Generates a random digit between 0 and 9
            otp.append(randomDigit);
        }

        return otp.toString();
    }
}
