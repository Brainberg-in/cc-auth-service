package com.mpsp.cc_auth_service.utils;

import java.security.SecureRandom;
import org.apache.commons.lang3.StringUtils;

public class GeneratorUtils {

  private static final SecureRandom secureRandom = new SecureRandom();

  private static final String EMAIL_REGEX = "(\\w{2})[^@]*(@.*)";

  public static String generateOTP(final int OTP_LENGTH) {
    final StringBuilder otp = new StringBuilder(OTP_LENGTH);
    for (int i = 0; i < OTP_LENGTH; i++) {

      otp.append(secureRandom.nextInt(10)); // Generates a random digit between 0
      // and 9
    }

    return otp.toString();
  }

  public static String maskEmail(String input) {
    if (StringUtils.isBlank(input)) {
      return null;
    }
    return input.replaceAll(EMAIL_REGEX, "$1****$2");
  }
}
