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

  public static boolean checkIfUrlsContainUri(final String uri, final String[] urls) {
    boolean skip = false;
    for (String value : urls) {
      if (uri.contains(value)) {
        skip = true;
        break;
      }
    }
    return skip;
  }

  /**
   * @param url
   * @param urls
   * @return true if the url ends with any of the String that is present in urls else false
   */
  public static boolean checkIfUrlEndsWith(final String url, final String[] urls) {
    boolean endsWith = false;
    for (String value : urls) {
      if (url.contains(value)) {
        endsWith = true;
        break;
      }
    }
    return endsWith;
  }
}
