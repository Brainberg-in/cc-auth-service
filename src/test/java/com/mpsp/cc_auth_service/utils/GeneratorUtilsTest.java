package com.mpsp.cc_auth_service.utils;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

public class GeneratorUtilsTest {

  @Test
  public void testGenerateOTP() {
    String otp = GeneratorUtils.generateOTP(6);
    assertNotNull(otp);
    assertEquals(6, otp.length());
    assertTrue(otp.matches("\\d{6}")); // Verify it contains only digits
  }

  @Test
  public void testMaskEmail() {
    assertEquals("jo****@example.com", GeneratorUtils.maskEmail("john@example.com"));
    assertEquals("te****@test.com", GeneratorUtils.maskEmail("test@test.com"));
    assertNull(GeneratorUtils.maskEmail(null));
    assertEquals("", GeneratorUtils.maskEmail(""));
  }

  @Test
  public void testCheckIfUrlsContainUri() {
    String[] urls = {"/api/", "/auth/", "/public/"};

    assertTrue(GeneratorUtils.checkIfUrlsContainUri("/api/users", urls));
    assertTrue(GeneratorUtils.checkIfUrlsContainUri("/auth/login", urls));
    assertFalse(GeneratorUtils.checkIfUrlsContainUri("/private/data", urls));
  }

  @Test
  public void testCheckIfUrlEndsWith() {
    String[] extensions = {".jpg", ".png", ".pdf"};

    assertTrue(GeneratorUtils.checkIfUrlEndsWith("document.pdf", extensions));
    assertTrue(GeneratorUtils.checkIfUrlEndsWith("image.jpg", extensions));
    assertFalse(GeneratorUtils.checkIfUrlEndsWith("file.txt", extensions));
  }
}
