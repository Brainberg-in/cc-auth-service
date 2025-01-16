package com.mpsp.cc_auth_service.pojo;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.mpsp.cc_auth_service.entity.PasswordHistory;
import org.junit.jupiter.api.Test;

public class PasswordHistoryTest {
  final PasswordHistory passwordHistory = new PasswordHistory(1, "abc");

  @Test
  public void testPasswordHistory() {
    assertEquals(1, passwordHistory.getUserId());
    assertEquals("abc", passwordHistory.getCurrentPassword());
  }
}
