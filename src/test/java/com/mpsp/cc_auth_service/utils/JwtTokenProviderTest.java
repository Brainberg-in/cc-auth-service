package com.mpsp.cc_auth_service.utils;

import com.mpsp.cc_auth_service.dto.User;
import com.nimbusds.jose.JOSEException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {JwtTokenProvider.class})
@SpringBootTest
public class JwtTokenProviderTest {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private User user;

    @Test
    public void testGenerateToken() {
        when(user.getUserId()).thenReturn(1);
        String token = jwtTokenProvider.generateToken(user, false);
        assertNotNull(token, "Token should not be null");
    }

    @Test
    public void testVerifyToken() throws ParseException, JOSEException {
        when(user.getUserId()).thenReturn(1);
        String token = jwtTokenProvider.generateToken(user, false);
        assertDoesNotThrow(() -> jwtTokenProvider.verifyToken(token, "1", false));
    }

    @Test
    public void testGetSubject() throws ParseException {
        when(user.getUserId()).thenReturn(1);
        String token = jwtTokenProvider.generateToken(user, false);
        String subject = jwtTokenProvider.getSubject(token);
        assertEquals("1", subject, "Subject should match the user ID");
    }
}