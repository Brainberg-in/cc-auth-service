package com.mpsp.cc_auth_service.utils;

import com.mpsp.cc_auth_service.constants.AppConstants;
import com.mpsp.cc_auth_service.dto.User;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import java.text.ParseException;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class JwtTokenProvider {
  private final JWSAlgorithm algorithm = JWSAlgorithm.HS256;

  @Value("${jwt.secret}")
  private String jwtSecret;

  @Value("${jwt.expiration}")
  private long jwtExpiration;

  @Value("${jwt.refresh.expiration}")
  private long refreshTokenExpiration;

  @Value("${base.url}")
  private String issuer;

  @Value("${jwt.aud}")
  private String aud;

  public String generateToken(final User user, final boolean isRefreshToken) {

    final JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject(String.valueOf(user.getUserId()))
            // TODO check how this works for a student. Else workaround this problem.
            .claim(AppConstants.USER_EMAIL, user.getEmail())
            .claim(AppConstants.IS_REFRESHTOKEN, isRefreshToken)
            .issueTime(new Date())
            .expirationTime(
                new Date(
                    System.currentTimeMillis()
                        + (isRefreshToken ? jwtExpiration : refreshTokenExpiration)))
            .issuer(issuer)
            .audience(aud)
            .build();
    final Payload payload = new Payload(claims.toJSONObject());
    final JWSObject jwsObject = new JWSObject(new JWSHeader(algorithm), payload);
    try {
      jwsObject.sign(new MACSigner(jwtSecret));
    } catch (JOSEException e) {
      log.error("Failed to generate token", e);
      throw new RuntimeException(e.getMessage());
    }
    return jwsObject.serialize();
  }

  public boolean verifyToken(
      final String token, final String userId, final boolean isRefreshToken) {
    try {
      // Parse the token, stripping the "Bearer " prefix if present
      final JWSObject jwsObject =
          JWSObject.parse(
              token.startsWith(AppConstants.BEARER)
                  ? token.substring(AppConstants.BEARER.length())
                  : token);
      final JWSVerifier verifier = new MACVerifier(jwtSecret);

      // Create a claims verifier to match the expected claims
      final DefaultJWTClaimsVerifier<?> claimsVerifier =
          new DefaultJWTClaimsVerifier<>(
              new JWTClaimsSet.Builder()
                  .issuer(issuer)
                  .subject(userId)
                  .claim(AppConstants.IS_REFRESHTOKEN, isRefreshToken)
                  .build(),
              new HashSet<>(List.of("exp")));

      // Verify the token's signature
      if (jwsObject.verify(verifier)) {
        // Verify the token's claims
        try {
          claimsVerifier.verify(JWTClaimsSet.parse(jwsObject.getPayload().toJSONObject()), null);
          return true; // Token is valid
        } catch (BadJWTException e) {
          log.error("Token Verification failed: {}", token, e);
          return false; // Invalid claims
        }
      } else {
        log.error("Invalid Token Signature");
        return false; // Invalid signature
      }
    } catch (JOSEException | ParseException e) {
      log.error("Failed to verify token: {}", token, e);
      return false; // Parsing or verification exception
    }
  }

  public String getSubject(final String token) {
    try {
      final JWSObject jwsObject =
          JWSObject.parse(
              token.startsWith(AppConstants.BEARER)
                  ? token.substring(AppConstants.BEARER.length())
                  : token);

      final JWTClaimsSet claims = JWTClaimsSet.parse(jwsObject.getPayload().toJSONObject());
      return claims.getSubject();
    } catch (ParseException e) {
      log.error("Failed to parse {}", token, e);
      throw new GlobalExceptionHandler.RefreshTokenException("Invalid token");
    }
  }

  public String getUserEmail(final String token) {
    try {
      final JWSObject jwsObject =
          JWSObject.parse(
              token.startsWith(AppConstants.BEARER)
                  ? token.substring(AppConstants.BEARER.length())
                  : token);

      final JWTClaimsSet claims = JWTClaimsSet.parse(jwsObject.getPayload().toJSONObject());
      return claims.getClaim(AppConstants.USER_EMAIL).toString();
    } catch (ParseException e) {
      log.error("Failed to parse {}", token, e);
      throw new GlobalExceptionHandler.RefreshTokenException("Invalid token");
    }
  }
}
