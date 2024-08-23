package com.mpsp.cc_auth_service.utils;

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
import main.java.com.mpsp.cc_auth_service.constants.AppConstants;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class JwtTokenProvider {

  private final String issuer = "traitfit";
  private final JWSAlgorithm algorithm = JWSAlgorithm.HS256;

  @Value("${jwt.secret}")
  private String jwtSecret;

  @Value("${jwt.expiration}")
  private long jwtExpiration;

  @Value("${jwt.refresh.expiration}")
  private long refreshTokenExpiration;

  public String generateToken(final User user, final boolean isRefreshToken) {

    final JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject(user.getEmail())
            // .claim("role", role)
            .claim(AppConstants.IS_REFRESHTOKEN, isRefreshToken)
            .issueTime(new Date())
            .expirationTime(
                new Date(
                    System.currentTimeMillis()
                        + (isRefreshToken ? jwtExpiration : refreshTokenExpiration)))
            .issuer(issuer)
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

  public boolean verifyToken(final String token, final String userId, final boolean isRefreshToken)
      throws ParseException, JOSEException {
    final JWSObject jwsObject = JWSObject.parse(token);

    final JWSVerifier verifier = new MACVerifier(jwtSecret);
    final DefaultJWTClaimsVerifier<?> claimsVerifier =
        new DefaultJWTClaimsVerifier<>(
            new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(userId)
                .claim(AppConstants.IS_REFRESHTOKEN, isRefreshToken)
                .build(),
            new HashSet<>(List.of("exp")));

    if (jwsObject.verify(verifier)) {
      try {
        claimsVerifier.verify(JWTClaimsSet.parse(jwsObject.getPayload().toJSONObject()), null);
        return true;
      } catch (BadJWTException e) {
        // log.error("Token Verification failed", e);
        if (e.getMessage().trim().equals("Expired JWT")) {
          // LoggerUtility.error(UUID.randomUUID().toString(), e.getMessage(), e, null,
          // e);
          log.error(e.getMessage());
          return false;
        } else throw new RuntimeException("Invalid issuer or subject", e);
      }
    }
    throw new RuntimeException("Invalid Signature");
  }

  public String getSubject(final String token) throws ParseException {
    final JWSObject jwsObject = JWSObject.parse(token);

    final JWTClaimsSet claims = JWTClaimsSet.parse(jwsObject.getPayload().toJSONObject());
    return claims.getSubject();
  }
}
