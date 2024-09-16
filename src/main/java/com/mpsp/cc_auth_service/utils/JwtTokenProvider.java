package com.mpsp.cc_auth_service.utils;

import com.mpsp.cc_auth_service.constants.AppConstants;
import com.mpsp.cc_auth_service.dto.User;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.EncryptedJWT;
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

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

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

  public String generateToken(final User user, final boolean isRefreshToken, List<String> userRoles) {

    final JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject(String.valueOf(user.getUserId()))
            //TODO check how this works for a student. Else workaround this problem. 
            .claim(AppConstants.USER_EMAIL, user.getEmail())
                  .claim(AppConstants.USER_ROLE, userRoles.get(0))
                .claim(AppConstants.IS_MULTIROLE, userRoles.size() > 1)
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

  public String generateRoleToken(final User user, final boolean isRefreshToken, List<String> userRoles) {

    final JWTClaimsSet claims =
            new JWTClaimsSet.Builder()
                    .subject(String.valueOf(user.getUserId()))
                    .claim(AppConstants.USER_EMAIL, user.getEmail())
                    .claim(AppConstants.USER_ROLE, userRoles.toString())
                    .claim(AppConstants.IS_MULTIROLE, userRoles.size() > 1)
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

  private String encryptToken(String signedToken) {
    try {
      // Create the JWE header with encryption algorithm (AES-256-GCM)
      JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);

      // Create the encrypted JWT with the signed token as payload
      EncryptedJWT encryptedJWT = new EncryptedJWT(jweHeader, JWTClaimsSet.parse(signedToken));

      // Encrypt the token using the encryption key
      SecretKey secretKey = generateSecretKey();
      DirectEncrypter encrypter = new DirectEncrypter(secretKey);
      encryptedJWT.encrypt(encrypter);

      // Return the encrypted JWT as a serialized string
      return encryptedJWT.serialize();
    } catch (Exception e) {
      log.error("Failed to encrypt token", e);
      throw new RuntimeException("Encryption failed");
    }

    public String decryptToken(String encryptedToken) {
      try {
        EncryptedJWT encryptedJWT = EncryptedJWT.parse(encryptedToken);

        // Decrypt using the same secret key
        SecretKey secretKey = generateSecretKey();
        DirectDecrypter decrypter = new DirectDecrypter(secretKey);
        encryptedJWT.decrypt(decrypter);

        // Get the signed JWT back from the encrypted payload
        return encryptedJWT.getJWTClaimsSet().toJSONObject().toJSONString();
      } catch (Exception e) {
        log.error("Failed to decrypt token", e);
        throw new RuntimeException("Decryption failed");
      }
    }

    // Helper method to generate a secret key (could be improved with key management)
    private SecretKey generateSecretKey() throws Exception {
      KeyGenerator keyGen = KeyGenerator.getInstance("AES");
      keyGen.init(256); // AES-256
      return keyGen.generateKey();
    }
    }
}
