package util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import exception.JwtGenerationException;
import lombok.experimental.UtilityClass;

import javax.naming.AuthenticationException;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@UtilityClass
public class JoseJwtUtil {
    private static final String SECRET = "88cf3e49-e28e-4c0e-b95f-6a68a785a89d";
    public static final String CLAIMS = "claims";

    public String generateSafeToken(String subject) {
        return generateSafeToken(subject, new HashMap<>());
    }

    public String generateSafeToken(String subject, Map<String, Object> claims) {
        return generateSafeTokenWithExpiryTime(subject, claims, 15);
    }

    public String generateSafeTokenWithExpiryTime(String subject, Map<String, Object> claims, long expiryInMinutes) {
        try {
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .expirationTime(new Date(System.currentTimeMillis() + 1000 * 60 * expiryInMinutes))
                    .claim(CLAIMS, claims)
                    .build();

            JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.HS256).build();
            SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
            signedJWT.sign(new MACSigner(SECRET.getBytes()));
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new JwtGenerationException("Failed to generate JWT token for subject: " + subject, e);
        }
    }

    public JWTClaimsSet extractClaims(String bearerToken) throws ParseException, JOSEException, AuthenticationException {
        String token = null;
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            token = bearerToken.substring(7);
        }
        assert token != null;
        SignedJWT signedJWT = SignedJWT.parse(token);

        if (!isTokenValid(signedJWT)) {
            throw new AuthenticationException("Invalid bearer token");
        }
        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
        if (isTokenExpired(jwtClaimsSet.getExpirationTime())) {
            throw new AuthenticationException("Bearer token expired");
        }
        return jwtClaimsSet;
    }

    public boolean isTokenValid(SignedJWT signedJWT) throws JOSEException {
        return signedJWT.verify(new MACVerifier(SECRET.getBytes()));
    }

    public boolean isTokenExpired(Date expirationDate) {
        return new Date().after(expirationDate);
    }
}