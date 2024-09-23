package util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;

import java.util.Map;
import java.util.function.Function;

public class JwtAuthenticationHandler {

    private final Function<String, String> headerExtractor;
    private final Function<Map<String, Object>, Void> errorHandler;

    public JwtAuthenticationHandler(
            Function<String, String> headerExtractor,
            Function<Map<String, Object>, Void> errorHandler) {
        this.headerExtractor = headerExtractor;
        this.errorHandler = errorHandler;
    }

    public JWTClaimsSet authenticate(Map<String, Object> request) {
        String bearerToken = headerExtractor.apply("Authorization");
        if (bearerToken == null || !bearerToken.startsWith("Bearer ")) {
            errorHandler.apply(Map.of(
                    "status", 401,
                    "message", "JWT token not found in the request header"
            ));
            return null;
        }

        try {
            return JoseJwtUtil.extractClaims(bearerToken);
        } catch (Exception e) {
            errorHandler.apply(Map.of(
                    "status", 401,
                    "message", e.getMessage()
            ));
            return null;
        }
    }

    public String refreshToken(JWTClaimsSet claimsSet) throws JOSEException {
        if (claimsSet == null) return null;
        String subject = claimsSet.getSubject();
        Map<String, Object> claims = (Map<String, Object>) claimsSet.getClaim("claims");
        return JoseJwtUtil.generateToken(subject, claims);
    }
}