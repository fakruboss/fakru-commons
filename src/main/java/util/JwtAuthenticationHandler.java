package util;

import com.nimbusds.jwt.JWTClaimsSet;

import java.util.Map;
import java.util.function.Function;
import java.util.function.UnaryOperator;

public class JwtAuthenticationHandler {

    private final UnaryOperator<String> headerExtractor;
    private final Function<Map<String, Object>, Void> errorHandler;

    public JwtAuthenticationHandler(
            UnaryOperator<String> headerExtractor,
            Function<Map<String, Object>, Void> errorHandler) {
        this.headerExtractor = headerExtractor;
        this.errorHandler = errorHandler;
    }

    public JWTClaimsSet authenticate() {
        String bearerToken = headerExtractor.apply("Authorization");
        if (bearerToken == null || !bearerToken.startsWith("Bearer ")) {
            errorHandler.apply(Map.of(
                    "status", 401,
                    "message", "JWT token not found in the request header"
            ));
            return null;
        }

        try {
            return JoseJwtUtil.extractClaimsSet(bearerToken);
        } catch (Exception e) {
            errorHandler.apply(Map.of(
                    "status", 401,
                    "message", e.getMessage()
            ));
            return null;
        }
    }
}