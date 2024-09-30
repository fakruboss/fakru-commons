package exception;

public class JwtGenerationException extends RuntimeException {

    public JwtGenerationException(String message) {
        super(message);
    }

    public JwtGenerationException(String message, Throwable cause) {
        super(message, cause);
    }

    public JwtGenerationException(Throwable cause) {
        super(cause);
    }

    public JwtGenerationException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}