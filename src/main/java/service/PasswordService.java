package service;

import org.mindrot.jbcrypt.BCrypt;

public class PasswordService {

    private final int logRounds;

    public PasswordService(int logRounds) {
        this.logRounds = logRounds;
    }

    public String hashPassword(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(logRounds));
    }

    public boolean verifyPassword(String password, String storedHash) {
        return BCrypt.checkpw(password, storedHash);
    }
}
