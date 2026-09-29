package vulntracker;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public final class PasswordUtil {
    private static final int SALT_BYTES = 16;
    private static final int ITERATIONS = 120_000;
    private static final int KEY_BITS = 256;
    private PasswordUtil() {}

    public static String hash(String password) {
        if (password == null || password.length() < 8) throw new IllegalArgumentException("Password must be at least 8 characters");
        byte[] salt = new byte[SALT_BYTES];
        new SecureRandom().nextBytes(salt);
        byte[] key = derive(password, salt);
        return "PBKDF2$" + ITERATIONS + "$" + Base64.getEncoder().encodeToString(salt) + "$" + Base64.getEncoder().encodeToString(key);
    }

    public static boolean verify(String password, String encoded) {
        if (password == null || encoded == null || !encoded.startsWith("PBKDF2$")) return false;
        try {
            String[] parts = encoded.split("\\$", -1);
            if (parts.length != 4) return false;
            int iterations = Integer.parseInt(parts[1]);
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expected = Base64.getDecoder().decode(parts[3]);
            byte[] actual = derive(password, salt, iterations);
            return MessageDigest.isEqual(actual, expected);
        } catch (RuntimeException e) { return false; }
    }

    private static byte[] derive(String password, byte[] salt) { return derive(password, salt, ITERATIONS); }
    private static byte[] derive(String password, byte[] salt, int iterations) {
        try {
            var spec = new javax.crypto.spec.PBEKeySpec(password.toCharArray(), salt, iterations, KEY_BITS);
            return javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (Exception e) { throw new IllegalStateException("Unable to hash password", e); }
    }
}
