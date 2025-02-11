package my.unifi.eset.keycloak.piidataencryption.utils;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang3.ArrayUtils;
import org.jboss.logging.Logger;

/**
 * Provides encryption functionalities.
 *
 * @author MLukman (https://github.com/MLukman)
 */
public final class EncryptionUtils {

    /**
     * Encryption algorithm to use.
     */
    static String algorithm = "AES/CBC/PKCS5Padding";

    /**
     * String to prefixed to encrypted value before it is stored in db to
     * prevent double encryption. MUST NOT BE AN EMPTY STRING.
     */
    static final String CIPHERTEXT_PREFIX = "$$$";

    static SecretKeySpec key = null;

    /**
     * Encrypts the passed String value.
     *
     * @param value String to encrypt
     * @return The encrypted value
     */
    public static String encryptValue(String value) {
        try {
            if (value == null || isEncryptedValue(value)) {
                return value;
            }
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, getEncryptionKey(), new IvParameterSpec(iv));
            byte[] cipherText = cipher.doFinal(value.getBytes());
            return CIPHERTEXT_PREFIX + Base64.getEncoder().encodeToString(ArrayUtils.addAll(iv, cipherText));
        } catch (NoSuchAlgorithmException
                | BadPaddingException
                | IllegalBlockSizeException
                | NoSuchPaddingException
                | InvalidKeyException
                | InvalidAlgorithmParameterException ex) {
            return value;
        }
    }

    /**
     * Decrypts the passed value.
     *
     * @param value String to decrypt
     * @return The decrypted value
     */
    public static String decryptValue(String value) {
        try {
            if (value == null || !isEncryptedValue(value)) {
                return value;
            }
            byte[] cipherTextWithIv = Base64.getDecoder().decode(value.substring(CIPHERTEXT_PREFIX.length()));
            byte[] iv = ArrayUtils.subarray(cipherTextWithIv, 0, 16);
            byte[] cipherText = ArrayUtils.subarray(cipherTextWithIv, 16, cipherTextWithIv.length);
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, getEncryptionKey(), new IvParameterSpec(iv));
            byte[] plainText = cipher.doFinal(cipherText);
            return new String(plainText);
        } catch (NoSuchAlgorithmException
                | NoSuchPaddingException
                | InvalidKeyException
                | InvalidAlgorithmParameterException
                | IllegalBlockSizeException
                | BadPaddingException
                | IllegalArgumentException ex) {
            return value;
        }
    }

    /**
     * Checks if the passed value is encrypted.
     *
     * @param value String to check whether encrypted or not
     * @return true if encrypted value, false otherwise.
     */
    public static boolean isEncryptedValue(String value) {
        return value != null && value.startsWith(CIPHERTEXT_PREFIX);
    }

    /**
     * Gets encryption key from KC_PII_ENCKEY envvar, or generate one from
     * KC_DB_URL envvar.
     *
     * @return SecretKey
     * @throws NoSuchAlgorithmException
     */
    static synchronized SecretKey getEncryptionKey() throws NoSuchAlgorithmException {
        if (key != null) {
            return key;
        }

        String rawkey = System.getenv("KC_PII_ENCKEY");
        if (rawkey == null || rawkey.isBlank()) {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(System.getenv("KC_DB_URL").getBytes());
            rawkey = HexFormat.of().formatHex(md.digest()).toLowerCase();
            Logger.getLogger(EncryptionUtils.class).warn("Encryption key generated using MD5 hash of KC_DB_URL. It is recommended to set this key as KC_PII_ENCKEY envvar.");
        }

        SecretKeySpec genKey = new SecretKeySpec(rawkey.getBytes(), "AES");
        try {
            validateKey(genKey);
        } catch (IllegalArgumentException e) {
            throw e;
        }

        return key = genKey;
    }

    /**
     * Validates if the provided SecretKeySpec is a valid key.
     *
     * @param candidateKey SecretKeySpec
     */
    public static void validateKey(SecretKeySpec candidateKey) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, candidateKey, new IvParameterSpec(new byte[16]));
            // Trivial encryption to validate
            cipher.doFinal("test".getBytes(StandardCharsets.UTF_8));
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            throw new IllegalArgumentException("Invalid encryption key for algorithm " + algorithm, e);
        }
    }

    // Makes this class un-instantiatable
    private EncryptionUtils() {
    }

}
