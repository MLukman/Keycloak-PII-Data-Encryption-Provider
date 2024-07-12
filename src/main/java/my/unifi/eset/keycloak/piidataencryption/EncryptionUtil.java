package my.unifi.eset.keycloak.piidataencryption;

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

/**
 * Provide encryption functionalities
 *
 * @author MLukman (https://github.com/MLukman)
 */
public class EncryptionUtil {

    /**
     * Encryption algorithm to use
     */
    static String algorithm = "AES/CBC/PKCS5Padding";

    /**
     * String to prefixed to encrypted value before it is stored in db to
     * prevent double encryption
     */
    static String safeguardPrefix = "$$$";

    public static String encryptValue(String value) {
        try {
            if (safeguardPrefix.length() > 0 && value.startsWith(safeguardPrefix)) {
                return value;
            }
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(algorithm);
            SecretKey key = getEncryptionKey();
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] cipherText = cipher.doFinal(value.getBytes());
            return safeguardPrefix + Base64.getEncoder().encodeToString(
                    ArrayUtils.addAll(iv, cipherText)
            );
        } catch (NoSuchAlgorithmException
                | BadPaddingException
                | IllegalBlockSizeException
                | NoSuchPaddingException
                | InvalidKeyException
                | InvalidAlgorithmParameterException ex) {
            return value;
        }
    }

    public static String decryptValue(String value) {
        try {
            if (safeguardPrefix.length() > 0 && !value.startsWith(safeguardPrefix)) {
                return value;
            }
            byte[] cipherTextWithIv = Base64.getDecoder().decode(
                    value.substring(safeguardPrefix.length())
            );
            byte[] iv = ArrayUtils.subarray(cipherTextWithIv, 0, 16);
            byte[] cipherText = ArrayUtils.subarray(cipherTextWithIv, 16, cipherTextWithIv.length);
            Cipher cipher = Cipher.getInstance(algorithm);
            SecretKey key = getEncryptionKey();
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
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

    static SecretKey getEncryptionKey() throws NoSuchAlgorithmException {
        String key = System.getenv("KC_PII_ENCKEY");
        if (key == null || key.isBlank()) {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(System.getenv("KC_DB_URL").getBytes());
            key = HexFormat.of().formatHex(md.digest()).toLowerCase();
        }
        return new SecretKeySpec(key.getBytes(), "AES");
    }

}
