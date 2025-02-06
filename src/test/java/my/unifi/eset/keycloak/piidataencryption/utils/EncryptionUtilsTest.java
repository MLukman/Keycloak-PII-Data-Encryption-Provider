package my.unifi.eset.keycloak.piidataencryption.utils;

import org.junit.jupiter.api.BeforeEach;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.security.NoSuchAlgorithmException;

import static my.unifi.eset.keycloak.piidataencryption.utils.EncryptionUtils.algorithm;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SystemStubsExtension.class)
class EncryptionUtilsTest {

    @SystemStub
    private EnvironmentVariables environmentVariables;

    protected final String envVarKey = "KC_PII_ENCKEY";
    protected final String validEncKey = "1234567891123456";

    @BeforeEach
    void setUp() {
        EncryptionUtils.key = null;

        environmentVariables.set(envVarKey, validEncKey);
    }

    @Test
    void testEncryptValue() throws NoSuchAlgorithmException {
        String encryptedValue = EncryptionUtils.encryptValue("test");
        assertNotEquals("test", encryptedValue);

        String decryptedValue = EncryptionUtils.decryptValue(encryptedValue);
        assertEquals("test", decryptedValue);
    }

    @Test
    void testDecryptValue() throws NoSuchAlgorithmException {
        SecretKey key = EncryptionUtils.getEncryptionKey();

        String decryptedValue = EncryptionUtils.decryptValue("$$$GTaogsGC8vbgE098AN9kC+UCHD8vYzVgFF0hFDnuKIw=");

        assertEquals("test", decryptedValue);
    }

    @Test
    void testWrongKeySize() {
        environmentVariables.set(envVarKey, "invalid");

        Throwable thrown = assertThrows(RuntimeException.class, () -> {
            EncryptionUtils.getEncryptionKey();
        });

        assertEquals("Invalid encryption key for algorithm " + algorithm, thrown.getMessage());


        environmentVariables.set(envVarKey, validEncKey);
        assertDoesNotThrow(() -> EncryptionUtils.getEncryptionKey(), "should work once the key is correct and not reuse the previous one");
    }

    @Test
    void testValidKey() {
        byte[] validKeyBytes = validEncKey.getBytes();
        SecretKeySpec validKey = new SecretKeySpec(validKeyBytes, "AES");

        assertDoesNotThrow(() -> EncryptionUtils.validateKey(validKey));
    }

    @Test
    void testValidateAnInvalidKey() {
        byte[] invalidKeyBytes = "invalid_size".getBytes();
        SecretKeySpec invalidKey = new SecretKeySpec(invalidKeyBytes, "AES");

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> {
            EncryptionUtils.validateKey(invalidKey);
        });

        String expectedMessage = "Invalid encryption key for algorithm " + algorithm;
        assertThrows(IllegalArgumentException.class, () -> EncryptionUtils.validateKey(invalidKey));
        assert(thrown.getMessage().contains(expectedMessage));
    }
}
