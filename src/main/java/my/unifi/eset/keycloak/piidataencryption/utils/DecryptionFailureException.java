package my.unifi.eset.keycloak.piidataencryption.utils;

import org.jboss.logging.Logger;

/**
 * Exception to be used when there is a failure to decrypted encrypted data.
 *
 * @author MLukman (https://github.com/MLukman)
 */
public class DecryptionFailureException extends RuntimeException {

    public DecryptionFailureException(String realmId, String userId) {
        this(String.format("Event: USER_DECRYPTION_FAILURE, Realm: %s, User: %s", realmId, userId));
    }

    public DecryptionFailureException(String realmId, String userId, String attributeName) {
        this(String.format("Event: USER_ATTRIBUTE_DECRYPTION_FAILURE, Realm: %s, User: %s, Attribute: %s", realmId, userId, attributeName));
    }

    public void outputToLog(Logger logger) {
        logger.warn(getMessage());
    }

    private DecryptionFailureException(String errorMessage) {
        super(errorMessage);
    }
}
