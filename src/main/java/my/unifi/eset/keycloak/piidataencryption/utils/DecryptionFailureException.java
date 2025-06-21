/*
 * Copyright (C) 2025 Muhammad Lukman Nasaruddin <lukman.nasaruddin@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */

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
