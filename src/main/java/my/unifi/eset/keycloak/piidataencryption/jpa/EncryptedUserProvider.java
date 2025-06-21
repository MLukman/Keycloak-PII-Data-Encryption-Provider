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

package my.unifi.eset.keycloak.piidataencryption.jpa;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import my.unifi.eset.keycloak.piidataencryption.utils.LogicUtils;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.JpaUserProvider;

public class EncryptedUserProvider extends JpaUserProvider {

    private static final Logger logger = Logger.getLogger(EncryptedUserProvider.class);
    private final KeycloakSession ks;

    public EncryptedUserProvider(KeycloakSession session, EntityManager em) {
        super(session, em);
        this.ks = session;
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        UserModel user;
        if (null != (user = super.getUserByUsername(realm, username))) {
            return user;
        }
        logger.debugf("getUserByUsername (using hash): " + username);
        return super.getUserByUsername(realm, LogicUtils.hash(username));
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        UserModel user;
        if (null != (user = super.getUserByEmail(realm, email))) {
            return user;
        }
        logger.debugf("getUserByEmail (using hash): " + email);
        return super.getUserByEmail(realm, LogicUtils.hash(email));
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> attributes, Integer firstResult, Integer maxResults) {
        List<UserModel> results = super.searchForUserStream(realm, attributes, firstResult, maxResults).toList();
        if (!results.isEmpty()) {
            return results.stream();
        }
        try {
            logger.debugf("searchForUserStream (using hash): " + new ObjectMapper().writeValueAsString(attributes));
        } catch (JsonProcessingException ex) {
            logger.warnf("searchForUserStream (using hash): <unable to convert into JSON>");
        }
        List<String> encrypted = Arrays.asList(UserModel.SEARCH, "username", "email", "firstName", "lastName");
        for (Map.Entry<String, String> attribute : attributes.entrySet()) {
            if (encrypted.contains(attribute.getKey()) || LogicUtils.shouldEncryptAttribute(ks, realm.getId(), attribute.getKey())) {
                attribute.setValue(LogicUtils.hash(attribute.getValue()));
            }
        }
        return super.searchForUserStream(realm, attributes, firstResult, maxResults);
    }

}
