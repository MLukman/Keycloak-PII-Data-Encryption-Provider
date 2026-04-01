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
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.util.ArrayList;
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
import org.keycloak.models.jpa.UserAdapter;
import org.keycloak.models.jpa.entities.UserAttributeEntity;
import org.keycloak.models.jpa.entities.UserEntity;

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
        return searchByHashedAttributes(realm, attributes, firstResult, maxResults);
    }

    /**
     * Searches for users using exact match on pre-hashed attribute values.
     * <p>
     * This bypasses JpaUserProvider's default LOWER() wrapping which is redundant
     * for SHA-1 hash values (already lowercase hex) and prevents Postgres from
     * using a standard B-tree index on the value column.
     */
    private Stream<UserModel> searchByHashedAttributes(RealmModel realm, Map<String, String> attributes, Integer firstResult, Integer maxResults) {
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<UserEntity> cq = cb.createQuery(UserEntity.class);
        Root<UserEntity> root = cq.from(UserEntity.class);

        List<Predicate> predicates = new ArrayList<>();
        predicates.add(cb.equal(root.get("realmId"), realm.getId()));

        // Exclude service accounts unless explicitly included
        if (!Boolean.parseBoolean(attributes.getOrDefault(UserModel.INCLUDE_SERVICE_ACCOUNT, Boolean.FALSE.toString()))) {
            predicates.add(cb.isNull(root.get("serviceAccountClientLink")));
        }

        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            if (value == null || value.isEmpty()) continue;

            switch (key) {
                case UserModel.SEARCH:
                    // Hash was computed from the full search term — exact match across all user fields
                    predicates.add(cb.or(
                            cb.equal(root.get("username"), value),
                            cb.equal(root.get("email"), value),
                            cb.equal(root.get("firstName"), value),
                            cb.equal(root.get("lastName"), value)
                    ));
                    break;
                case "username":
                    predicates.add(cb.equal(root.get("username"), value));
                    break;
                case "email":
                    predicates.add(cb.equal(root.get("email"), value));
                    break;
                case "firstName":
                    predicates.add(cb.equal(root.get("firstName"), value));
                    break;
                case "lastName":
                    predicates.add(cb.equal(root.get("lastName"), value));
                    break;
                case UserModel.ENABLED:
                    predicates.add(cb.equal(root.get("enabled"), Boolean.parseBoolean(value)));
                    break;
                case UserModel.EMAIL_VERIFIED:
                    predicates.add(cb.equal(root.get("emailVerified"), Boolean.parseBoolean(value)));
                    break;
                case UserModel.EXACT:
                case UserModel.INCLUDE_SERVICE_ACCOUNT:
                    // Control flags, not search values
                    break;
                default:
                    // Custom attribute — exact match on hashed value, no LOWER()
                    Join<UserEntity, UserAttributeEntity> attrJoin = root.join("attributes", JoinType.INNER);
                    predicates.add(cb.and(
                            cb.equal(attrJoin.get("name"), key),
                            cb.equal(attrJoin.get("value"), value)
                    ));
                    break;
            }
        }

        cq.select(root).distinct(true).where(predicates.toArray(new Predicate[0]));

        TypedQuery<UserEntity> tq = em.createQuery(cq);
        if (firstResult != null && firstResult >= 0) tq.setFirstResult(firstResult);
        if (maxResults != null && maxResults >= 0) tq.setMaxResults(maxResults);

        return tq.getResultStream()
                .map(entity -> new UserAdapter(ks, realm, em, entity));
    }

    @Override
    public UserModel addUser(RealmModel realm, String id, String username, boolean addDefaultRoles, boolean addDefaultRequiredActions) {
        UserModel userModel = super.addUser(realm, id, username, addDefaultRoles, addDefaultRequiredActions);
        LogicUtils.encryptUserEntity(ks, em, LogicUtils.getUserEntity(em, userModel.getId()));
        em.flush();
        logger.debugf("addUser (encrypted): " + username);
        return userModel;
    }

}
