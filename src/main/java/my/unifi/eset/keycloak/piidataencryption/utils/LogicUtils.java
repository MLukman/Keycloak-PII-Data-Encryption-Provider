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

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.Query;
import java.util.List;
import my.unifi.eset.keycloak.piidataencryption.admin.PiiDataEncryptionValidatorProvider;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserAttributeEntity;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserEntity;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserProvider;
import org.apache.commons.codec.digest.DigestUtils;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.jpa.entities.UserAttributeEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.userprofile.config.UPAttribute;
import org.keycloak.storage.jpa.JpaHashUtils;
import org.keycloak.userprofile.DeclarativeUserProfileProvider;
import org.keycloak.userprofile.UserProfileProvider;

/**
 * Provides core logics such as encryption/decryption of user entity & user
 * attribute entity, a few checks on whether or not the encryption feature is
 * enabled.
 *
 * @author MLukman (https://github.com/MLukman)
 */
public final class LogicUtils {

    static final Logger logger = Logger.getLogger(LogicUtils.class);

    /**
     * Enables/disables user encryption for a particular realm
     *
     * @param realm The RealmModel
     * @param enabled True to enable, false to disable
     */
    public static void setUserEncryptionEnabled(RealmModel realm, boolean enabled) {
        realm.setAttribute("users.encrypt", enabled);
        logger.debugf("Event: ENCRYPTION_%s, Realm: %s", enabled ? "ENABLED" : "DISABLED", realm.getId());
    }

    /**
     * Checks if the user encryption enabled or not
     *
     * @param ks KeycloakSession
     * @param realm RealmModel
     * @return true if enabled, false if disabled
     */
    public static boolean isUserEncryptionEnabled(KeycloakSession ks, RealmModel realm) {
        return ks.getProvider(UserProvider.class) instanceof EncryptedUserProvider
                && realm.getAttribute("users.encrypt", false);
    }

    /**
     * Checks if the user encryption enabled or not
     *
     * @param ks KeycloakSession
     * @param realmId Realm ID
     * @return true if enabled, false if disabled
     */
    public static boolean isUserEncryptionEnabled(KeycloakSession ks, String realmId) {
        return isUserEncryptionEnabled(ks, ks.realms().getRealm(realmId));
    }

    /**
     * Checks if a particular user attribute should be encrypted or not
     *
     * @param ks KeycloakSession
     * @param realmId The ID of the realm
     * @param attributeName The name of the user attribute
     * @return true if should encrypted, false if not
     */
    public static boolean shouldEncryptAttribute(KeycloakSession ks, String realmId, String attributeName) {
        if (!isUserEncryptionEnabled(ks, realmId)) {
            return false;
        }
        if (attributeName.startsWith("pii-")) {
            return true;
        }
        UserProfileProvider upp = ks.getProvider(UserProfileProvider.class);
        if (upp instanceof DeclarativeUserProfileProvider dup) {
            UPAttribute upa = dup.getConfiguration().getAttribute(attributeName);
            if (upa != null && upa.getValidations().containsKey(PiiDataEncryptionValidatorProvider.ID)) {
                return Boolean.parseBoolean(String.valueOf(upa.getValidations().get(PiiDataEncryptionValidatorProvider.ID).getOrDefault("enable", false)));
            }
        }
        return false;
    }

    /**
     * Checks if a particular user attribute should be encrypted or not
     *
     * @param ks KeycloakSession
     * @param userAttributeEntity The UserAttributeEntity
     * @return true if should encrypted, false if not
     */
    public static boolean shouldEncryptAttribute(KeycloakSession ks, UserAttributeEntity userAttributeEntity) {
        return shouldEncryptAttribute(ks, userAttributeEntity.getUser().getRealmId(), userAttributeEntity.getName());
    }

    /**
     * Gets the user entity with the specific ID
     *
     * @param em EntityManager
     * @param id User ID
     * @return
     */
    public static UserEntity getUserEntity(EntityManager em, String id) {
        return em.createQuery("SELECT u FROM UserEntity u WHERE u.id = :id", UserEntity.class)
                .setParameter("id", id)
                .getSingleResult();
    }

    /**
     * Gets existing encrypted user entity if exists, if not exists then either
     * create a new one or return null
     *
     * @param em EntityManager
     * @param ue The corresponding UserEntity
     * @param createIfMissing True if a new one should be created if missing,
     * false to simply return null
     * @return Either existing record, else if parameter createIfMissing is true
     * then a new record, else null
     */
    public static EncryptedUserEntity getEncryptedUserEntity(EntityManager em, UserEntity ue, boolean createIfMissing) {
        try {
            return em.createQuery("SELECT e FROM EncryptedUserEntity e WHERE e.user = :user", EncryptedUserEntity.class)
                    .setParameter("user", ue)
                    .getSingleResult();
        } catch (NoResultException ex) {
            if (createIfMissing) {
                return new EncryptedUserEntity(KeycloakModelUtils.generateId(), ue);
            }
            return null;
        }
    }

    /**
     * Gets existing encrypted user attribute entity if exists, if not exists
     * then either create a new one or return null
     *
     * @param em EntityManager
     * @param ue The corresponding UserEntity
     * @param name The attribute name
     * @param createIfMissing True if a new one should be created if missing,
     * false to simply return null
     * @return Either existing record, else if parameter createIfMissing is true
     * then a new record, else null
     */
    public static EncryptedUserAttributeEntity getEncryptedUserAttributeEntity(EntityManager em, UserEntity ue, String name, boolean createIfMissing) {
        try {
            return em.createQuery("SELECT e FROM EncryptedUserAttributeEntity e WHERE e.user = :user AND e.name = :name", EncryptedUserAttributeEntity.class)
                    .setParameter("user", ue)
                    .setParameter("name", name)
                    .getSingleResult();
        } catch (NoResultException ex) {
            if (createIfMissing) {
                return new EncryptedUserAttributeEntity(KeycloakModelUtils.generateId(), ue, name);
            }
            return null;
        }
    }

    /**
     * Encrypts all existing user entities under a specific realm
     *
     * @param ks KeycloakSession
     * @param em EntityManager
     * @param realmId The realm ID
     */
    public static void encryptExistingUserEntities(KeycloakSession ks, EntityManager em, RealmModel realm) {
        List<UserEntity> realmUsers = em.createQuery("SELECT u FROM UserEntity u WHERE u.realmId = :realmId", UserEntity.class).setParameter("realmId", realm.getId()).getResultList();
        for (UserEntity user : realmUsers) {
            if (user.getServiceAccountClientLink() != null) {
                continue; // skip service accounts
            }
            encryptUserEntity(ks, em, user);
            logger.debugf("Event: USER_ENCRYPTION, Realm: %s, User: %s", realm.getId(), user.getId());
            for (UserAttributeEntity uae : user.getAttributes()) {
                encryptUserAttributeEntity(ks, em, uae);
            }
        }
    }

    /**
     * Encrypts an existing user entity
     *
     * @param ks KeycloakSession
     * @param em EntityManager
     * @param ue The UserEntity to encrypt
     */
    public static void encryptUserEntity(KeycloakSession ks, EntityManager em, UserEntity ue) {
        if (!LogicUtils.isUserEncryptionEnabled(ks, ue.getRealmId())) {
            return;
        }
        EncryptedUserEntity eue = LogicUtils.getEncryptedUserEntity(em, ue, true);
        if (ue.getUsername().length() == 40 && ue.getUsername().matches("^[0-9a-fA-F]+$")) {
            // somehow the value is already hashed so we skip it to avoid double hash/encrypt
            // we only need to check email because email has a specific string format
            return;
        }
        eue.setUsername(EncryptionUtils.encryptValue(ue.getUsername()));
        eue.setEmail(EncryptionUtils.encryptValue(ue.getEmail()));
        eue.setFirstName(EncryptionUtils.encryptValue(ue.getFirstName()));
        eue.setLastName(EncryptionUtils.encryptValue(ue.getLastName()));
        em.persist(eue);
        Query update = em.createQuery("UPDATE UserEntity u SET u.username = :username, u.email = :email, u.emailConstraint = :emailConstraint, u.firstName = :firstName, u.lastName = :lastName WHERE u.id = :id");
        update.setParameter("id", ue.getId());
        update.setParameter("username", hash(ue.getUsername()));
        String emailHash = hash(ue.getEmail());
        update.setParameter("email", emailHash);
        if (!ks.realms().getRealm(ue.getRealmId()).isDuplicateEmailsAllowed()) {
            update.setParameter("emailConstraint", emailHash);
        } else {
            update.setParameter("emailConstraint", ue.getEmailConstraint());
        }
        update.setParameter("firstName", hash(ue.getFirstName()));
        update.setParameter("lastName", hash(ue.getLastName()));
        update.executeUpdate();
    }

    /**
     * Encrypts an existing user attribute entity
     *
     * @param ks KeycloakSession
     * @param em EntityManager
     * @param uae The UserAttributeEntity to encrypt
     */
    public static void encryptUserAttributeEntity(KeycloakSession ks, EntityManager em, UserAttributeEntity uae) {
        if (shouldEncryptAttribute(ks, uae)) {
            String value = uae.getValue();
            if (value.length() == 40 && value.matches("^[0-9a-fA-F]+$")) {
                // somehow the value is already hashed so we skip it to avoid double hash/encrypt
                return;
            }
            EncryptedUserAttributeEntity euae = getEncryptedUserAttributeEntity(em, uae.getUser(), uae.getName(), true);
            euae.setValue(EncryptionUtils.encryptValue(value));
            euae.setAttribute(uae);
            em.persist(euae);
            if (value.length() > 255) {
                Query update = em.createQuery("UPDATE UserAttributeEntity u SET u.value = null, u.longValue = :longValue, u.longValueHash = :longValueHash, u.longValueHashLowerCase = :longValueHashLowerCase WHERE u.id = :id");
                update.setParameter("id", uae.getId());
                update.setParameter("longValue", hash(value));
                update.setParameter("longValueHash", JpaHashUtils.hashForAttributeValue(value));
                update.setParameter("longValueHashLowerCase", JpaHashUtils.hashForAttributeValueLowerCase(value));
                update.executeUpdate();
            } else {
                Query update = em.createQuery("UPDATE UserAttributeEntity u SET u.value = :value, u.longValue = null, u.longValueHash = null, u.longValueHashLowerCase = null WHERE u.id = :id");
                update.setParameter("id", uae.getId());
                update.setParameter("value", hash(value));
                update.executeUpdate();
            }
        }
    }

    /**
     * Decrypts all existing user entities under a specific realm
     *
     * @param em EntityManager
     * @param realm RealmModel
     */
    public static void decryptExistingUserEntities(EntityManager em, RealmModel realm) {
        List<UserEntity> realmUsers = em.createQuery("SELECT u FROM UserEntity u WHERE u.realmId = :realmId", UserEntity.class).setParameter("realmId", realm.getId()).getResultList();
        for (UserEntity user : realmUsers) {
            try {
                EncryptedUserEntity eue = getEncryptedUserEntity(em, user, false);
                if (eue != null) {
                    decryptUserEntity(em, realm, eue);
                    logger.debugf("Event: USER_DECRYPTION, Realm: %s, User: %s", realm.getId(), user.getId());
                }
                List<EncryptedUserAttributeEntity> encryptedAttributes = em.createQuery("SELECT a FROM EncryptedUserAttributeEntity a WHERE a.user = :user", EncryptedUserAttributeEntity.class).setParameter("user", user).getResultList();
                for (EncryptedUserAttributeEntity euae : encryptedAttributes) {
                    decryptUserAttributeEntity(em, realm, euae);
                }
            } catch (DecryptionFailureException ex) {
                ex.outputToLog(logger);
            }
        }
    }

    /**
     * Decrypts an encrypted user entity
     *
     * @param em EntityManager
     * @param realm RealmModel
     * @param eue EncryptedUserEntity
     */
    public static void decryptUserEntity(EntityManager em, RealmModel realm, EncryptedUserEntity eue) {
        UserEntity user = eue.getUser();
        if (!user.getUsername().equalsIgnoreCase(EncryptionUtils.decryptValue(eue.getUsername()))) {
            throw new DecryptionFailureException(realm.getId(), user.getId());
        }
        Query update = em.createQuery("UPDATE UserEntity u SET u.username = :username, u.email = :email, u.emailConstraint = :emailConstraint, u.firstName = :firstName, u.lastName = :lastName WHERE u.id = :id");
        update.setParameter("id", user.getId());
        update.setParameter("username", EncryptionUtils.decryptValue(eue.getUsername()));
        String decryptedEmail = EncryptionUtils.decryptValue(eue.getEmail());
        update.setParameter("email", decryptedEmail);
        if (!realm.isDuplicateEmailsAllowed()) {
            update.setParameter("emailConstraint", decryptedEmail);
        } else {
            update.setParameter("emailConstraint", user.getEmailConstraint()); // basically no change
        }
        update.setParameter("firstName", EncryptionUtils.decryptValue(eue.getFirstName()));
        update.setParameter("lastName", EncryptionUtils.decryptValue(eue.getLastName()));
        update.executeUpdate();
        em.remove(eue);
    }

    /**
     * Decrypts an encrypted user attribute entity
     *
     * @param em EntityManager
     * @param realm RealmModel
     * @param euae EncryptedUserAttributeEntity
     */
    public static void decryptUserAttributeEntity(EntityManager em, RealmModel realm, EncryptedUserAttributeEntity euae) {
        UserAttributeEntity uae = euae.getAttribute();
        if (!uae.getValue().equalsIgnoreCase(EncryptionUtils.decryptValue(euae.getValue()))) {
            throw new DecryptionFailureException(realm.getId(), euae.getUser().getId(), euae.getName());
        }
        String value = EncryptionUtils.decryptValue(euae.getValue());
        if (value.length() > 255) {
            Query update = em.createQuery("UPDATE UserAttributeEntity u SET u.value = null, u.longValue = :longValue, u.longValueHash = :longValueHash, u.longValueHashLowerCase = :longValueHashLowerCase WHERE u.id = :id");
            update.setParameter("id", uae.getId());
            update.setParameter("longValue", value);
            update.setParameter("longValueHash", JpaHashUtils.hashForAttributeValue(value));
            update.setParameter("longValueHashLowerCase", JpaHashUtils.hashForAttributeValueLowerCase(value));
            update.executeUpdate();
        } else {
            Query update = em.createQuery("UPDATE UserAttributeEntity u SET u.value = :value, u.longValue = null, u.longValueHash = null, u.longValueHashLowerCase = null WHERE u.id = :id");
            update.setParameter("id", uae.getId());
            update.setParameter("value", value);
            update.executeUpdate();
        }
        em.remove(euae);
    }

    /**
     * Generates the hash value to be store in place of the plain text value
     *
     * @param raw The plain text value
     * @return The hash of the input raw
     */
    public static String hash(String raw) {
        return raw != null ? DigestUtils.sha1Hex(raw.trim().toLowerCase()) : null;
    }

    // Makes this class un-instantiatable
    private LogicUtils() {
    }

}
