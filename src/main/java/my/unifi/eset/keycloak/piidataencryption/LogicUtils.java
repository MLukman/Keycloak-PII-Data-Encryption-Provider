package my.unifi.eset.keycloak.piidataencryption;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.Query;
import java.util.List;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserAttributeEntity;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserEntity;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserProvider;
import org.apache.commons.codec.digest.DigestUtils;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.jpa.entities.UserAttributeEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.userprofile.config.UPAttribute;
import org.keycloak.userprofile.DeclarativeUserProfileProvider;
import org.keycloak.userprofile.UserProfileProvider;

public final class LogicUtils {

    public static void setUserEncryptionEnabled(RealmModel realm, boolean enabled) {
        realm.setAttribute("users.encrypt", enabled);
    }

    public static boolean isUserEncryptionEnabled(KeycloakSession ks, RealmModel realm) {
        return ks.getProvider(UserProvider.class) instanceof EncryptedUserProvider
                && realm.getAttribute("users.encrypt", false);
    }

    public static boolean isUserEncryptionEnabled(KeycloakSession ks, String realmId) {
        return isUserEncryptionEnabled(ks, ks.realms().getRealm(realmId));
    }

    public static boolean shouldEncryptAttribute(KeycloakSession ks, UserAttributeEntity userAttributeEntity) {
        return shouldEncryptAttribute(ks, userAttributeEntity.getName());
    }

    public static boolean shouldEncryptAttribute(KeycloakSession ks, String name) {
        if (name.startsWith("pii-")) {
            return true;
        }
        UserProfileProvider upp = ks.getProvider(UserProfileProvider.class);
        if (upp instanceof DeclarativeUserProfileProvider dup) {
            UPAttribute upa = dup.getConfiguration().getAttribute(name);
            if (upa != null && upa.getValidations().containsKey(PiiDataEncryptionValidatorProvider.ID)) {
                return Boolean.parseBoolean(String.valueOf(upa.getValidations().get(PiiDataEncryptionValidatorProvider.ID).getOrDefault("enable", false)));
            }
        }
        return false;
    }

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

    public static void encryptExistingUserEntities(KeycloakSession ks, EntityManager em, String realmId) {
        List<UserEntity> realmUsers = em.createQuery("SELECT u FROM UserEntity u WHERE u.realmId = :realmId", UserEntity.class).setParameter("realmId", realmId).getResultList();
        for (UserEntity user : realmUsers) {
            EncryptedUserEntity eue = LogicUtils.getEncryptedUserEntity(em, user, true);
            if (user.getEmail().length() == 40 && user.getEmail().matches("^[0-9a-fA-F]+$")) {
                // somehow the value is already hashed so we skip it to avoid double hash/encrypt
                continue;
            }
            eue.setUsername(EncryptionUtils.encryptValue(user.getUsername()));
            eue.setEmail(EncryptionUtils.encryptValue(user.getEmail()));
            eue.setFirstName(EncryptionUtils.encryptValue(user.getFirstName()));
            eue.setLastName(EncryptionUtils.encryptValue(user.getLastName()));
            em.persist(eue);
            Query update = em.createQuery("UPDATE UserEntity u SET u.username = :username, u.email = :email, u.firstName = :firstName, u.lastName = :lastName WHERE u.id = :id");
            update.setParameter("id", user.getId());
            update.setParameter("username", LogicUtils.hash(user.getUsername()));
            update.setParameter("email", LogicUtils.hash(user.getEmail()));
            update.setParameter("firstName", LogicUtils.hash(user.getFirstName()));
            update.setParameter("lastName", LogicUtils.hash(user.getLastName()));
            update.executeUpdate();
            List<UserAttributeEntity> attributes = em.createQuery("SELECT a FROM UserAttributeEntity a WHERE a.user = :user", UserAttributeEntity.class).setParameter("user", user).getResultList();
            for (UserAttributeEntity attribute : attributes) {
                if (LogicUtils.shouldEncryptAttribute(ks, attribute)) {
                    String value = attribute.getValue();
                    if (value.length() == 40 && value.matches("^[0-9a-fA-F]+$")) {
                        // somehow the value is already hashed so we skip it to avoid double hash/encrypt
                        continue;
                    }
                    EncryptedUserAttributeEntity euae = LogicUtils.getEncryptedUserAttributeEntity(em, user, attribute.getName(), true);
                    euae.setValue(EncryptionUtils.encryptValue(value));
                    euae.setAttribute(attribute);
                    em.persist(euae);
                    update = em.createQuery("UPDATE UserAttributeEntity u SET u.value = :value WHERE u.id = :id");
                    update.setParameter("id", attribute.getId());
                    update.setParameter("value", LogicUtils.hash(value));
                    update.executeUpdate();
                }
            }
        }
    }

    public static void decryptExistingUserEntities(EntityManager em, String realmId) {
        List<UserEntity> realmUsers = em.createQuery("SELECT u FROM UserEntity u WHERE u.realmId = :realmId", UserEntity.class).setParameter("realmId", realmId).getResultList();
        for (UserEntity user : realmUsers) {
            EncryptedUserEntity eue;
            eue = LogicUtils.getEncryptedUserEntity(em, user, false);
            if (eue != null) {
                Query update = em.createQuery("UPDATE UserEntity u SET u.username = :username, u.email = :email, u.firstName = :firstName, u.lastName = :lastName WHERE u.id = :id");
                update.setParameter("id", user.getId());
                update.setParameter("username", EncryptionUtils.decryptValue(eue.getUsername()));
                update.setParameter("email", EncryptionUtils.decryptValue(eue.getEmail()));
                update.setParameter("firstName", EncryptionUtils.decryptValue(eue.getFirstName()));
                update.setParameter("lastName", EncryptionUtils.decryptValue(eue.getLastName()));
                update.executeUpdate();
                em.remove(eue);
            }
            List<EncryptedUserAttributeEntity> encryptedAttributes = em.createQuery("SELECT a FROM EncryptedUserAttributeEntity a WHERE a.user = :user", EncryptedUserAttributeEntity.class).setParameter("user", user).getResultList();
            for (EncryptedUserAttributeEntity euae : encryptedAttributes) {
                Query update = em.createQuery("UPDATE UserAttributeEntity u SET u.value = :value WHERE u = :attribute");
                update.setParameter("attribute", euae.getAttribute());
                update.setParameter("value", EncryptionUtils.decryptValue(euae.getValue()));
                update.executeUpdate();
                em.remove(euae);
            }
        }
    }

    public static String hash(String raw) {
        return raw != null ? DigestUtils.sha1Hex(raw) : null;
    }

    private LogicUtils() {
    }

}
