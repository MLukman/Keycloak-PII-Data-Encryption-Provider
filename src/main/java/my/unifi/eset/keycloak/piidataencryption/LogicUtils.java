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

    public static UserEntity getUserEntity(EntityManager em, String id) {
        return em
                .createQuery("SELECT u FROM UserEntity u WHERE u.id = :id", UserEntity.class)
                .setParameter("id", id)
                .getSingleResult();
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
            if (user.getServiceAccountClientLink() != null) {
                continue;
            }
            encryptUserEntity(ks, em, user);
            for (UserAttributeEntity uae : user.getAttributes()) {
                encryptUserAttributeEntity(ks, em, uae);
            }
        }
    }

    public static void encryptUserEntity(KeycloakSession ks, EntityManager em, UserEntity ue) {
        EncryptedUserEntity eue = LogicUtils.getEncryptedUserEntity(em, ue, true);
        if (ue.getEmail() != null && ue.getEmail().length() == 40 && ue.getEmail().matches("^[0-9a-fA-F]+$")) {
            // somehow the value is already hashed so we skip it to avoid double hash/encrypt
            // we only need to check email because email has a specific string format
            return;
        }
        eue.setUsername(EncryptionUtils.encryptValue(ue.getUsername()));
        eue.setEmail(EncryptionUtils.encryptValue(ue.getEmail()));
        eue.setFirstName(EncryptionUtils.encryptValue(ue.getFirstName()));
        eue.setLastName(EncryptionUtils.encryptValue(ue.getLastName()));
        em.persist(eue);
        Query update = em.createQuery("UPDATE UserEntity u SET u.username = :username, u.email = :email, u.firstName = :firstName, u.lastName = :lastName WHERE u.id = :id");
        update.setParameter("id", ue.getId());
        update.setParameter("username", LogicUtils.hash(ue.getUsername()));
        update.setParameter("email", LogicUtils.hash(ue.getEmail()));
        update.setParameter("firstName", LogicUtils.hash(ue.getFirstName()));
        update.setParameter("lastName", LogicUtils.hash(ue.getLastName()));
        update.executeUpdate();
    }

    public static void encryptUserAttributeEntity(KeycloakSession ks, EntityManager em, UserAttributeEntity uae) {
        if (LogicUtils.shouldEncryptAttribute(ks, uae)) {
            String value = uae.getValue();
            if (value.length() == 40 && value.matches("^[0-9a-fA-F]+$")) {
                // somehow the value is already hashed so we skip it to avoid double hash/encrypt
                return;
            }
            EncryptedUserAttributeEntity euae = LogicUtils.getEncryptedUserAttributeEntity(em, uae.getUser(), uae.getName(), true);
            euae.setValue(EncryptionUtils.encryptValue(value));
            euae.setAttribute(uae);
            em.persist(euae);
            Query update = em.createQuery("UPDATE UserAttributeEntity u SET u.value = :value WHERE u.id = :id");
            update.setParameter("id", uae.getId());
            update.setParameter("value", LogicUtils.hash(value));
            update.executeUpdate();
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
        return raw != null ? DigestUtils.sha1Hex(raw.trim().toLowerCase()) : null;
    }

    private LogicUtils() {
    }

}
