package my.unifi.eset.keycloak.piidataencryption;

import jakarta.persistence.PostLoad;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.jpa.entities.UserAttributeEntity;
import org.keycloak.representations.userprofile.config.UPAttribute;
import org.keycloak.userprofile.DeclarativeUserProfileProvider;
import org.keycloak.userprofile.UserProfileProvider;
import org.keycloak.utils.KeycloakSessionUtil;

/**
 * Listen to PrePersist, PreUpdate & PostLoad entity events and perform
 * encryption and decryption if entity is UserAttributeEntity
 *
 * @author MLukman (https://github.com/MLukman)
 */
public class EntityListener {

    @PrePersist
    void prePersist(Object entity) {
        if (entity instanceof UserAttributeEntity userAttributeEntity
                && shouldEncryptAttribute(userAttributeEntity)) {
            userAttributeEntity.setValue(
                    EncryptionUtil.encryptValue(userAttributeEntity.getValue())
            );
        }
    }

    @PreUpdate
    void preUpdate(Object entity) {
        if (entity instanceof UserAttributeEntity userAttributeEntity
                && shouldEncryptAttribute(userAttributeEntity)) {
            userAttributeEntity.setValue(
                    EncryptionUtil.encryptValue(userAttributeEntity.getValue())
            );
        }
    }

    @PostLoad
    void postLoad(Object entity) {
        if (entity instanceof UserAttributeEntity userAttributeEntity) {
            userAttributeEntity.setValue(
                    EncryptionUtil.decryptValue(userAttributeEntity.getValue())
            );
        }
    }

    boolean shouldEncryptAttribute(UserAttributeEntity userAttributeEntity) {
        if (userAttributeEntity.getName().startsWith("pii-")) {
            return true;
        }
        KeycloakSession ks = KeycloakSessionUtil.getKeycloakSession();
        UserProfileProvider upp = ks.getProvider(UserProfileProvider.class);
        if (upp instanceof DeclarativeUserProfileProvider dup) {
            UPAttribute upa = dup.getConfiguration().getAttribute(userAttributeEntity.getName());
            if (upa != null && upa.getValidations().containsKey("pii-data-encryption")) {
                return true;
            }
        }
        return false;
    }

}
