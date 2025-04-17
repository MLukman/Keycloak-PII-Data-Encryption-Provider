package my.unifi.eset.keycloak.piidataencryption.listeners;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import my.unifi.eset.keycloak.piidataencryption.utils.LogicUtils;
import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.entities.UserAttributeEntity;
import org.keycloak.models.jpa.entities.UserEntity;

/**
 * Listens to REGISTER & UPDATE_PROFILE user events as well as CREATE & UPDATE
 * admin event on USER resource to perform encryption of UserEntity &
 * UserAttributeEntity
 *
 * @author MLukman (https://github.com/MLukman)
 */
public class EventListener implements EventListenerProvider {

    private final KeycloakSession session;
    static final Logger logger = Logger.getLogger(EventListener.class);

    public EventListener(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Intercept REGISTER & UPDATE_PROFILE user events
     *
     * @param event
     */
    @Override
    public void onEvent(Event event) {
        if (event.getType() == EventType.REGISTER || event.getType() == EventType.UPDATE_PROFILE) {
            UserModel user = session.users().getUserById(session.realms().getRealm(event.getRealmId()), event.getUserId());
            if (!LogicUtils.isUserEncryptionEnabled(session, event.getRealmId())) {
                logger.debugf("Event: USER_ENCRYPTION_SKIPPED, Realm: %s, User: %s", event.getRealmId(), user.getId());
                return;
            }
            encryptUserWithId(event.getRealmId(), user.getId());
        }
    }

    /**
     * Intercept UPDATE admin event on USER resource
     *
     * @param event
     * @param bln
     */
    @Override
    public void onEvent(AdminEvent event, boolean bln) {
        if (event.getResourceType() == ResourceType.USER) {
            String userId = null;
            if (event.getOperationType() == OperationType.CREATE) {
                try {
                    JsonNode json = (new ObjectMapper()).readTree(event.getRepresentation());
                    String username = json.get("username").asText();
                    UserModel user = session.users().getUserByUsername(session.realms().getRealm(event.getRealmId()), username);
                    userId = user != null ? user.getId() : null;
                } catch (JsonProcessingException ex) {
                }
            }
            if (event.getOperationType() == OperationType.UPDATE) {
                userId = event.getResourcePath().split("/")[1];
            }
            if (userId != null) {
                if (!LogicUtils.isUserEncryptionEnabled(session, event.getRealmId())) {
                    logger.debugf("Event: USER_ENCRYPTION_SKIPPED, Realm: %s, User: %s", event.getRealmId(), userId);
                    return;
                }
                encryptUserWithId(event.getRealmId(), userId);
            }
        }
    }

    @Override
    public void close() {
    }

    private void encryptUserWithId(String realmId, String userId) {
        logger.debugf("Event: USER_ENCRYPTION, Realm: %s, User: %s", realmId, userId);
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        UserEntity userEntity = LogicUtils.getUserEntity(em, userId);
        LogicUtils.encryptUserEntity(session, em, userEntity);
        for (UserAttributeEntity uae : userEntity.getAttributes()) {
            LogicUtils.encryptUserAttributeEntity(session, em, uae);
        }
        em.flush();
    }

}
