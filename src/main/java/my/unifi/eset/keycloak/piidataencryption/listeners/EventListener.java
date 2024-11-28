package my.unifi.eset.keycloak.piidataencryption.listeners;

import my.unifi.eset.keycloak.piidataencryption.utils.LogicUtils;
import jakarta.persistence.EntityManager;
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

public class EventListener implements EventListenerProvider {

    private final KeycloakSession session;

    public EventListener(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void onEvent(Event event) {
        if (event.getType() != EventType.REGISTER && event.getType() != EventType.UPDATE_PROFILE) {
            // non-relevant event
            return;
        }

        UserModel user = session.users().getUserById(session.realms().getRealm(event.getRealmId()), event.getUserId());
        encryptUserWithId(user.getId());
    }

    @Override
    public void onEvent(AdminEvent ae, boolean bln) {
        if (ae.getResourceType() == ResourceType.USER && ae.getOperationType() == OperationType.UPDATE) {
            String userId = ae.getResourcePath().split("/")[1];
            encryptUserWithId(userId);
        }
    }

    @Override
    public void close() {
    }

    private void encryptUserWithId(String userId) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        UserEntity userEntity = LogicUtils.getUserEntity(em, userId);
        LogicUtils.encryptUserEntity(session, em, userEntity);
        for (UserAttributeEntity uae : userEntity.getAttributes()) {
            LogicUtils.encryptUserAttributeEntity(session, em, uae);
        }
        em.flush();
    }

}
