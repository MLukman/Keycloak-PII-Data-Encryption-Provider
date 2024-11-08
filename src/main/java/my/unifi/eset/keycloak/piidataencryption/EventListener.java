package my.unifi.eset.keycloak.piidataencryption;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.entities.UserAttributeEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.utils.KeycloakSessionUtil;

public class EventListener implements EventListenerProvider, EventListenerProviderFactory {

    private static final Logger logger = Logger.getLogger(EventListener.class);
    public static final String ID = "pii-data-encryption";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void onEvent(Event event) {
        if (event.getType() != EventType.REGISTER && event.getType() != EventType.UPDATE_PROFILE) {
            // non-relevant event
            return;
        }

        KeycloakSession session = KeycloakSessionUtil.getKeycloakSession();
        UserModel user = session.users().getUserById(session.realms().getRealm(event.getRealmId()), event.getUserId());
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        UserEntity userEntity = LogicUtils.getUserEntity(em, user.getId());

        LogicUtils.encryptUserEntity(session, em, userEntity);
        for (UserAttributeEntity uae : userEntity.getAttributes()) {
            LogicUtils.encryptUserAttributeEntity(session, em, uae);
        }
        em.flush();
    }

    @Override
    public void onEvent(AdminEvent ae, boolean bln) {
    }

    @Override
    public void close() {
    }

    @Override
    public EventListenerProvider create(KeycloakSession ks) {
        return this;
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory ksf) {
    }

}
