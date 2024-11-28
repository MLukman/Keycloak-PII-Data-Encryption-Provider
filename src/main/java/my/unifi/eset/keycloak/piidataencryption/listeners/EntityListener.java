package my.unifi.eset.keycloak.piidataencryption.listeners;

import my.unifi.eset.keycloak.piidataencryption.utils.EncryptionUtils;
import my.unifi.eset.keycloak.piidataencryption.utils.LogicUtils;
import jakarta.persistence.EntityManager;
import java.util.HashMap;
import java.util.Map;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserAttributeEntity;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserEntity;
import org.hibernate.boot.Metadata;
import org.hibernate.boot.spi.BootstrapContext;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.event.service.spi.EventListenerRegistry;
import org.hibernate.event.spi.EventType;
import org.hibernate.event.spi.PostLoadEvent;
import org.hibernate.event.spi.PostLoadEventListener;
import org.hibernate.event.spi.PreLoadEvent;
import org.hibernate.event.spi.PreLoadEventListener;
import org.hibernate.integrator.spi.Integrator;
import org.hibernate.service.spi.SessionFactoryServiceRegistry;
import org.jboss.logging.Logger;
import org.keycloak.models.jpa.entities.UserAttributeEntity;
import org.keycloak.models.jpa.entities.UserEntity;

/**
 * Listen to PrePersist, PreUpdate & PostLoad entity events and perform
 * encryption and decryption if entity is UserAttributeEntity
 *
 * @author MLukman (https://github.com/MLukman)
 */
public class EntityListener implements Integrator, PreLoadEventListener, PostLoadEventListener {

    static final Logger logger = Logger.getLogger(EntityListener.class);

    @Override
    public void integrate(Metadata metadata, BootstrapContext bootstrapContext, SessionFactoryImplementor sessionFactory) {
        EventListenerRegistry eventListenerRegistry = sessionFactory.getServiceRegistry()
                .getService(EventListenerRegistry.class);
        eventListenerRegistry.appendListeners(EventType.PRE_LOAD, this);
        eventListenerRegistry.appendListeners(EventType.POST_LOAD, this);
    }

    @Override
    public void disintegrate(SessionFactoryImplementor sfi, SessionFactoryServiceRegistry sfsr) {
    }

    @Override
    public void onPreLoad(PreLoadEvent ple) {
        EntityManager em = ple.getSession().getSessionFactory().createEntityManager();
        EncryptedUserEntity eue;
        if (ple.getEntity() instanceof UserEntity ue && null != (eue = LogicUtils.getEncryptedUserEntity(em, ue, false))) {
            String[] props = ple.getPersister().getEntityMetamodel().getPropertyNames();
            Object[] states = ple.getState();
            for (int i = 0; i < props.length; i++) {
                switch (props[i]) {
                    case "username" ->
                        states[i] = EncryptionUtils.decryptValue(eue.getUsername());
                    case "email" ->
                        states[i] = EncryptionUtils.decryptValue(eue.getEmail());
                    case "firstName" ->
                        states[i] = EncryptionUtils.decryptValue(eue.getFirstName());
                    case "lastName" ->
                        states[i] = EncryptionUtils.decryptValue(eue.getLastName());
                }
            }
        }
        if (ple.getEntity() instanceof UserAttributeEntity uae) {
            Map<String, Integer> cols = new HashMap<>(Map.of("user", -1, "name", -1, "value", -1));
            String[] propertyNames = ple.getPersister().getEntityMetamodel().getPropertyNames();
            Object[] states = ple.getState();
            for (int i = 0; i < propertyNames.length; i++) {
                if (cols.containsKey(propertyNames[i])) {
                    cols.put(propertyNames[i], i);
                }
            }
            EncryptedUserAttributeEntity euae = LogicUtils.getEncryptedUserAttributeEntity(em, (UserEntity) states[cols.get("user")], String.valueOf(states[cols.get("name")]), false);
            if (euae != null) {
                states[cols.get("value")] = EncryptionUtils.decryptValue(euae.getValue());
            } else if (EncryptionUtils.isEncryptedValue(String.valueOf(states[cols.get("value")]))) {
                states[cols.get("value")] = EncryptionUtils.decryptValue(String.valueOf(states[cols.get("value")]));
            }
        }
    }

    @Override
    public void onPostLoad(PostLoadEvent ple) {
        if (ple.getEntity() instanceof UserAttributeEntity uae && EncryptionUtils.isEncryptedValue(uae.getValue())) {
            logger.warnf("Event: ATTRIBUTE_DECRYPTION_FAILURE, Realm: %s, User: %s, Attribute: %s", uae.getUser().getRealmId(), uae.getUser().getUsername(), uae.getName());
        }
    }
}
