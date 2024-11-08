package my.unifi.eset.keycloak.piidataencryption;

import jakarta.persistence.EntityManager;
import java.util.HashMap;
import java.util.Map;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserAttributeEntity;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserEntity;
import org.hibernate.boot.Metadata;
import org.hibernate.boot.spi.BootstrapContext;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.event.service.spi.EventListenerRegistry;
import org.hibernate.event.spi.EventSource;
import org.hibernate.event.spi.EventType;
import org.hibernate.event.spi.PostInsertEvent;
import org.hibernate.event.spi.PostInsertEventListener;
import org.hibernate.event.spi.PostLoadEvent;
import org.hibernate.event.spi.PostLoadEventListener;
import org.hibernate.event.spi.PreInsertEvent;
import org.hibernate.event.spi.PreInsertEventListener;
import org.hibernate.event.spi.PreLoadEvent;
import org.hibernate.event.spi.PreLoadEventListener;
import org.hibernate.event.spi.PreUpdateEvent;
import org.hibernate.event.spi.PreUpdateEventListener;
import org.hibernate.integrator.spi.Integrator;
import org.hibernate.persister.entity.EntityPersister;
import org.hibernate.service.spi.SessionFactoryServiceRegistry;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.jpa.entities.UserAttributeEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.utils.KeycloakSessionUtil;

/**
 * Listen to PrePersist, PreUpdate & PostLoad entity events and perform
 * encryption and decryption if entity is UserAttributeEntity
 *
 * @author MLukman (https://github.com/MLukman)
 */
public class EntityListener implements Integrator, PreLoadEventListener, PostLoadEventListener, PreInsertEventListener, PreUpdateEventListener, PostInsertEventListener {

    static final Logger logger = Logger.getLogger(EntityListener.class);

    @Override
    public void integrate(Metadata metadata, BootstrapContext bootstrapContext, SessionFactoryImplementor sessionFactory) {
        EventListenerRegistry eventListenerRegistry = sessionFactory.getServiceRegistry()
                .getService(EventListenerRegistry.class);
        eventListenerRegistry.appendListeners(EventType.PRE_LOAD, this);
        eventListenerRegistry.appendListeners(EventType.POST_LOAD, this);
        eventListenerRegistry.appendListeners(EventType.PRE_INSERT, this);
        eventListenerRegistry.appendListeners(EventType.PRE_UPDATE, this);
        eventListenerRegistry.appendListeners(EventType.POST_INSERT, this);
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

    @Override
    public boolean onPreInsert(PreInsertEvent pie) {
        KeycloakSession ks = KeycloakSessionUtil.getKeycloakSession();
        if (pie.getEntity() instanceof UserEntity ue && LogicUtils.isUserEncryptionEnabled(ks, ue.getRealmId())) {
            doEncryptUserEntity(ue,
                    pie.getPersister().getEntityMetamodel().getPropertyNames(),
                    pie.getState(),
                    pie.getSession());
        }
        if (pie.getEntity() instanceof UserAttributeEntity uae && LogicUtils.shouldEncryptAttribute(ks, uae)) {
            if (LogicUtils.isUserEncryptionEnabled(ks, uae.getUser().getRealmId())) {
                doEncryptUserAttributeEntity(uae,
                        pie.getPersister().getEntityMetamodel().getPropertyNames(),
                        pie.getState(),
                        pie.getSession());
            } else {
                logger.warnf("Event: ATTRIBUTE_ENCRYPTION_NOT_ENABLED, Realm: %s, User: %s, Attribute: %s", uae.getUser().getRealmId(), uae.getUser().getUsername(), uae.getName());
            }
        }
        return false;
    }

    @Override
    public boolean onPreUpdate(PreUpdateEvent pue) {
        if (pue.getEntity() instanceof UserEntity ue) {
            doEncryptUserEntity(ue,
                    pue.getPersister().getEntityMetamodel().getPropertyNames(),
                    pue.getState(),
                    pue.getSession());
        }
        return false;
    }

    void doEncryptUserEntity(UserEntity ue, String[] propertyNames, Object[] states, EventSource session) {
        EntityManager em = session.getSessionFactory().createEntityManager();
        EncryptedUserEntity eue = LogicUtils.getEncryptedUserEntity(em, ue, true);
        for (int i = 0; i < propertyNames.length; i++) {
            String valueToStore = states[i] != null ? EncryptionUtils.encryptValue(String.valueOf(states[i])) : null;
            switch (propertyNames[i]) {
                case "username" ->
                    eue.setUsername(valueToStore);
                case "email" ->
                    eue.setEmail(valueToStore);
                case "firstName" ->
                    eue.setFirstName(valueToStore);
                case "lastName" ->
                    eue.setLastName(valueToStore);
                default -> {
                    continue;
                }
            }
            states[i] = LogicUtils.hash(String.valueOf(states[i]));
        }
        em.persist(eue);
        em.flush();
    }

    void doEncryptUserAttributeEntity(UserAttributeEntity uae, String[] propertyNames, Object[] states, EventSource session) {
        EntityManager em = session.getSessionFactory().createEntityManager();
        EncryptedUserAttributeEntity euae = LogicUtils.getEncryptedUserAttributeEntity(em, uae.getUser(), uae.getName(), true);
        euae.setValue(EncryptionUtils.encryptValue(uae.getValue()));
        em.persist(euae);
        for (int i = 0; i < propertyNames.length; i++) {
            if ("value".equalsIgnoreCase(propertyNames[i])) {
                states[i] = LogicUtils.hash(String.valueOf(states[i]));
                logger.debugf("Event: ATTRIBUTE_ENCRYPTION_SUCCESS, Realm: %s, User: %s, Attribute: %s", uae.getUser().getRealmId(), uae.getUser().getUsername(), uae.getName());
                em.flush();
                return;
            }
        }
        logger.warnf("Event: ATTRIBUTE_ENCRYPTION_FAILURE, Realm: %s, User: %s, Attribute: %s", uae.getUser().getRealmId(), uae.getUser().getUsername(), uae.getName());
    }

    @Override
    public void onPostInsert(PostInsertEvent pie) {
        /*
        * For UserAttributeEntity, during PreInsert we persisted its corresponding EncryptedUserAttributeEntity
        * but without the attribute column populated because the entity is not persisted yet.
        * Hence, we need do it here in PostInsert.
         */
        if (pie.getEntity() instanceof UserAttributeEntity uae) {
            EntityManager em = pie.getSession().getSessionFactory().createEntityManager();
            EncryptedUserAttributeEntity euae = LogicUtils.getEncryptedUserAttributeEntity(em, uae.getUser(), uae.getName(), false);
            if (euae != null) {
                euae.setAttribute(uae);
            }
        }
    }

    @Override
    public boolean requiresPostCommitHandling(EntityPersister ep) {
        return false;
    }

}
