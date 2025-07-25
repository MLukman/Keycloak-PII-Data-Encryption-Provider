package my.unifi.eset.keycloak.piidataencryption.ldap;

import jakarta.persistence.EntityManager;
import my.unifi.eset.keycloak.piidataencryption.utils.LogicUtils;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.storage.ldap.LDAPStorageProviderFactory;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.user.SynchronizationResult;

public class EncryptedLDAPStorageProviderFactory extends LDAPStorageProviderFactory {

    @Override
    public int order() {
        return 1000;
    }

    @Override
    protected SynchronizationResult syncImpl(KeycloakSessionFactory sessionFactory, LDAPQuery userQuery, String realmId, ComponentModel fedModel) {
        SynchronizationResult result = super.syncImpl(sessionFactory, userQuery, realmId, fedModel);
        KeycloakSession session = sessionFactory.create();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        LogicUtils.encryptExistingUserEntities(session, em, session.realms().getRealm(realmId));
        em.flush();
        return result;
    }

}
