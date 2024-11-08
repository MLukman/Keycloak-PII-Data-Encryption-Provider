package my.unifi.eset.keycloak.piidataencryption;

import jakarta.persistence.EntityManager;
import jakarta.persistence.FlushModeType;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserProvider;
import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserProvider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.services.ui.extend.UiTabProvider;
import org.keycloak.services.ui.extend.UiTabProviderFactory;
import org.keycloak.utils.KeycloakSessionUtil;

public class UserEntityEncryptionConfigurationProvider implements UiTabProvider, UiTabProviderFactory<ComponentModel> {

    public static final String ID = "User Entity Encryption";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getHelpText() {
        return "Enable/disable encryption of PII columns inside the USER_ENTITY table in the database";
    }

    @Override
    public String getPath() {
        return "/:realm/realm-settings/:tab?";
    }

    @Override
    public Map<String, String> getParams() {
        Map<String, String> params = new HashMap<>();
        params.put("tab", "user-entity-encryption");
        return params;
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory ksf) {
    }

    @Override
    public void close() {
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        final ProviderConfigurationBuilder builder = ProviderConfigurationBuilder.create();
        builder.property()
                .name("enable")
                .label("Enable encryption")
                .helpText("Enable encryption of username & email in the database")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .add();
        return builder.build();
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model) throws ComponentValidationException {
        boolean providerActive = KeycloakSessionUtil.getKeycloakSession().getProvider(UserProvider.class) instanceof EncryptedUserProvider;
        boolean eventListenerActive = realm.getEventsListenersStream().anyMatch((t) -> t.equals(EventListener.ID));
        if (model.get("enable", false) && !(providerActive && eventListenerActive)) {
            throw new ComponentValidationException("\nUser entity encryption cannot be enabled until \n(1) EncryptedUserProvider is enabled using --spi-user-provider=jpa-encrypted build/start flag \n(2) pii-data-encryption' event listener is added to the realm events setting");
        }
    }

    @Override
    public void onCreate(KeycloakSession session, RealmModel realm, ComponentModel model) {
        saveConfiguration(session, realm, model);
        UiTabProviderFactory.super.onCreate(session, realm, model);
    }

    @Override
    public void onUpdate(KeycloakSession session, RealmModel realm, ComponentModel oldModel, ComponentModel newModel) {
        saveConfiguration(session, realm, newModel);
        UiTabProviderFactory.super.onUpdate(session, realm, oldModel, newModel);
    }

    void saveConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model) {
        boolean toEncrypt = model.get("enable", false);
        if (session.getProvider(UserProvider.class) instanceof EncryptedUserProvider) {
            LogicUtils.setUserEncryptionEnabled(realm, toEncrypt);
            if (toEncrypt) {
                EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
                em.setFlushMode(FlushModeType.COMMIT);
                LogicUtils.encryptExistingUserEntities(session, em, realm.getId());
                em.flush();
            }
        } else {
            toEncrypt = false;
        }
        if (!toEncrypt) {
            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
            em.setFlushMode(FlushModeType.COMMIT);
            LogicUtils.decryptExistingUserEntities(em, realm.getId());
            em.flush();
        }
    }

}
