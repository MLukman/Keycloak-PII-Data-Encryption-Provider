package my.unifi.eset.keycloak.piidataencryption.listeners;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Registers event listener pii-data-encryption to be in the event listeners 
 * drop-down in the realm settings
 * 
 * @author MLukman (https://github.com/MLukman)
 */
public class EventListenerFactory implements EventListenerProviderFactory {

    public static final String ID = "pii-data-encryption";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void close() {
    }

    @Override
    public EventListenerProvider create(KeycloakSession ks) {
        return new EventListener(ks);
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory ksf) {
    }

}
