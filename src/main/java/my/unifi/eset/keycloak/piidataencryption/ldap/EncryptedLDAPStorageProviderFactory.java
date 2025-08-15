/*
 * Copyright (C) 2025 Muhammad Lukman Nasaruddin <lukman.nasaruddin@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */
package my.unifi.eset.keycloak.piidataencryption.ldap;

import java.util.Map;
import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.storage.ldap.LDAPIdentityStoreRegistry;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.LDAPStorageProviderFactory;
import org.keycloak.storage.ldap.idm.store.ldap.LDAPIdentityStore;
import org.keycloak.storage.ldap.mappers.LDAPConfigDecorator;

public class EncryptedLDAPStorageProviderFactory extends LDAPStorageProviderFactory {

    LDAPIdentityStoreRegistry ldapStoreRegistryOverride;

    @Override
    public int order() {
        return 1000;
    }

    @Override
    public void init(Config.Scope config) {
        super.init(config);
        this.ldapStoreRegistryOverride = new LDAPIdentityStoreRegistry();
    }

    @Override
    public void close() {
        super.close();
        this.ldapStoreRegistryOverride = null;
    }

    @Override
    public LDAPStorageProvider create(KeycloakSession session, ComponentModel model) {
        Map<ComponentModel, LDAPConfigDecorator> configDecorators = getLDAPConfigDecorators(session, model);
        LDAPIdentityStore ldapIdentityStore = this.ldapStoreRegistryOverride.getLdapStore(session, model, configDecorators);
        return new EncryptedLDAPStorageProvider(this, session, model, ldapIdentityStore);
    }

}
