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

package my.unifi.eset.keycloak.piidataencryption.jpa;

import jakarta.persistence.EntityManager;
import org.keycloak.Config;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserProviderFactory;
import org.keycloak.provider.Provider;

public class EncryptedUserProviderFactory implements UserProviderFactory {

    @Override
    public Provider create(KeycloakSession ks) {
        EntityManager em = ks.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new EncryptedUserProvider(ks, em);
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
    public String getId() {
        return "jpa-encrypted";
    }

}
