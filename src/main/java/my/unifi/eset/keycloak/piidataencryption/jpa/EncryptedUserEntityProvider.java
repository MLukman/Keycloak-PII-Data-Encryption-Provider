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

import java.util.Arrays;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Applies the Liquibase changelog that contains the database table definition for
 * USER_ENTITY_ENCRYPTED and register the corresponding entity class.
 */
public class EncryptedUserEntityProvider implements JpaEntityProviderFactory, JpaEntityProvider {

    @Override
    public JpaEntityProvider create(KeycloakSession ks) {
        return this;
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
        return "EncryptedUserEntity";
    }

    @Override
    public List<Class<?>> getEntities() {
        return Arrays.asList(EncryptedUserEntity.class, EncryptedUserAttributeEntity.class);
    }

    @Override
    public String getChangelogLocation() {
        return "META-INF/user_entity_encrypted.xml";
    }

    @Override
    public String getFactoryId() {
        return "USER_ENTITY_ENCRYPTED";
    }

}
