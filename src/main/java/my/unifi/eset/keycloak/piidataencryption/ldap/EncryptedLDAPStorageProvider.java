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

import jakarta.persistence.EntityManager;
import my.unifi.eset.keycloak.piidataencryption.utils.LogicUtils;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.LDAPStorageProviderFactory;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.store.ldap.LDAPIdentityStore;

public class EncryptedLDAPStorageProvider extends LDAPStorageProvider {

    private static final Logger logger = Logger.getLogger(EncryptedLDAPStorageProvider.class);

    public EncryptedLDAPStorageProvider(LDAPStorageProviderFactory factory, KeycloakSession session, ComponentModel model, LDAPIdentityStore ldapIdentityStore) {
        super(factory, session, model, ldapIdentityStore);
    }

    @Override
    protected UserModel importUserFromLDAP(KeycloakSession session, RealmModel realm, LDAPObject ldapUser, ImportType importType) {
        logger.debugf("importUserFromLDAP(KeycloakSession session, RealmModel realm, LDAPObject ldapUser, ImportType importType)");
        UserModel userModel = super.importUserFromLDAP(session, realm, ldapUser, importType);
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        LogicUtils.encryptUserEntity(session, em, LogicUtils.getUserEntity(em, userModel.getId()));
        em.flush();
        logger.debugf("importUserFromLDAP (encrypted): " + userModel.getUsername());
        return userModel;
    }

}
