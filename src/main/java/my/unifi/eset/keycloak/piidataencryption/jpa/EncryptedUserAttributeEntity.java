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

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import org.keycloak.models.jpa.entities.UserAttributeEntity;
import org.keycloak.models.jpa.entities.UserEntity;

@Entity
@Table(name = "USER_ATTRIBUTE_ENCRYPTED")
public class EncryptedUserAttributeEntity {

    @Id
    @Column(name = "ID", length = 36)
    protected String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "USER_ID")
    protected UserEntity user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "USER_ATTRIBUTE_ID")
    protected UserAttributeEntity attribute;

    @Column(name = "NAME", length = 255)
    protected String name;

    @Column(name = "VALUE", length = 1000)
    protected String value;

    public EncryptedUserAttributeEntity() {
    }

    public EncryptedUserAttributeEntity(String id, UserEntity user, String name) {
        this.id = id;
        this.user = user;
        this.name = name;
    }

    public String getId() {
        return id;
    }

    public UserEntity getUser() {
        return user;
    }

    public String getName() {
        return name;
    }

    public UserAttributeEntity getAttribute() {
        return attribute;
    }

    public void setAttribute(UserAttributeEntity attribute) {
        this.attribute = attribute;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

}
