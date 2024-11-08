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
