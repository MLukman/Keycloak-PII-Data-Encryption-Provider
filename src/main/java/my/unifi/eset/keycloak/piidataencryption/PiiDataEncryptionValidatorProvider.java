package my.unifi.eset.keycloak.piidataencryption;

import java.util.ArrayList;
import java.util.List;
import org.keycloak.provider.ConfiguredProvider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.validate.AbstractSimpleValidator;
import org.keycloak.validate.ValidationContext;
import org.keycloak.validate.ValidatorConfig;

/**
 * Provide "pii-data-encryption" user attribute validator type inside
 * Create/Edit attribute forms.
 *
 * @author MLukman (https://github.com/MLukman)
 */
public class PiiDataEncryptionValidatorProvider extends AbstractSimpleValidator implements ConfiguredProvider {

    public static final String ID = "pii-data-encryption";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getHelpText() {
        return "This validator does not validate the value. Instead, it encrypts the value before storing to the database.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return new ArrayList<>();
    }

    @Override
    protected boolean skipValidation(Object o, ValidatorConfig vc) {
        return true;
    }

    @Override
    protected void doValidate(Object o, String string, ValidationContext vc, ValidatorConfig vc1) {
        throw new UnsupportedOperationException("This code should not be executed because skipValidation() returns true");
    }

}
