package my.unifi.eset.keycloak.piidataencryption.admin;

import my.unifi.eset.keycloak.piidataencryption.utils.LogicUtils;
import java.util.List;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ConfiguredProvider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.validate.AbstractSimpleValidator;
import org.keycloak.validate.ValidationContext;
import org.keycloak.validate.ValidationResult;
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
        final ProviderConfigurationBuilder builder = ProviderConfigurationBuilder.create();
        builder.property()
                .name("enable")
                .label("Enable encryption")
                .helpText("Enable encryption of this attribute in the database")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue(true)
                .add();
        return builder.build();
    }

    @Override
    public ValidationResult validateConfig(KeycloakSession session, ValidatorConfig config) {
        if (config.getBooleanOrDefault("enable", false) && !LogicUtils.isUserEncryptionEnabled(session, session.getContext().getRealm())) {
            throw new ComponentValidationException(String.format(" (%s -> Please enable user entity encryption in its tab under this realm settings)", ID));
        }
        return super.validateConfig(session, config);
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
