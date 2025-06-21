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

package my.unifi.eset.keycloak.piidataencryption.admin;

import java.util.List;
import org.keycloak.provider.ConfiguredProvider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
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
    protected boolean skipValidation(Object o, ValidatorConfig vc) {
        return true;
    }

    @Override
    protected void doValidate(Object o, String string, ValidationContext vc, ValidatorConfig vc1) {
        throw new UnsupportedOperationException("This code should not be executed because skipValidation() returns true");
    }

}
