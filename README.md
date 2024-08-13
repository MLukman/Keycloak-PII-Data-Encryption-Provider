# Keycloak PII Data Encryption Provider

## Introduction

This provider encrypts user attribute values before storing them to the database and decrypt them upon loading from the database. This is to address data security regulations such as GDPR that require any PII data to not be stored in plain/raw format at rest.

## How to install

### Manual install

Git clone this repo:

```shell
git clone https://github.com/MLukman/Keycloak-PII-Data-Encryption-Provider.git Keycloak-PII-Data-Encryption-Provider
cd Keycloak-PII-Data-Encryption-Provider
```

Compile this provider into a JAR file using the following command. JDK 17 or above and Maven are required to be pre-installed on the machine.

```shell 
mvn clean package
```

Copy paste the packaged JAR file from inside `target` folder into Keycloak's `providers` folder. Run `kc.sh build` command to get Keycloak to register this provider.

### Install inside Docker Image

Use this method if this provider needs to be pre-packaged inside a custom Keycloak Docker image. Below is a sample Dockerfile:

```dockerfile
# ARG defined before FROM in multi-staged Dockerfile is shared among the stages
ARG KEYCLOAK_VERSION=25.0.2

# Build the provider
FROM maven:3.8.1-openjdk-17-slim AS keycloak-pii-data-encryption
ARG KEYCLOAK_VERSION # Dockerfile peculiarity that requires ARG defined before FROM to be re-declared afterwards if we want to use instead the stage
WORKDIR /app
RUN apt-get update && apt-get install -y git && apt-get clean
RUN git clone https://github.com/MLukman/Keycloak-PII-Data-Encryption-Provider.git .
RUN mvn clean package -Dkeycloak.version=$KEYCLOAK_VERSION

################################################################################

# Base image from official keycloak
FROM quay.io/keycloak/keycloak:$KEYCLOAK_VERSION

# Add provider JAR
COPY --from=keycloak-pii-data-encryption /app/target/*.jar /opt/keycloak/providers

# Need to build after adding providers
RUN /opt/keycloak/bin/kc.sh build

```

## How to use

### Setting the encryption key

This provider requires the encryption key to be provided via environment variable `KC_PII_ENCKEY`. There is, however, a default fallback that uses MD5 hash of environment variable `KC_DB_URL` if the encryption key is not provided. If you rely on this fallback and in the future need to migrate your Keycloak data into another databases that results in a different value of `KC_DB_URL`, you need to get the old value of `KC_DB_URL`, encode it using lowercased MD5 hash and set the value to the `KC_PII_ENCKEY` environment variable.

### Enabling the encryption

Enabling the encryption for a specific user attribute is as simple as adding the custom validator of type `pii-data-encryption` inside the "Create attribute" or "Edit attribute" form of that attribute in the admin console.

![Screenshot of "Add validator" popup dialog](screenshot-add-validator.png)

This provider also automatically encrypts any user attributes that have their names start with "pii-" prefix even without the validator.

## Known issues/limitations

1. Built-in user attributes `username` and `email` as well as unmanaged attributes are not supported.
2. If the encrypted values in the database cannot be decrypted for whatever reason, the base64 encrypted value will be displayed as-is to the users and clients. This may cause confusions.

