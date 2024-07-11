# Keycloak PII Data Encryption Provider

## Introduction

This provider encrypts user attribute values before storing them to the database and decrypt them upon loading from the database. This is to address PDPA/GDPR requirement that needs any PII data to not be stored in plain/raw format at rest.

## How to install

### Manual Install

Git clone this repo:

```shell
git clone https://github.com/MLukman/Keycloak-PII-Data-Encryption-Provider.git Keycloak-PII-Data-Encryption-Provider
cd Keycloak-PII-Data-Encryption-Provider
```

Compile this provider into a JAR file using. JDK 17 or above and Maven are required to be pre-installed on the machine:

```shell 
mvn clean package
```

Copy paste the packaged JAR file from inside `target` folder into Keycloak's `providers` folder. Run `kc.sh build` command to get Keycloak to register this provider.

### Install Inside Docker Image

Use this method if this provider needs to be pre-packaged inside a custom Keycloak Docker image. Below is a sample Dockerfile:

```dockerfile
# Build the provider
FROM maven:3.8.1-openjdk-17-slim AS keycloak-pii-data-encryption
WORKDIR /app
RUN apt-get update && apt-get install -y git && apt-get clean
RUN git clone https://github.com/MLukman/Keycloak-PII-Data-Encryption-Provider.git .
RUN mvn clean package

################################################################################

# Base image from official keycloak
FROM quay.io/keycloak/keycloak:25.0.1

# Add provider JAR
COPY --from=keycloak-pii-data-encryption /app/target/*.jar /opt/keycloak/providers

# Need to build after adding providers
RUN /opt/keycloak/bin/kc.sh build

```

## How to use

This provider requires the encryption key to be provided via environment variable `KC_PII_ENCKEY`. There is a default fallback that uses MD5 hash of environment variable `KC_DB_URL` if the encryption key is not provided. 

As of now, this provider automatically encrypt and decrypt any user attributes that have their names start with "pii-" prefix. Future versions might introduce more methods to specify which attributes to be encrypted and decrypted.