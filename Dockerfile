ARG KEYCLOAK_VERSION=26.3.0

### Build provider keycloak-pii-data-encryption

FROM maven:3-openjdk-17-slim AS provider-pii
ARG KEYCLOAK_VERSION
WORKDIR /app
COPY pom.xml .
RUN mvn verify -B -Dkeycloak.version=$KEYCLOAK_VERSION
COPY src ./src
RUN mvn test package -B -Dkeycloak.version=$KEYCLOAK_VERSION

### Build customized Keycloak

# Base image from official keycloak
FROM quay.io/keycloak/keycloak:$KEYCLOAK_VERSION

COPY --from=provider-pii /app/target/*.jar /opt/keycloak/providers

# Need to build after adding providers
RUN /opt/keycloak/bin/kc.sh build --db=mysql --features="declarative-ui" --spi-user-provider=jpa-encrypted

