# Stock Keycloak base + realm import + the Java MFA-setup authenticator. Java authenticators are
# Kiban behavior and ship; theming/Node stays out — no Node stage here.
FROM maven:3-eclipse-temurin-17@sha256:1e539ad894cb86c5b87a9c81223732a90c6cb7c23e4ac206c2cea892538fd8d7 AS authenticator-builder

WORKDIR /workspace
COPY authenticator/ ./
RUN mvn -q -f pom.xml package

FROM quay.io/keycloak/keycloak:26.6.1@sha256:dea26401d06341095cc4ea9d66896200b55de5ca1daa1d2fcbe58493afa6e0ad

COPY --from=authenticator-builder /workspace/target/kiban-authenticator-*.jar /opt/keycloak/providers/
# --chown: the container runs as the non-root `keycloak` user (uid 1000, gid 0) and
# start.sh renders the template in place at boot — /opt/keycloak/data/import is root:root 755
# by default in the base image, so without this the render's redirect hits Permission denied.
COPY --chown=keycloak:root realm-kiban.json /opt/keycloak/data/import/realm-kiban.json.template
COPY --chmod=755 start.sh /opt/keycloak/bin/kiban-start.sh

RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kiban-start.sh"]
CMD ["start", "--import-realm"]
