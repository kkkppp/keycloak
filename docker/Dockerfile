# Use the official Keycloak image as the base
FROM quay.io/keycloak/keycloak:24.0.2

# Set environment variables for Keycloak
ENV KC_DB=postgres
ENV KC_DB_URL=jdbc:postgresql://${DB_HOST:-localhost}:${DB_PORT:-5432}/${DB_DATABASE:-keycloak}
ENV KC_DB_USERNAME=${DB_USER:-keycloak}
ENV KC_DB_PASSWORD=${DB_PASSWORD:-keycloak}

# Set the working directory
WORKDIR /opt/keycloak

# Copy your provider JAR into the providers directory
COPY build/libs/keycloak-1.0.0.jar /opt/keycloak/providers/
COPY build/libs/external/*.jar /opt/keycloak/providers/

# Copy realm settings for import
COPY src/main/resources/json/realm-export.json /opt/keycloak/data/import/realm-export.json
USER root
RUN chmod 777 /opt/keycloak/data/import
USER keycloak

# Create scripts directory
RUN mkdir -p /opt/keycloak/scripts

# Copy the script into the container
COPY docker/replace-host.sh /opt/keycloak/scripts/replace-host.sh

# Make the script executable
#RUN chmod 755 /opt/keycloak/scripts/replace-host.sh
# Optional: If you have additional configuration files, copy them
# COPY keycloak.conf /opt/keycloak/conf/keycloak.conf

# Build the Keycloak distribution
RUN /opt/keycloak/bin/kc.sh build --verbose

# Expose the Keycloak port
EXPOSE 8080
#EXPOSE 5005

# Set the entrypoint
ENTRYPOINT ["/bin/sh", "-c", "/opt/keycloak/scripts/replace-host.sh && /opt/keycloak/bin/kc.sh start-dev --import-realm"]

# Define the command to run Keycloak
#CMD ["start-dev", "--verbose", "--import-realm"]
