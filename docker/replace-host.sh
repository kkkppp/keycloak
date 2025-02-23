#!/bin/sh

echo "Replacing 'http://localhost' with '${HOST_URL}' in realm-export.json..."
sed -i "s|http://localhost|${HOST_URL}|g" /opt/keycloak/data/import/realm-export.json

echo "Starting Keycloak with updated realm-export.json..."
exec "$@"
