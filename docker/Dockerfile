# Keycloak with PTSS Custom Theme
# Based on official Keycloak image with custom theme included

FROM quay.io/keycloak/keycloak:latest

# Copy custom theme to Keycloak themes directory
COPY themes/ptss_keycloak_theme /opt/keycloak/themes/ptss_keycloak_theme

# Set proper ownership
USER root
RUN chown -R keycloak:keycloak /opt/keycloak/themes/ptss_keycloak_theme
USER keycloak

# Set environment variables for production
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true

# Build Keycloak (optimizes startup time)
RUN /opt/keycloak/bin/kc.sh build

# Default command - can be overridden
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start"]
