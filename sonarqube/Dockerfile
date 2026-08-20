FROM sonarqube:lts-community

ARG PLUGIN_VERSION=0.2.1
ARG PLUGIN_FILENAME=community-rust-plugin-${PLUGIN_VERSION}.jar
ARG PLUGIN_URL=https://github.com/C4tWithShell/community-rust/releases/download/v${PLUGIN_VERSION}/${PLUGIN_FILENAME}

USER root

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl ca-certificates; \
    mkdir -p /opt/sonarqube/extensions/plugins; \
    curl -fL "${PLUGIN_URL}" -o "/opt/sonarqube/extensions/plugins/${PLUGIN_FILENAME}"; \
    chown -R 1000:1000 /opt/sonarqube/extensions; \
    apt-get remove -y curl && apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*

USER 1000
