# Plugin binary for OpenBao to download. OpenBao reads ENTRYPOINT to find it.
FROM scratch
ARG TARGET
ARG SOURCE=https://github.com/bjd5o/openbao-plugin-secrets-kanidm
LABEL org.opencontainers.image.source=${SOURCE}
LABEL org.opencontainers.image.licenses=MPL-2.0
COPY bin/openbao-plugin-secrets-kanidm_${TARGET} /openbao-plugin-secrets-kanidm
ENTRYPOINT ["/openbao-plugin-secrets-kanidm"]
