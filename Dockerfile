# OpenBao with the Kanidm secrets engine baked into its plugin directory.
#
#   docker build -t openbao-kanidm .
#   docker build --build-arg TAGS=faulthook -t openbao-kanidm:itest .   # test-only fault hook
#
# Register the plugin declaratively (see deploy/openbao.hcl) using the
# SHA-256 printed in the build log, or read it from
# /openbao/plugins/openbao-plugin-secrets-kanidm.sha256 in the image.

ARG GO_VERSION=1.27
ARG OPENBAO_VERSION=2.7.1

FROM docker.io/golang:${GO_VERSION} AS build
ARG VERSION=v0.1.0
ARG TAGS=""
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -tags "${TAGS}" \
      -ldflags "-s -w -X openbao-plugin-secrets-kanidm/backend.Version=${VERSION}" \
      -o /out/openbao-plugin-secrets-kanidm ./cmd/openbao-plugin-secrets-kanidm \
 && cd /out && sha256sum openbao-plugin-secrets-kanidm | cut -d' ' -f1 > openbao-plugin-secrets-kanidm.sha256 \
 && echo "sha256: $(cat openbao-plugin-secrets-kanidm.sha256)"

FROM docker.io/openbao/openbao:${OPENBAO_VERSION}
COPY --from=build --chown=root:root --chmod=0755 /out/openbao-plugin-secrets-kanidm /openbao/plugins/
COPY --from=build --chown=root:root --chmod=0644 /out/openbao-plugin-secrets-kanidm.sha256 /openbao/plugins/
