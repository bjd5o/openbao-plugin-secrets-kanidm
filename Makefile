BINARY  := openbao-plugin-secrets-kanidm
VERSION ?= v0.1.0
GOOS    ?= $(shell go env GOOS)
GOARCH  ?= $(shell go env GOARCH)
LDFLAGS := -s -w -X openbao-plugin-secrets-kanidm/backend.Version=$(VERSION)

.PHONY: build test integration release image clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY) ./cmd/$(BINARY)

test:
	go vet ./...
	go vet -tags integration ./integration/
	go test -race -count=1 ./...

integration:
	scripts/integration.sh

# Static linux binaries plus SHA256SUMS, for publishing with a release.
release:
	rm -rf dist/release && mkdir -p dist/release
	for arch in amd64 arm64; do \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
	    -o dist/release/$(BINARY)_$(VERSION)_linux_$$arch ./cmd/$(BINARY) || exit 1; \
	done
	cd dist/release && sha256sum $(BINARY)_* > SHA256SUMS 2>/dev/null || shasum -a 256 $(BINARY)_* > SHA256SUMS
	cat dist/release/SHA256SUMS

image:
	docker build --build-arg VERSION=$(VERSION) -t openbao-kanidm:$(VERSION) .

clean:
	rm -rf dist integration/.state
