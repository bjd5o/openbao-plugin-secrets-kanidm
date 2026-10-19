BINARY  := openbao-plugin-secrets-kanidm
VERSION ?= v0.1.0
IMAGE   ?= ghcr.io/bjd5o/openbao-plugin-secrets-kanidm
SOURCE  ?= https://github.com/bjd5o/openbao-plugin-secrets-kanidm
LDFLAGS := -s -w -X openbao-plugin-secrets-kanidm/backend.Version=$(VERSION)

# Same targets as github.com/openbao/openbao-plugins. The suffix is the
# Go architecture variant (GOAMD64=v1, GOARM=6, GOARM64=v8) and is part of
# the artifact name; OpenBao selects the image entry by platform.
TARGETS := \
	linux_amd64_v1 \
	linux_arm_6 \
	linux_arm64_v8 \
	linux_ppc64le \
	linux_riscv64_rva20u64 \
	linux_s390x \
	darwin_amd64_v1 \
	darwin_arm64_v8 \
	dragonfly_amd64_v1 \
	freebsd_amd64_v1 \
	freebsd_arm_6 \
	freebsd_arm64_v8 \
	illumos_amd64_v1 \
	netbsd_amd64_v1 \
	netbsd_arm_6 \
	netbsd_arm64_v8 \
	openbsd_amd64_v1 \
	openbsd_arm_6 \
	openbsd_arm64_v8 \
	windows_amd64_v1 \
	windows_arm64_v8

BINARIES := $(addprefix bin/$(BINARY)_,$(TARGETS))
TARBALLS := $(addprefix dist/$(BINARY)_,$(addsuffix .tar.gz,$(filter-out windows_%,$(TARGETS))))
ZIPS     := $(addprefix dist/$(BINARY)_,$(addsuffix .zip,$(filter windows_%,$(TARGETS))))
ARCHIVES := $(TARBALLS) $(ZIPS)
SIGNATURES := $(ARCHIVES:=.sig)
SBOMS := $(ARCHIVES:=.spdx.sbom.json)

# Clear variant flags first so a later target in one Make process does not
# inherit GOARM from an earlier one.
define set_vars
GOOS :=
GOARCH :=
GOARM :=
ifeq ($1, linux_amd64_v1)
GOOS := linux
GOARCH := amd64
else ifeq ($1, linux_arm_6)
GOOS := linux
GOARCH := arm
GOARM := 6
else ifeq ($1, linux_arm64_v8)
GOOS := linux
GOARCH := arm64
else ifeq ($1, linux_ppc64le)
GOOS := linux
GOARCH := ppc64le
else ifeq ($1, linux_riscv64_rva20u64)
GOOS := linux
GOARCH := riscv64
else ifeq ($1, linux_s390x)
GOOS := linux
GOARCH := s390x
else ifeq ($1, darwin_amd64_v1)
GOOS := darwin
GOARCH := amd64
else ifeq ($1, darwin_arm64_v8)
GOOS := darwin
GOARCH := arm64
else ifeq ($1, dragonfly_amd64_v1)
GOOS := dragonfly
GOARCH := amd64
else ifeq ($1, freebsd_amd64_v1)
GOOS := freebsd
GOARCH := amd64
else ifeq ($1, freebsd_arm_6)
GOOS := freebsd
GOARCH := arm
GOARM := 6
else ifeq ($1, freebsd_arm64_v8)
GOOS := freebsd
GOARCH := arm64
else ifeq ($1, illumos_amd64_v1)
GOOS := illumos
GOARCH := amd64
else ifeq ($1, netbsd_amd64_v1)
GOOS := netbsd
GOARCH := amd64
else ifeq ($1, netbsd_arm_6)
GOOS := netbsd
GOARCH := arm
GOARM := 6
else ifeq ($1, netbsd_arm64_v8)
GOOS := netbsd
GOARCH := arm64
else ifeq ($1, openbsd_amd64_v1)
GOOS := openbsd
GOARCH := amd64
else ifeq ($1, openbsd_arm_6)
GOOS := openbsd
GOARCH := arm
GOARM := 6
else ifeq ($1, openbsd_arm64_v8)
GOOS := openbsd
GOARCH := arm64
else ifeq ($1, windows_amd64_v1)
GOOS := windows
GOARCH := amd64
else ifeq ($1, windows_arm64_v8)
GOOS := windows
GOARCH := arm64
endif
endef

.PHONY: build build-target build-all test integration release plugin-image push clean ci-targets

build: | dist
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY) ./cmd/$(BINARY)

build-target: bin/$(BINARY)_$(TARGET)

build-all: $(BINARIES)

bin dist:
	@mkdir -p $@

bin/$(BINARY)_%: | bin
	$(eval $(call set_vars,$*))
	@echo "building $@ ($(GOOS)/$(GOARCH) GOARM=$(GOARM))"
	@test -n "$(GOOS)" && test -n "$(GOARCH)"
	GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) CGO_ENABLED=0 \
		go build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/$(BINARY)

test:
	go vet ./...
	go vet -tags integration ./integration/
	go test -race -count=1 ./...

integration:
	scripts/integration.sh

ci-targets:
	@python3 -c 'import json; print("targets=" + json.dumps("$(TARGETS)".split()))'

dist/%.tar.gz: bin/% | dist
	@echo "archiving $@"
	@tar cfz $@ LICENSE -C bin $*

dist/%.zip: bin/% | dist
	@echo "archiving $@"
	@zip -qj $@ LICENSE $^

dist/checksums.txt: $(BINARIES) $(ARCHIVES) | dist
	@echo "creating checksums $@"
	@{ \
		cd bin && sha256sum $(notdir $(BINARIES)); \
		cd ../dist && sha256sum $(notdir $(ARCHIVES)); \
	} | LC_ALL=C sort -k2 > $@

dist/%.sig: dist/%
	@echo "signing $@"
	@gpg --detach-sign --pinentry-mode loopback --passphrase "$$GPG_PASSWORD" --batch --output $@ $<

dist/%.spdx.sbom.json: dist/%
	@echo "creating SBOM $@"
	@syft scan $< -q -o cyclonedx-json=$@

release: dist/checksums.txt $(SIGNATURES) $(SBOMS)
	@echo "release assets in dist/"

plugin-image: Containerfile $(BINARIES)
	buildah manifest rm $(IMAGE):$(VERSION) || true
	buildah manifest create $(IMAGE):$(VERSION)
	$(foreach target,$(TARGETS),buildah build -f Containerfile --platform $(subst _,/,$(target)) --build-arg TARGET=$(target) --build-arg SOURCE=$(SOURCE) -t $(IMAGE):$(VERSION)_$(target) . &&) true
	$(foreach target,$(TARGETS),buildah manifest add $(IMAGE):$(VERSION) $(IMAGE):$(VERSION)_$(target) &&) true

push: plugin-image | dist
	buildah manifest push --all --digestfile dist/image-digest.txt $(IMAGE):$(VERSION) docker://$(IMAGE):$(VERSION)
	@cat dist/image-digest.txt

clean:
	rm -rf bin dist integration/.state
