# Copyright (c) 2019 Tigera, Inc. All rights reserved.

# This Makefile requires the following dependencies on the host system:
# - go
#
# TODO: Add in the necessary variables, etc, to make this Makefile work.
# TODO: Add in multi-arch stuff.


# Shortcut targets
default: build

## Build binary for current platform
all: build

## Run the tests for the current platform/architecture
test: ut

# Both native and cross architecture builds are supported.
# The target architecture is select by setting the ARCH variable.
# When ARCH is undefined it is set to the detected host architecture.
# When ARCH differs from the host architecture a crossbuild will be performed.
ARCHES=$(patsubst build/Dockerfile.%,%,$(wildcard build/Dockerfile.*))

# BUILDARCH is the host architecture
# ARCH is the target architecture
# we need to keep track of them separately
BUILDARCH ?= $(shell uname -m)
BUILDOS ?= $(shell uname -s | tr A-Z a-z)

# canonicalized names for host architecture
ifeq ($(BUILDARCH),aarch64)
        BUILDARCH=arm64
endif
ifeq ($(BUILDARCH),x86_64)
        BUILDARCH=amd64
endif

# unless otherwise set, I am building for my own architecture, i.e. not cross-compiling
ARCH ?= $(BUILDARCH)

# canonicalized names for target architecture
ifeq ($(ARCH),aarch64)
        override ARCH=arm64
endif
ifeq ($(ARCH),x86_64)
    override ARCH=amd64
endif

# we want to be able to run the same recipe on multiple targets keyed on the image name
# to do that, we would use the entire image name, e.g. calico/node:abcdefg, as the stem, or '%', in the target
# however, make does **not** allow the usage of invalid filename characters - like / and : - in a stem, and thus errors out
# to get around that, we "escape" those characters by converting all : to --- and all / to ___ , so that we can use them
# in the target, we then unescape them back
escapefs = $(subst :,---,$(subst /,___,$(1)))
unescapefs = $(subst ---,:,$(subst ___,/,$(1)))

# these macros create a list of valid architectures for pushing manifests
space :=
space +=
comma := ,
prefix_linux = $(addprefix linux/,$(strip $1))
join_platforms = $(subst $(space),$(comma),$(call prefix_linux,$(strip $1)))

# Targets used when cross building.
.PHONY: register
# Enable binfmt adding support for miscellaneous binary formats.
# This is only needed when running non-native binaries.
register:
ifneq ($(BUILDARCH),$(ARCH))
	docker run --rm --privileged multiarch/qemu-user-static:register || true
endif

# list of arches *not* to build when doing *-all
#    until s390x works correctly
EXCLUDEARCH ?= s390x
VALIDARCHES = $(filter-out $(EXCLUDEARCH),$(ARCHES))

###############################################################################

PACKAGE_NAME?=github.com/tigera/operator
LOCAL_USER_ID?=$(shell id -u $$USER)
GO_BUILD_VER?=v0.40
CALICO_BUILD?=calico/go-build:$(GO_BUILD_VER)
SRC_FILES=$(shell find ./pkg -name '*.go')
SRC_FILES+=$(shell find ./cmd -name '*.go')

EXTRA_DOCKER_ARGS += -e GO111MODULE=on -e GOPRIVATE=github.com/tigera/*
ifeq ($(GIT_USE_SSH),true)
	GIT_CONFIG_SSH ?= git config --global url."ssh://git@github.com/".insteadOf "https://github.com/";
endif

ifdef SSH_AUTH_SOCK
  EXTRA_DOCKER_ARGS += -v $(SSH_AUTH_SOCK):/ssh-agent --env SSH_AUTH_SOCK=/ssh-agent
endif

ifneq ($(GOPATH),)
	# If the environment is using multiple comma-separated directories for gopath, use the first one, as that
	# is the default one used by go modules.
	GOMOD_CACHE = $(shell echo $(GOPATH) | cut -d':' -f1)/pkg/mod
else
	# If gopath is empty, default to $(HOME)/go.
	GOMOD_CACHE = $(HOME)/go/pkg/mod
endif

EXTRA_DOCKER_ARGS += -v $(GOMOD_CACHE):/go/pkg/mod:rw

CONTAINERIZED= mkdir -p .go-pkg-cache $(GOMOD_CACHE) && \
	docker run --rm \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
		-v $(CURDIR)/.go-pkg-cache:/go-cache/:rw \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-e GOPATH=/go \
		-e GOCACHE=/go-cache \
		-e KUBECONFIG=/go/src/$(PACKAGE_NAME)/kubeconfig.yaml \
		-w /go/src/$(PACKAGE_NAME) \
		--net=host \
		$(EXTRA_DOCKER_ARGS) \
		$(CALICO_BUILD)

BUILD_IMAGE?=tigera/operator
BUILD_INIT_IMAGE?=tigera/operator-init

BINDIR?=build/_output/bin

PUSH_IMAGE_PREFIXES?=quay.io/
RELEASE_PREFIXES?=
# If this is a release, also tag and push additional images.
ifeq ($(RELEASE),true)
PUSH_IMAGE_PREFIXES+=$(RELEASE_PREFIXES)
endif

# remove from the list to push to manifest any registries that do not support multi-arch
EXCLUDE_MANIFEST_REGISTRIES?=quay.io/
PUSH_MANIFEST_IMAGE_PREFIXES=$(PUSH_IMAGE_PREFIXES:$(EXCLUDE_MANIFEST_REGISTRIES)%=)
PUSH_NONMANIFEST_IMAGE_PREFIXES=$(filter-out $(PUSH_MANIFEST_IMAGE_PREFIXES),$(PUSH_IMAGE_PREFIXES))


imagetag:
ifndef IMAGETAG
	$(error IMAGETAG is undefined - run using make <target> IMAGETAG=X.Y.Z)
endif

## push one arch
push: imagetag $(addprefix sub-single-push-,$(call escapefs,$(PUSH_IMAGE_PREFIXES)))

sub-single-push-%:
	docker push $(call unescapefs,$*$(BUILD_IMAGE):$(IMAGETAG)-$(ARCH))
	docker push $(call unescapefs,$*$(BUILD_INIT_IMAGE):$(IMAGETAG)-$(ARCH))

## push all arches
push-all: imagetag $(addprefix sub-push-,$(ARCHES))
sub-push-%:
	$(MAKE) push ARCH=$* IMAGETAG=$(IMAGETAG)

push-manifests: imagetag  $(addprefix sub-manifest-,$(call escapefs,$(PUSH_MANIFEST_IMAGE_PREFIXES)))
sub-manifest-%:
	# Docker login to hub.docker.com required before running this target as we are using $(DOCKER_CONFIG) holds the docker login credentials
	# path to credentials based on manifest-tool's requirements here https://github.com/estesp/manifest-tool#sample-usage
	docker run -t --entrypoint /bin/sh -v $(DOCKER_CONFIG):/root/.docker/config.json $(CALICO_BUILD) -c "/usr/bin/manifest-tool push from-args --platforms $(call join_platforms,$(VALIDARCHES)) --template $(call unescapefs,$*$(BUILD_IMAGE):$(IMAGETAG))-ARCH --target $(call unescapefs,$*$(BUILD_IMAGE):$(IMAGETAG))"
	docker run -t --entrypoint /bin/sh -v $(DOCKER_CONFIG):/root/.docker/config.json $(CALICO_BUILD) -c "/usr/bin/manifest-tool push from-args --platforms $(call join_platforms,$(VALIDARCHES)) --template $(call unescapefs,$*$(BUILD_INIT_IMAGE):$(IMAGETAG))-ARCH --target $(call unescapefs,$*$(BUILD_INIT_IMAGE):$(IMAGETAG))"

## push default amd64 arch where multi-arch manifest is not supported
push-non-manifests: imagetag $(addprefix sub-non-manifest-,$(call escapefs,$(PUSH_NONMANIFEST_IMAGE_PREFIXES)))
sub-non-manifest-%:
ifeq ($(ARCH),amd64)
	docker push $(call unescapefs,$*$(BUILD_IMAGE):$(IMAGETAG))
	docker push $(call unescapefs,$*$(BUILD_INIT_IMAGE):$(IMAGETAG))
else
	$(NOECHO) $(NOOP)
endif

## tag images of one arch
tag-images: imagetag $(addprefix sub-single-tag-images-arch-,$(call escapefs,$(PUSH_IMAGE_PREFIXES))) $(addprefix sub-single-tag-images-non-manifest-,$(call escapefs,$(PUSH_NONMANIFEST_IMAGE_PREFIXES)))
sub-single-tag-images-arch-%:
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(call unescapefs,$*$(BUILD_IMAGE):$(IMAGETAG)-$(ARCH))
	docker tag $(BUILD_INIT_IMAGE):latest-$(ARCH) $(call unescapefs,$*$(BUILD_INIT_IMAGE):$(IMAGETAG)-$(ARCH))

# because some still do not support multi-arch manifest
sub-single-tag-images-non-manifest-%:
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(call unescapefs,$*$(BUILD_IMAGE):$(IMAGETAG))
	docker tag $(BUILD_INIT_IMAGE):latest-$(ARCH) $(call unescapefs,$*$(BUILD_INIT_IMAGE):$(IMAGETAG))
else
	$(NOECHO) $(NOOP)
endif

## tag images of all archs
tag-images-all: imagetag $(addprefix sub-tag-images-,$(VALIDARCHES))
sub-tag-images-%:
	$(MAKE) tag-images ARCH=$* IMAGETAG=$(IMAGETAG)

###############################################################################
# Building the code
###############################################################################
.PHONY: build

# Get version from git.
ifeq ($(LOCAL_BUILD),true)
  GIT_VERSION?=$(shell git describe --tags --dirty --always)-dev-build
else
  GIT_VERSION?=$(shell git describe --tags --dirty --always)
endif

build: $(BINDIR)/operator-$(ARCH)
$(BINDIR)/operator-$(ARCH): $(SRC_FILES)
	mkdir -p $(BINDIR)
	$(CONTAINERIZED) \
	sh -c '$(GIT_CONFIG_SSH) \
	go build -v -i -o $(BINDIR)/operator-$(ARCH) -ldflags "-X github.com/tigera/operator/version.VERSION=$(GIT_VERSION) -s -w" ./cmd/manager/main.go'

.PHONY: image
image: build $(BUILD_IMAGE)
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

$(BUILD_IMAGE): $(BUILD_IMAGE)-$(ARCH)
$(BUILD_IMAGE)-$(ARCH): $(BINDIR)/operator-$(ARCH)
	docker build --pull -t $(BUILD_IMAGE):latest-$(ARCH) --build-arg GIT_VERSION=$(GIT_VERSION) -f ./build/Dockerfile.$(ARCH) .
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(BUILD_IMAGE):latest
endif

build/init/bin/kubectl:
	mkdir -p build/init/bin
	curl -o build/init/bin/kubectl https://storage.googleapis.com/kubernetes-release/release/v1.14.0/bin/linux/amd64/kubectl

.PHONY: image-init
image-init: build/init/bin/kubectl $(BUILD_INIT_IMAGE)
$(BUILD_INIT_IMAGE): $(BUILD_INIT_IMAGE)-$(ARCH)
$(BUILD_INIT_IMAGE)-$(ARCH):
	docker build --pull -t $(BUILD_INIT_IMAGE):latest-$(ARCH) --build-arg GIT_VERSION=$(GIT_VERSION) -f ./build/init/Dockerfile.$(ARCH) .
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_INIT_IMAGE):latest-$(ARCH) $(BUILD_INIT_IMAGE):latest
endif

.PHONY: images
images: image image-init

# Build the images for the target architecture
.PHONY: images-all
images-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) images ARCH=$*

clean:
	rm -rf build/_output
	rm -rf build/init/bin
	rm -rf hack/bin
	rm -rf .go-pkg-cache
	rm -f *-release-notes.md
	docker rmi -f $(BUILD_IMAGE):latest $(BUILD_IMAGE):latest-$(ARCH)

###############################################################################
# Tests
###############################################################################
WHAT?=.
GINKGO_ARGS?= -v
GINKGO_FOCUS?=.*

## Run the full set of tests
ut: cluster-create run-uts cluster-destroy
run-uts:
	-mkdir -p .go-pkg-cache report
	$(CONTAINERIZED) sh -c '$(GIT_CONFIG_SSH) \
	ginkgo -r --skipPackage ./vendor -focus="$(GINKGO_FOCUS)" $(GINKGO_ARGS) $(WHAT)'

## Create a local kind dual stack cluster.
KUBECONFIG?=./kubeconfig.yaml
cluster-create: kubectl
	# First make sure any previous cluster is deleted
	make cluster-destroy
	./deploy/scripts/create_kind_cluster.sh
	cp ~/.kube/kind-config-kind $(KUBECONFIG)
	$(MAKE) deploy-crds
	$(MAKE) create-tigera-operator-namespace

deploy-crds: kubectl
	@export KUBECONFIG=$(KUBECONFIG) && \
		./kubectl apply -f deploy/crds/calico/ && \
		./kubectl apply -f deploy/crds/enterprise/ && \
		./kubectl apply -f deploy/crds/operator.tigera.io_managers_crd.yaml && \
		./kubectl apply -f deploy/crds/operator.tigera.io_logcollectors_crd.yaml && \
		./kubectl apply -f deploy/crds/operator.tigera.io_intrusiondetections_crd.yaml && \
		./kubectl apply -f deploy/crds/operator.tigera.io_compliances_crd.yaml && \
		./kubectl apply -f deploy/crds/operator.tigera.io_apiservers_crd.yaml && \
		./kubectl apply -f deploy/crds/operator.tigera.io_installations_crd.yaml && \
		./kubectl apply -f deploy/crds/operator.tigera.io_tigerastatuses_crd.yaml && \
		./kubectl apply -f deploy/crds/operator.tigera.io_logstorages_crd.yaml && \
		./kubectl apply -f deploy/crds/operator.tigera.io_managementclusters_crd.yaml && \
		./kubectl apply -f deploy/crds/operator.tigera.io_managementclusterconnections_crd.yaml && \
		./kubectl apply -f deploy/crds/operator.tigera.io_amazoncloudintegrations_crd.yaml && \
		./kubectl apply -f deploy/crds/operator.tigera.io_authentications_crd.yaml && \
		./kubectl apply -f deploy/crds/elastic/elasticsearch-crd.yaml && \
		./kubectl apply -f deploy/crds/elastic/kibana-crd.yaml

create-tigera-operator-namespace: kubectl
	KUBECONFIG=$(KUBECONFIG) ./kubectl create ns tigera-operator

## Destroy local kind cluster
cluster-destroy:
	./deploy/scripts/delete_kind_cluster.sh
	rm -f $(KUBECONFIG)

kubectl:
	curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.17.0/bin/linux/amd64/kubectl
	chmod +x ./kubectl


###############################################################################
# Static checks
###############################################################################
.PHONY: static-checks
## Perform static checks on the code.
static-checks:
	$(CONTAINERIZED) golangci-lint run --deadline 5m

.PHONY: fix
## Fix static checks
fix:
	goimports -w $(SRC_FILES)

foss-checks:
	@echo Running $@...
	docker run --rm \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-w /go/src/$(PACKAGE_NAME)
		-e FOSSA_API_KEY=$(FOSSA_API_KEY) \
		$(CALICO_BUILD) /usr/local/bin/fossa

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
## Run what CI runs
ci: clean images test $(BINDIR)/gen-versions validate-gen-versions

validate-gen-versions:
	./hack/gen-versions/validate.sh

## Deploys images to registry
cd:
ifndef CONFIRM
	$(error CONFIRM is undefined - run using make <target> CONFIRM=true)
endif
ifndef BRANCH_NAME
	$(error BRANCH_NAME is undefined - run using make <target> BRANCH_NAME=var or set an environment variable)
endif
	$(MAKE) tag-images-all push-all push-manifests push-non-manifests IMAGETAG=${BRANCH_NAME} EXCLUDEARCH="$(EXCLUDEARCH)"
	$(MAKE) tag-images-all push-all push-manifests push-non-manifests IMAGETAG=$(shell git describe --tags --dirty --always --long) EXCLUDEARCH="$(EXCLUDEARCH)"

###############################################################################
# Release
###############################################################################
## Determines if we are on a tag and if so builds a release.
maybe-build-release:
	./hack/maybe-build-release.sh

## Tags and builds a release from start to finish.
release: release-prereqs
ifneq ($(VERSION), $(GIT_VERSION))
	$(error Attempt to build $(VERSION) from $(GIT_VERSION))
endif
	$(MAKE) release-build
	$(MAKE) release-verify

	@echo ""
	@echo "Release build complete. Next, push the produced images."
	@echo ""
	@echo "  make VERSION=$(VERSION) release-publish"
	@echo ""

## Produces a clean build of release artifacts at the specified version.
release-build: release-prereqs clean
# Check that the correct code is checked out.
ifneq ($(VERSION), $(GIT_VERSION))
	$(error Attempt to build $(VERSION) from $(GIT_VERSION))
endif
	$(MAKE) image-all
	$(MAKE) tag-images-all RELEASE=true IMAGETAG=$(VERSION)
	# Generate the `latest` images.
	$(MAKE) tag-images-all RELEASE=true IMAGETAG=latest

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	if ! docker run quay.io/$(BUILD_IMAGE):$(VERSION)-$(ARCH) --version | grep '^Operator: $(VERSION)$$'; then echo "Reported version:" `docker run quay.io/$(BUILD_IMAGE):$(VERSION)-$(ARCH) --version ` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

release-publish-images: release-prereqs
	# Push images.
	$(MAKE) push-all push-manifests push-non-manifests RELEASE=true IMAGETAG=$(VERSION)

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs
	# Push the git tag.
	git push origin $(VERSION)

	$(MAKE) release-publish-images IMAGETAG=$(VERSION)

	@echo "Finalize the GitHub release based on the pushed tag."
	@echo ""
	@echo "  https://$(PACKAGE_NAME)/releases/tag/$(VERSION)"
	@echo ""
	@echo "If this is the latest stable release, then run the following to push 'latest' images."
	@echo ""
	@echo "  make VERSION=$(VERSION) release-publish-latest"
	@echo ""

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
ifdef LOCAL_BUILD
	$(error LOCAL_BUILD must not be set for a release)
endif

###############################################################################
# Utilities
###############################################################################
OPERATOR_SDK_VERSION=v0.18.1
hack/bin/operator-sdk-$(OPERATOR_SDK_VERSION):
	mkdir -p hack/bin
	curl --fail -L -o hack/bin/operator-sdk-$(OPERATOR_SDK_VERSION) \
		https://github.com/operator-framework/operator-sdk/releases/download/${OPERATOR_SDK_VERSION}/operator-sdk-${OPERATOR_SDK_VERSION}-x86_64-linux-gnu
	chmod +x hack/bin/operator-sdk-$(OPERATOR_SDK_VERSION)

## Generating code after API changes.
gen-files: hack/bin/operator-sdk-$(OPERATOR_SDK_VERSION)
	cp hack/bin/operator-sdk-$(OPERATOR_SDK_VERSION) hack/bin/operator-sdk
	$(CONTAINERIZED) hack/bin/operator-sdk generate crds
	# we don't need this CRD but there don't seem to be any flags to have generate
	# skip the ippools api so just remove this file until there is something better
	rm deploy/crds/crd.projectcalico.org_ippools_crd.yaml
	rm deploy/crds/crd.projectcalico.org_felixconfigurations_crd.yaml
	$(CONTAINERIZED) hack/bin/operator-sdk generate k8s

OS_VERSIONS?=config/calico_versions.yml
EE_VERSIONS?=config/enterprise_versions.yml
gen-versions: $(BINDIR)/gen-versions
	$(BINDIR)/gen-versions -os-versions=$(OS_VERSIONS) > pkg/components/calico.go
	$(BINDIR)/gen-versions -ee-versions=$(EE_VERSIONS) > pkg/components/enterprise.go

$(BINDIR)/gen-versions: $(shell find ./hack/gen-versions -type f)
	mkdir -p $(BINDIR)
	$(CONTAINERIZED) \
	sh -c '$(GIT_CONFIG_SSH) \
	go build -o $(BINDIR)/gen-versions ./hack/gen-versions'

.PHONY: help
## Display this help text
help: # Some kind of magic from https://gist.github.com/rcmachado/af3db315e31383502660
	$(info Available targets)
	@awk '/^[a-zA-Z\-\_0-9\/]+:/ {                                      \
		nb = sub( /^## /, "", helpMsg );                                \
		if(nb == 0) {                                                   \
			helpMsg = $$0;                                              \
			nb = sub( /^[^:]*:.* ## /, "", helpMsg );                   \
		}                                                               \
		if (nb)                                                         \
			printf "\033[1;31m%-" width "s\033[0m %s\n", $$1, helpMsg;  \
	}                                                                   \
	{ helpMsg = $$0 }'                                                  \
	width=20                                                            \
	$(MAKEFILE_LIST)
