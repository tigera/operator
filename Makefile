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
test: fmt vet ut

# Both native and cross architecture builds are supported.
# The target architecture is select by setting the ARCH variable.
# When ARCH is undefined it is set to the detected host architecture.
# When ARCH differs from the host architecture a crossbuild will be performed.
ARCHES ?= $(patsubst build/Dockerfile.%,%,$(wildcard build/Dockerfile.*))

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

# Required to prevent `FROM SCRATCH` from pulling an amd64 image in the build phase.
ifeq ($(ARCH),arm64)
	TARGET_PLATFORM=arm64/v8
endif
ifeq ($(ARCH),ppc64le)
	TARGET_PLATFORM=ppc64le
endif
ifeq ($(ARCH),amd64)
	TARGET_PLATFORM=amd64
endif
EXTRA_DOCKER_ARGS += --platform=linux/$(TARGET_PLATFORM)

# location of docker credentials to push manifests
DOCKER_CONFIG ?= $(HOME)/.docker/config.json

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

# We need CGO to leverage Boring SSL.  However, the cross-compile doesn't support CGO yet.
ifeq ($(ARCH), $(filter $(ARCH),amd64))
CGO_ENABLED=1
else
CGO_ENABLED=0
endif

###############################################################################

PACKAGE_NAME?=github.com/tigera/operator
LOCAL_USER_ID?=$(shell id -u $$USER)
GO_BUILD_VER?=v0.65.2
CALICO_BUILD?=calico/go-build:$(GO_BUILD_VER)-$(ARCH)
SRC_FILES=$(shell find ./pkg -name '*.go')
SRC_FILES+=$(shell find ./api -name '*.go')
SRC_FILES+=$(shell find ./controllers -name '*.go')
SRC_FILES+=main.go

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
		$(EXTRA_DOCKER_ARGS)

BUILD_IMAGE?=tigera/operator
BUILD_INIT_IMAGE?=tigera/operator-init

BINDIR?=build/_output/bin

IMAGE_REGISTRY?=quay.io
PUSH_IMAGE_PREFIXES?=quay.io/
RELEASE_PREFIXES?=
# If this is a release, also tag and push additional images.
ifeq ($(RELEASE),true)
PUSH_IMAGE_PREFIXES+=$(RELEASE_PREFIXES)
endif

# remove from the list to push to manifest any registries that do not support multi-arch
EXCLUDE_MANIFEST_REGISTRIES?=""
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

## push all arches
push-all: imagetag $(addprefix sub-push-,$(ARCHES))
sub-push-%:
	$(MAKE) push ARCH=$* IMAGETAG=$(IMAGETAG)

push-manifests: imagetag  $(addprefix sub-manifest-,$(call escapefs,$(PUSH_MANIFEST_IMAGE_PREFIXES)))
sub-manifest-%:
	# Docker login to hub.docker.com required before running this target as we are using $(DOCKER_CONFIG) holds the docker login credentials
	# path to credentials based on manifest-tool's requirements here https://github.com/estesp/manifest-tool#sample-usage
	docker run -t --entrypoint /bin/sh -v $(DOCKER_CONFIG):/root/.docker/config.json $(CALICO_BUILD) -c "/usr/bin/manifest-tool push from-args --platforms $(call join_platforms,$(VALIDARCHES)) --template $(call unescapefs,$*$(BUILD_IMAGE):$(IMAGETAG))-ARCH --target $(call unescapefs,$*$(BUILD_IMAGE):$(IMAGETAG))"

## push default amd64 arch where multi-arch manifest is not supported
push-non-manifests: imagetag $(addprefix sub-non-manifest-,$(call escapefs,$(PUSH_NONMANIFEST_IMAGE_PREFIXES)))
sub-non-manifest-%:
ifeq ($(ARCH),amd64)
	docker push $(call unescapefs,$*$(BUILD_IMAGE):$(IMAGETAG))
else
	$(NOECHO) $(NOOP)
endif

## tag images of one arch
tag-images: imagetag $(addprefix sub-single-tag-images-arch-,$(call escapefs,$(PUSH_IMAGE_PREFIXES))) $(addprefix sub-single-tag-images-non-manifest-,$(call escapefs,$(PUSH_NONMANIFEST_IMAGE_PREFIXES)))
sub-single-tag-images-arch-%:
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(call unescapefs,$*$(BUILD_IMAGE):$(IMAGETAG)-$(ARCH))

# because some still do not support multi-arch manifest
sub-single-tag-images-non-manifest-%:
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(call unescapefs,$*$(BUILD_IMAGE):$(IMAGETAG))
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
  GIT_VERSION?=$(shell git describe --tags --dirty --always --abbrev=12)-dev-build
else
  GIT_VERSION?=$(shell git describe --tags --dirty --always --abbrev=12)
endif

build: fmt vet $(BINDIR)/operator-$(ARCH)
$(BINDIR)/operator-$(ARCH): $(SRC_FILES)
	mkdir -p $(BINDIR)
	$(CONTAINERIZED) -e CGO_ENABLED=$(CGO_ENABLED) $(CALICO_BUILD) \
	sh -c '$(GIT_CONFIG_SSH) \
	go build -v -i -o $(BINDIR)/operator-$(ARCH) -ldflags "-X $(PACKAGE_NAME)/version.VERSION=$(GIT_VERSION) -w" ./main.go'

.PHONY: image
image: build $(BUILD_IMAGE)

$(BUILD_IMAGE): $(BUILD_IMAGE)-$(ARCH)
$(BUILD_IMAGE)-$(ARCH): register $(BINDIR)/operator-$(ARCH)
	docker build --pull -t $(BUILD_IMAGE):latest-$(ARCH) --platform=linux/$(TARGET_PLATFORM) --build-arg GIT_VERSION=$(GIT_VERSION) -f ./build/Dockerfile.$(ARCH) .
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(BUILD_IMAGE):latest
endif

.PHONY: images
images: register image

# Build the images for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) images ARCH=$*

.PHONY: image-init
image-init: image
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(BUILD_INIT_IMAGE):latest
endif

BINDIR?=build/init/bin
$(BINDIR)/kubectl:
	mkdir -p $(BINDIR)
	curl -L https://storage.googleapis.com/kubernetes-release/release/v1.22.0/bin/linux/$(ARCH)/kubectl -o $@
	chmod +x $@

kubectl: $(BINDIR)/kubectl

$(BINDIR)/kind:
	$(CONTAINERIZED) $(CALICO_BUILD) sh -c "GOBIN=/go/src/$(PACKAGE_NAME)/$(BINDIR) go install sigs.k8s.io/kind"

clean:
	rm -rf build/_output
	rm -rf build/init/bin
	rm -rf hack/bin
	rm -rf .go-pkg-cache
	rm -rf .crds
	rm -f *-release-notes.md
	docker rmi -f $(shell docker images -f "reference=$(BUILD_IMAGE):latest*" -q) > /dev/null 2>&1 || true

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
	$(CONTAINERIZED) $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
	ginkgo -r --skipPackage ./vendor -focus="$(GINKGO_FOCUS)" $(GINKGO_ARGS) "$(WHAT)"'

## Create a local kind dual stack cluster.
KUBECONFIG?=./kubeconfig.yaml
K8S_VERSION?=v1.21.2
cluster-create: $(BINDIR)/kubectl $(BINDIR)/kind
	# First make sure any previous cluster is deleted
	make cluster-destroy

	# Create a kind cluster.
	$(BINDIR)/kind create cluster \
	        --config ./deploy/kind-config.yaml \
	        --kubeconfig $(KUBECONFIG) \
	        --image kindest/node:$(K8S_VERSION)

	./deploy/scripts/ipv6_kind_cluster_update.sh
	# Deploy resources needed in test env.
	$(MAKE) deploy-crds

	# Wait for controller manager to be running and healthy.
	while ! KUBECONFIG=$(KUBECONFIG) $(BINDIR)/kubectl get serviceaccount default; do echo "Waiting for default serviceaccount to be created..."; sleep 2; done

## Deploy CRDs needed for UTs.  CRDs needed by ECK that we don't use are not deployed.
## kubectl create is used for prometheus as a workaround for https://github.com/prometheus-community/helm-charts/issues/1500
deploy-crds: kubectl
	@export KUBECONFIG=$(KUBECONFIG) && \
		$(BINDIR)/kubectl apply -f pkg/crds/operator/ && \
		$(BINDIR)/kubectl apply -f pkg/crds/calico/ && \
		$(BINDIR)/kubectl apply -f pkg/crds/enterprise/ && \
		$(BINDIR)/kubectl apply -f deploy/crds/elastic/elasticsearch-crd.yaml && \
		$(BINDIR)/kubectl apply -f deploy/crds/elastic/kibana-crd.yaml && \
		$(BINDIR)/kubectl create -f deploy/crds/prometheus

create-tigera-operator-namespace: kubectl
	KUBECONFIG=$(KUBECONFIG) $(BINDIR)/kubectl create ns tigera-operator

## Destroy local kind cluster
cluster-destroy: $(BINDIR)/kubectl $(BINDIR)/kind
	-$(BINDIR)/kind delete cluster
	rm -f $(KUBECONFIG)



###############################################################################
# Static checks
###############################################################################
.PHONY: static-checks
## Perform static checks on the code.
static-checks: check-boring-ssl
	$(CONTAINERIZED) $(CALICO_BUILD) golangci-lint run --deadline 5m

check-boring-ssl: $(BINDIR)/operator-amd64
	$(CONTAINERIZED) -e CGO_ENABLED=$(CGO_ENABLED) $(CALICO_BUILD) \
		go tool nm $(BINDIR)/operator-amd64 > $(BINDIR)/tags.txt && grep '_Cfunc__goboringcrypto_' $(BINDIR)/tags.txt 1> /dev/null
	-rm -f $(BINDIR)/tags.txt

.PHONY: fix
## Fix static checks
fix:
	$(CONTAINERIZED) $(CALICO_BUILD) \
	sh -c '$(GIT_CONFIG_SSH) \
	goimports -w $(SRC_FILES)'

.PHONY: format-check
format-check:
	@$(CONTAINERIZED) $(CALICO_BUILD) \
	sh -c '$(GIT_CONFIG_SSH) \
	files=$$(gofmt -l ./pkg ./controllers ./api ./test); \
	[ "$$files" = "" ] && exit 0; \
	echo The following files need a format update:; \
	echo $$files; \
	echo Try running \"make fix\" and committing any changes; \
	exit 1'

.PHONY: dirty-check
dirty-check:
	@if [ "$$(git diff --stat)" != "" ]; then \
	echo "The following files are dirty"; git diff --stat; exit 1; fi
	@# Check that no new CRDs needed to be committed
	@if [ "$$(git status --porcelain pkg/crds)" != "" ]; then \
	echo "The following CRD files need to be added"; git status --porcelain pkg/crds; exit 1; fi

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
ci: clean format-check validate-gen-versions static-checks image-all test dirty-check test-crds

validate-gen-versions:
	make gen-versions
	make dirty-check

## Deploys images to registry
cd:
ifndef CONFIRM
	$(error CONFIRM is undefined - run using make <target> CONFIRM=true)
endif
ifndef BRANCH_NAME
	$(error BRANCH_NAME is undefined - run using make <target> BRANCH_NAME=var or set an environment variable)
endif
	$(MAKE) tag-images-all push-all push-manifests push-non-manifests IMAGETAG=${BRANCH_NAME} EXCLUDEARCH="$(EXCLUDEARCH)"
	$(MAKE) tag-images-all push-all push-manifests push-non-manifests IMAGETAG=$(shell git describe --tags --dirty --always --long --abbrev=12) EXCLUDEARCH="$(EXCLUDEARCH)"

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
	if ! docker run $(IMAGE_REGISTRY)/$(BUILD_IMAGE):$(VERSION)-$(ARCH) --version | grep '^Operator: $(VERSION)$$'; then echo "Reported version:" `docker run $(IMAGE_REGISTRY)/$(BUILD_IMAGE):$(VERSION)-$(ARCH) --version ` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

release-check-image-exists: release-prereqs
	@echo "Checking if $(IMAGE_REGISTRY)/$(BUILD_IMAGE):$(VERSION) exists already"; \
	if docker manifest inspect $(IMAGE_REGISTRY)/$(BUILD_IMAGE):$(VERSION) >/dev/null; \
		then echo "Image $(IMAGE_REGISTRY)/$(BUILD_IMAGE):$(VERSION) already exists"; \
		exit 1; \
	else \
		echo "Image tag check passed; image does not already exist"; \
	fi

release-publish-images: release-prereqs release-check-image-exists
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
OPERATOR_SDK_VERSION=v1.0.1
OPERATOR_SDK_BARE=hack/bin/operator-sdk
OPERATOR_SDK=$(OPERATOR_SDK_BARE)-$(OPERATOR_SDK_VERSION)
$(OPERATOR_SDK):
	mkdir -p hack/bin
	curl --fail -L -o $@ \
		https://github.com/operator-framework/operator-sdk/releases/download/${OPERATOR_SDK_VERSION}/operator-sdk-${OPERATOR_SDK_VERSION}-x86_64-linux-gnu
	chmod +x $@

.PHONY: $(OPERATOR_SDK_BARE)
$(OPERATOR_SDK_BARE): $(OPERATOR_SDK)
	ln -f -s operator-sdk-$(OPERATOR_SDK_VERSION) $(OPERATOR_SDK_BARE)

## Generating code after API changes.
gen-files: manifests generate

OS_VERSIONS?=config/calico_versions.yml
EE_VERSIONS?=config/enterprise_versions.yml
COMMON_VERSIONS?=config/common_versions.yml

.PHONY: gen-versions gen-versions-calico gen-versions-enterprise gen-versions-common

gen-versions: gen-versions-calico gen-versions-enterprise gen-versions-common

gen-versions-calico: $(BINDIR)/gen-versions update-calico-crds
	$(BINDIR)/gen-versions -os-versions=$(OS_VERSIONS) > pkg/components/calico.go

gen-versions-enterprise: $(BINDIR)/gen-versions update-enterprise-crds
	$(BINDIR)/gen-versions -ee-versions=$(EE_VERSIONS) > pkg/components/enterprise.go

gen-versions-common: $(BINDIR)/gen-versions
	$(BINDIR)/gen-versions -common-versions=$(COMMON_VERSIONS) > pkg/components/common.go

$(BINDIR)/gen-versions: $(shell find ./hack/gen-versions -type f)
	mkdir -p $(BINDIR)
	$(CONTAINERIZED) $(CALICO_BUILD) \
	sh -c '$(GIT_CONFIG_SSH) \
	go build -o $(BINDIR)/gen-versions ./hack/gen-versions'

# $(1) is the github project
# $(2) is the branch or tag to fetch
# $(3) is the directory name to use
define prep_local_crds
    $(eval dir := $(1))
	rm -rf pkg/crds/$(dir)
	rm -rf .crds/$(dir)
	mkdir -p pkg/crds/$(dir)
	mkdir -p .crds/$(dir)
endef
define fetch_crds
    $(eval project := $(1))
    $(eval branch := $(2))
    $(eval dir := $(3))
	@echo "Fetching $(dir) CRDs from $(project) branch $(branch)"
	git -C .crds/$(dir) clone --depth 1 --branch $(branch) --single-branch git@github.com:$(project).git ./
endef
define copy_crds
    $(eval dir := $(1))
	@cp .crds/$(dir)/libcalico-go/config/crd/* pkg/crds/$(dir)/ && echo "Copied $(dir) CRDs"
endef

.PHONY: read-libcalico-version read-libcalico-enterprise-version
.PHONY: update-calico-crds update-enterprise-crds
.PHONY: fetch-calico-crds fetch-enterprise-crds
.PHONY: prepare-for-calico-crds prepare-for-enterprise-crds

CALICO?=projectcalico/calico
read-libcalico-calico-version:
	$(eval CALICO_BRANCH := $(shell $(CONTAINERIZED) $(CALICO_BUILD) \
	bash -c '$(GIT_CONFIG_SSH) \
	yq r config/calico_versions.yml components.libcalico-go.version'))
	if [ -z "$(CALICO_BRANCH)" ]; then echo "libcalico branch not defined"; exit 1; fi

update-calico-crds: fetch-calico-crds
	$(call copy_crds,"calico")

prepare-for-calico-crds:
	$(call prep_local_crds,"calico")

fetch-calico-crds: prepare-for-calico-crds read-libcalico-calico-version
	$(call fetch_crds,$(CALICO),$(CALICO_BRANCH),"calico")

CALICO_ENTERPRISE?=tigera/calico-private
read-libcalico-enterprise-version:
	$(eval CALICO_ENTERPRISE_BRANCH := $(shell $(CONTAINERIZED) $(CALICO_BUILD) \
	bash -c '$(GIT_CONFIG_SSH) \
	yq r config/enterprise_versions.yml components.libcalico-go.version'))
	if [ -z "$(CALICO_ENTERPRISE_BRANCH)" ]; then echo "libcalico enterprise branch not defined"; exit 1; fi

update-enterprise-crds: fetch-enterprise-crds
	$(call copy_crds,"enterprise")

prepare-for-enterprise-crds:
	$(call prep_local_crds,"enterprise")

fetch-enterprise-crds: prepare-for-enterprise-crds  read-libcalico-enterprise-version
	$(call fetch_crds,$(CALICO_ENTERPRISE),$(CALICO_ENTERPRISE_BRANCH),"enterprise")

.PHONY: prepull-image
prepull-image:
	@echo Pulling operator image...
	docker pull $(IMAGE_REGISTRY)/$(BUILD_IMAGE):v$(VERSION)

# Get the digest for the image. This target runs docker commands on the host since the
# build container doesn't have docker-in-docker. 'docker inspect' returns output like the example
# below. RepoDigests may have more than one entry so we need to filter.
# [
#     {
#         "Id": "sha256:34a1114040c03830da0a8d57f8d999deba26d8e31bda353aed201a375f68870b",
#         "RepoTags": [
#             "quay.io/tigera/operator:v1.3.1",
#             "..."
#         ],
#         "RepoDigests": [
#             "quay.io/tigera/operator@sha256:5e1d551b5a711592472f4a3cc4645698d5f826da4253f0d47cfa5d5b641a2e1a",
#             "..."
#         ],
#         ...
#     }
# ]
.PHONY: get-digest
get-digest: prepull-image
	@echo Getting operator image digest...
	$(eval OPERATOR_IMAGE_INSPECT=$(shell sh -c "docker image inspect $(IMAGE_REGISTRY)/$(BUILD_IMAGE):v$(VERSION) | base64 -w 0"))

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
#####################################
#####################################
# Image URL to use all building/pushing image targets
IMG ?= controller:latest
# Produce CRDs that work back to Kubernetes 1.11 (no version conversion)
CRD_OPTIONS ?= "crd:crdVersions=v1,trivialVersions=true"

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet manifests
	go run ./main.go

# Install CRDs into a cluster
install: manifests kustomize
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

# Uninstall CRDs from a cluster
uninstall: manifests kustomize
	$(KUSTOMIZE) build config/crd | kubectl delete -f -

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy: manifests kustomize
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | kubectl apply -f -

# Generate manifests e.g. CRD
# Can also generate RBAC and webhooks but that is not enabled currently
manifests: controller-gen
	$(CONTROLLER_GEN) $(CRD_OPTIONS) paths="./api/..." output:crd:artifacts:config=config/crd/bases
	for x in $$(find config/crd/bases/*); do sed -i -e '/creationTimestamp: null/d' $$x; done

# Run go fmt against code
fmt:
	$(CONTAINERIZED) $(CALICO_BUILD) \
	sh -c '$(GIT_CONFIG_SSH) \
	go fmt ./...'

# Run go vet against code
vet:
	$(CONTAINERIZED) $(CALICO_BUILD) \
	sh -c '$(GIT_CONFIG_SSH) \
	go vet ./...'

# Generate code
generate: $(BINDIR)/controller-gen
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

GO_GET_CONTAINER=docker run --rm \
		-v $(CURDIR)/$(BINDIR):/go/bin:rw \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-e GOPATH=/go \
		--net=host \
		$(EXTRA_DOCKER_ARGS) \
		$(CALICO_BUILD)

# download controller-gen if necessary
CONTROLLER_GEN=$(BINDIR)/controller-gen
controller-gen: $(BINDIR)/controller-gen
$(BINDIR)/controller-gen:
	mkdir -p $(BINDIR)
	$(GO_GET_CONTAINER) \
		sh -c '$(GIT_CONFIG_SSH) \
		set -e ;\
		CONTROLLER_GEN_TMP_DIR=$$(mktemp -d) ;\
		cd $$CONTROLLER_GEN_TMP_DIR ;\
		go mod init tmp ;\
		go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.3.0'

KUSTOMIZE=$(BINDIR)/kustomize
# download kustomize if necessary
$(BINDIR)/kustomize:
	mkdir -p $(BINDIR)
	$(GO_GET_CONTAINER) \
		sh -c '$(GIT_CONFIG_SSH) \
		set -e ;\
		CONTROLLER_GEN_TMP_DIR=$$(mktemp -d) ;\
		cd $$CONTROLLER_GEN_TMP_DIR ;\
		go mod init tmp ;\
		go get sigs.k8s.io/kustomize/kustomize/v3@v3.5.4 '


# Options for 'bundle-build'
ifneq ($(origin CHANNELS), undefined)
BUNDLE_CHANNELS := --channels=$(CHANNELS)
endif
ifneq ($(origin DEFAULT_CHANNEL), undefined)
BUNDLE_DEFAULT_CHANNEL := --default-channel=$(DEFAULT_CHANNEL)
endif
BUNDLE_METADATA_OPTS ?= $(BUNDLE_CHANNELS) $(BUNDLE_DEFAULT_CHANNEL)

BUNDLE_CRD_DIR ?= build/_output/bundle/$(VERSION)/crds
BUNDLE_DEPLOY_DIR ?= build/_output/bundle/$(VERSION)/deploy

## Create an operator bundle image.
# E.g., make bundle VERSION=1.13.1 PREV_VERSION=1.13.0 CHANNELS=release-v1.13 DEFAULT_CHANNEL=release-v1.13
.PHONY: bundle
bundle: bundle-generate bundle-crd-clean update-bundle bundle-validate bundle-image

.PHONY: bundle-crd-clean
bundle-crd-clean:
	git checkout -- config/crd/bases

.PHONY: bundle-validate
bundle-validate:
	$(OPERATOR_SDK_BARE) bundle validate bundle/$(VERSION)

.PHONY: bundle-manifests
bundle-manifests:
ifndef VERSION
	$(error VERSION is undefined - run using make $@ VERSION=X.Y.Z PREV_VERSION=D.E.F)
endif
ifndef PREV_VERSION
	$(error PREV_VERSION is undefined - run using make $@ VERSION=X.Y.Z PREV_VERSION=D.E.F)
endif
	$(eval EXTRA_DOCKER_ARGS += -e BUNDLE_CRD_DIR=$(BUNDLE_CRD_DIR) -e BUNDLE_DEPLOY_DIR=$(BUNDLE_DEPLOY_DIR))
	$(CONTAINERIZED) $(CALICO_BUILD) "hack/gen-bundle/get-manifests.sh"

.PHONY: bundle-generate
bundle-generate: manifests $(KUSTOMIZE) $(OPERATOR_SDK_BARE) bundle-manifests
	$(KUSTOMIZE) build config/manifests \
	| $(OPERATOR_SDK_BARE) generate bundle \
		--crds-dir $(BUNDLE_CRD_DIR) \
		--deploy-dir $(BUNDLE_DEPLOY_DIR) \
		--version $(VERSION) \
		--verbose \
		--manifests \
		--metadata $(BUNDLE_METADATA_OPTS)

# Update a generated bundle so that it can be certified.
.PHONY: update-bundle
update-bundle: $(OPERATOR_SDK_BARE) get-digest
	$(eval EXTRA_DOCKER_ARGS += -e OPERATOR_IMAGE_INSPECT="$(OPERATOR_IMAGE_INSPECT)" -e VERSION=$(VERSION) -e PREV_VERSION=$(PREV_VERSION))
	$(CONTAINERIZED) $(CALICO_BUILD) hack/gen-bundle/update-bundle.sh

# Build the bundle image.
.PHONY: bundle-build
bundle-image:
ifndef VERSION
	$(error VERSION is undefined - run using make $@ VERSION=X.Y.Z)
endif
	docker build -f bundle/bundle-v$(VERSION).Dockerfile -t tigera-operator-bundle:$(VERSION) bundle/


.PHONY: test-crds
test-crds: test-enterprise-crds test-calico-crds

# TODO: Improve this testing by comparing the individual source files
# with the yaml printed out, this will need to be a yaml diff since the
# fields won't necessarily be in the same order or indentation.
test-calico-crds: $(BINDIR)/operator-$(ARCH)
	$(BINDIR)/operator-$(ARCH) --print-calico-crds all >/dev/null 2>&1

# TODO: Improve this testing by comparing the individual source files
# with the yaml printed out, this will need to be a yaml diff since the
# fields won't necessarily be in the same order or indentation.
test-enterprise-crds: $(BINDIR)/operator-$(ARCH)
	$(BINDIR)/operator-$(ARCH) --print-enterprise-crds all >/dev/null 2>&1

# Always install the git hooks to prevent potentially problematic commits.
hooks_installed:=$(shell ./install-git-hooks)

.PHONY: install-git-hooks
install-git-hooks:
	./install-git-hooks

.PHONY: pre-commit
pre-commit:
	$(CONTAINERIZED) $(CALICO_BUILD) git-hooks/pre-commit-in-container
