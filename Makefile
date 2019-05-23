# Copyright (c) 2019 Tigera, Inc. All rights reserved.

# This Makefile requires the following dependencies on the host system:
# - dep
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
GO_BUILD_VER?=v0.20
CALICO_BUILD?=calico/go-build:$(GO_BUILD_VER)
CONTAINERIZED=docker run --rm \
		-v $(PWD):/go/src/$(PACKAGE_NAME):rw \
		-v $(PWD)/.go-pkg-cache:/go-cache/:rw \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-e GOCACHE=/go-cache \
		-e KUBECONFIG=/go/src/$(PACKAGE_NAME)/kubeconfig.yaml \
		-w /go/src/$(PACKAGE_NAME) \
		--net=host \
		$(CALICO_BUILD)

BUILD_IMAGE?=tigera/operator
PUSH_IMAGES?=quay.io/$(BUILD_IMAGE)
RELEASE_IMAGES?=

# remove from the list to push to manifest any registries that do not support multi-arch
EXCLUDE_MANIFEST_REGISTRIES ?= quay.io/
PUSH_MANIFEST_IMAGES=$(PUSH_IMAGES:$(EXCLUDE_MANIFEST_REGISTRIES)%=)
PUSH_NONMANIFEST_IMAGES=$(filter-out $(PUSH_MANIFEST_IMAGES),$(PUSH_IMAGES))

BINDIR?=build/_output/bin

# If this is a release, also tag and push additional images.
ifeq ($(RELEASE),true)
PUSH_IMAGES+=$(RELEASE_IMAGES)
endif

imagetag:
ifndef IMAGETAG
	$(error IMAGETAG is undefined - run using make <target> IMAGETAG=X.Y.Z)
endif

## push one arch
push: imagetag $(addprefix sub-single-push-,$(call escapefs,$(PUSH_IMAGES)))

sub-single-push-%:
	docker push $(call unescapefs,$*:$(IMAGETAG)-$(ARCH))

## push all arches
push-all: imagetag $(addprefix sub-push-,$(ARCHES))
sub-push-%:
	$(MAKE) push ARCH=$* IMAGETAG=$(IMAGETAG)

## push multi-arch manifest where supported
push-manifests: imagetag  $(addprefix sub-manifest-,$(call escapefs,$(PUSH_MANIFEST_IMAGES)))
sub-manifest-%:
	# Docker login to hub.docker.com required before running this target as we are using $(DOCKER_CONFIG) holds the docker login credentials
	# path to credentials based on manifest-tool's requirements here https://github.com/estesp/manifest-tool#sample-usage
	docker run -t --entrypoint /bin/sh -v $(DOCKER_CONFIG):/root/.docker/config.json $(CALICO_BUILD) -c "/usr/bin/manifest-tool push from-args --platforms $(call join_platforms,$(ARCHES)) --template $(call unescapefs,$*:$(IMAGETAG))-ARCH --target $(call unescapefs,$*:$(IMAGETAG))"

## push default amd64 arch where multi-arch manifest is not supported
push-non-manifests: imagetag $(addprefix sub-non-manifest-,$(call escapefs,$(PUSH_NONMANIFEST_IMAGES)))
sub-non-manifest-%:
ifeq ($(ARCH),amd64)
	docker push $(call unescapefs,$*:$(IMAGETAG))
else
	$(NOECHO) $(NOOP)
endif

## tag images of one arch for all supported registries
tag-images: imagetag $(addprefix sub-single-tag-images-arch-,$(call escapefs,$(PUSH_IMAGES))) $(addprefix sub-single-tag-images-non-manifest-,$(call escapefs,$(PUSH_NONMANIFEST_IMAGES)))

sub-single-tag-images-arch-%:
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(call unescapefs,$*:$(IMAGETAG)-$(ARCH))

# because some still do not support multi-arch manifest
sub-single-tag-images-non-manifest-%:
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(call unescapefs,$*:$(IMAGETAG))
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
build: $(BINDIR)/operator-$(ARCH)
$(BINDIR)/operator-$(ARCH): vendor $(GO_FILES)
	mkdir -p $(BINDIR)
	$(CONTAINERIZED) go build -v -o $(BINDIR)/operator-$(ARCH) ./cmd/manager/main.go

image: vendor build
	docker build -f build/Dockerfile.amd64 -t $(BUILD_IMAGE) .

image: $(BUILD_IMAGE)
$(BUILD_IMAGE): $(BUILD_IMAGE)-$(ARCH)
$(BUILD_IMAGE)-$(ARCH): $(BINDIR)/operator-$(ARCH)
	docker build --pull -t $(BUILD_IMAGE):latest-$(ARCH) -f ./build/Dockerfile.$(ARCH) .
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(BUILD_IMAGE):latest
endif

vendor:
	$(CONTAINERIZED) dep ensure

clean:
	rm -rf build/_output
	rm -rf vendor/
	docker rmi -f $(BUILD_IMAGE):latest $(BUILD_IMAGE):latest-$(ARCH)

###############################################################################
# Tests
###############################################################################
WHAT?=.
GINKGO_ARGS?=
GINKGO_FOCUS?=.*

## Run the full set of tests
ut: cluster-create run-uts cluster-destroy
run-uts: vendor
	-mkdir -p .go-pkg-cache report
	$(CONTAINERIZED) ginkgo -r --skipPackage vendor -focus="$(GINKGO_FOCUS)" $(GINKGO_ARGS) $(WHAT)

## Create a local docker-in-docker cluster.
cluster-create: k3d
	./k3d create \
		--workers 2 \
		--worker-arg="--no-flannel" \
		--server-arg="--no-flannel" \
		--name "operator-test-cluster"
	timeout 10 sh -c "while ! ./k3d get-kubeconfig --name='operator-test-cluster'; do echo 'Waiting for cluster'; sleep 1; done"
	cp ~/.config/k3d/operator-test-cluster/kubeconfig.yaml .
	$(MAKE) deploy-crds

deploy-crds: kubectl
	@export KUBECONFIG=./kubeconfig.yaml && \
		./kubectl apply -f deploy/crds/operator_v1alpha1_core_crd.yaml && \
		./kubectl apply -f deploy/crds/calico-resources/

## Destroy local docker-in-docker cluster
cluster-destroy: k3d
	./k3d delete --name "operator-test-cluster"
	rm -f ./kubeconfig.yaml

k3d:
	# TODO: Use a real release of k3d. For now, just use this build which turns off flannel.
	wget https://github.com/caseydavenport/k3d/releases/download/no-flannel/k3d
	chmod +x ./k3d

kubectl:
	curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.14.0/bin/linux/amd64/kubectl
	chmod +x ./kubectl


###############################################################################
# Static checks
###############################################################################
.PHONY: static-checks
## Perform static checks on the code.
static-checks: vendor
	$(CONTAINERIZED) gometalinter --deadline=300s --disable-all --enable=vet --enable=errcheck --enable=goimports --vendor pkg/...

.PHONY: fix
## Fix static checks
fix:
	goimports -w $(SRC_FILES)

foss-checks: vendor
	@echo Running $@...
	docker run --rm \
		-v $(PWD):/go/src/$(PACKAGE_NAME):rw \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-w /go/src/$(PACKAGE_NAME)
		-e FOSSA_API_KEY=$(FOSSA_API_KEY) \
		$(CALICO_BUILD) /usr/local/bin/fossa

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
## Run what CI runs
ci: image test

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
# Release: TODO
###############################################################################

###############################################################################
# Utilities
###############################################################################
## Generating code after API changes
gen-files:
	operator-sdk generate k8s --verbose

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
