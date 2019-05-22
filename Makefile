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
test: image ut st

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

###############################################################################
# Building the code
###############################################################################
.PHONY: build
build: vendor
	mkdir -p build/_output/bin
	$(CONTAINERIZED) go build -v -o build/_output/bin/operator ./cmd/manager/main.go

image: vendor build
	docker build -f build/Dockerfile -t tigera/operator .

vendor:
	$(CONTAINERIZED) dep ensure

clean:
	rm -rf build/_output
	rm -rf vendor/

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
ci: test #static-checks

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
