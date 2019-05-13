# TODO: Add in the necessary variables, etc, to make this Makefile work.
# TODO: Add in multi-arch stuff.

# Shortcut targets
default: build

## Build binary for current platform
all: build

## Run the tests for the current platform/architecture
test: build

###############################################################################
# Building the code 
###############################################################################
build: image
image: vendor operator-sdk
	./operator-sdk build calico/operator

operator-sdk:
	wget https://github.com/operator-framework/operator-sdk/releases/download/v0.7.0/operator-sdk-v0.7.0-x86_64-linux-gnu
	mv operator-sdk-v0.7.0-x86_64-linux-gnu ./operator-sdk
	chmod +x ./operator-sdk

# Use this to populate the vendor directory after checking out the repository.
vendor: 
	dep ensure

###############################################################################
# Tests: TODO: Add tests.
###############################################################################

###############################################################################
# Static checks
###############################################################################
.PHONY: static-checks
## Perform static checks on the code.
static-checks: vendor
	docker run --rm \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME) \
		-w /go/src/$(PACKAGE_NAME) \
		$(CALICO_BUILD) gometalinter --deadline=300s --disable-all --enable=vet --enable=errcheck --enable=goimports --vendor pkg/...

.PHONY: fix
## Fix static checks
fix:
	goimports -w $(SRC_FILES)

foss-checks: vendor
	@echo Running $@...
	@docker run --rm -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
	  -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	  -e FOSSA_API_KEY=$(FOSSA_API_KEY) \
	  -w /go/src/$(PACKAGE_NAME) \
	  $(CALICO_BUILD) /usr/local/bin/fossa

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
## Run what CI runs
ci: static-checks test

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
