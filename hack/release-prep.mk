GIT_PR_BRANCH_BASE ?= $(shell git branch --show-current)
GIT_DESCRIBE := $(shell git describe --tags --always)
GIT_REPO_SLUG ?= tigera/operator
AUTO_VERSION_VERSION = $(shell go run hack/increment_patch.go $(GIT_DESCRIBE))
ifdef AUTO_VERSION
VERSION = $(AUTO_VERSION_VERSION)
endif
CALICO_VERSION ?= $(shell $(YQ_V4) '.title' config/calico_versions.yml )
CALICO_ENTERPRISE_VERSION ?= $(shell $(YQ_V4) '.title' config/enterprise_versions.yml )