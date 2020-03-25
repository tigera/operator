#!/bin/sh
# Copyright (c) 2020 Tigera, Inc. All rights reserved.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script generates a ClusterServiceVersion for the given VERSION and
# PREV_VERSION. It generates the CSV into deploy/olm-catalog, then it generates
# the operator metadata bundle into bundle/.
set -e

# We also need a semver version string.
SEMVER=${VERSION#v}

# The ClusterServiceVersion that we'll be generating for this version.
DEPLOY_CSV=deploy/olm-catalog/tigera-operator/${SEMVER}/tigera-operator.${VERSION}.clusterserviceversion.yaml

# Generate the ClusterServiceVersion (CSV). This will update deploy/olm-catalog with new a ClusterServiceVersion.
operator-sdk generate csv --operator-name tigera-operator --csv-channel stable --csv-version ${SEMVER}

# Merge in our custom CSV updates (metadata about our operator, icon, etc.) into the generated CSV.
yq merge -i ${DEPLOY_CSV}  hack/gen-olm-bundle/csv-merge.yaml

# Overwrite a few keys in the CSV.
yq write -i -s hack/gen-olm-bundle/csv-writes.yaml ${DEPLOY_CSV}

# Set the previous version of the operator that this version replaces.
yq write -i ${DEPLOY_CSV} spec.replaces tigera-operator.${PREV_VERSION}

# Set the operator image tag using this gnarly yq path expression. TODO: change this to the SHA256 !!!!
yq write -i ${DEPLOY_CSV} spec.install.spec.deployments[0].spec.template.spec.containers[0].image quay.io/tigera/operator:${VERSION}

# Set the operator image metadata annotation.
yq write -i ${DEPLOY_CSV} metadata.annotations.containerImage quay.io/tigera/operator:${VERSION}

# Set the operator image creation timestamp annotation.
TIMESTAMP=$(docker image inspect quay.io/tigera/operator:${VERSION} | jq .[0].Created)

yq write -i ${DEPLOY_CSV} metadata.annotations.createdAt ${TIMESTAMP}

# Copy the CSV, crds, and package.yaml to the bundle dir. Within bundle/,
# every new version of the operator is in its own directory. The contents of
# the bundle directory look something like this (assuming versions 1.3.0 and
# 1.3.1 of the operator published):
#
# bundle/
#   1.3.1/
#     operator_v1_installation_crd.yaml
#     operator_v1_logstorage_crd.yaml
#     <remaining crds>
#     tigera-operator.v1.3.1.clusterserviceversion.yaml
#   1.3.0/
#     operator_v1_installation_crd.yaml
#     operator_v1_logstorage_crd.yaml
#     <remaining crds>
#     tigera-operator.v1.3.0.clusterserviceversion.yaml
#   tigera-operator.package.yaml
#
mkdir -p bundle/${SEMVER}

# Copy over the CSV we've been building in deploy/olm-catalog/ to bundle/
cp ${DEPLOY_CSV} bundle/${SEMVER}

find ./deploy/crds/ -iname '*_crd.yaml' | xargs -I{} cp {} bundle/${SEMVER}
cp deploy/olm-catalog/tigera-operator/tigera-operator.package.yaml bundle/
mkdir -p build/_output
cd bundle/ && zip -r ../build/_output/bundle-${VERSION}.zip . && cd -

